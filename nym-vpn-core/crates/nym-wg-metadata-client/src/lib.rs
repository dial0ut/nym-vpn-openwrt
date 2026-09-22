// Copyright 2025 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use nym_credentials_interface::CredentialSpendingData;
use nym_gateway_directory::NodeIdentity;
use nym_http_api_client::ReqwestClientBuilder;
use nym_wireguard_private_metadata_client::WireguardMetadataApiClient;
use nym_wireguard_private_metadata_shared::{AvailableBandwidth, Version, v1, v2};
use url::Url;

use error::Result;

use crate::error::MetadataClientError;

pub mod error;

#[derive(Clone)]
pub enum TunUpSendData {
    #[cfg(not(target_os = "windows"))]
    InterfaceName(String),
    TcpProxy(SocketAddr),
    Signal,
}

pub type TunUpSender = tokio::sync::oneshot::Sender<TunUpSendData>;
pub type TunUpReceiver = tokio::sync::oneshot::Receiver<TunUpSendData>;

#[derive(Debug, Clone)]
struct LazyMetadataClient {
    inner: nym_http_api_client::Client,
    version: Version,
}

impl LazyMetadataClient {
    async fn new(
        mut base_url: Url,
        bind_ip: IpAddr,
        retries: usize,
        timeout: Duration,
        sent_data: TunUpSendData,
    ) -> Result<Self> {
        let reqwest_builder = ReqwestClientBuilder::new();
        let reqwest_builder = match sent_data {
            #[cfg(not(target_os = "windows"))]
            TunUpSendData::InterfaceName(interface) => {
                reqwest_builder.interface(&interface).local_address(bind_ip)
            }
            TunUpSendData::TcpProxy(tcp_proxy) => {
                base_url.set_ip_host(tcp_proxy.ip()).map_err(|_| {
                    MetadataClientError::Internal("failed to set tcp proxy ip".to_owned())
                })?;

                base_url.set_port(Some(tcp_proxy.port())).map_err(|_| {
                    MetadataClientError::Internal("failed to set tcp proxy port".to_owned())
                })?;

                reqwest_builder
            }
            _ => reqwest_builder.local_address(bind_ip),
        };

        let inner = nym_http_api_client::Client::builder(base_url).and_then(|builder| {
            builder
                .with_reqwest_builder(reqwest_builder)
                .with_retries(retries)
                .with_timeout(timeout)
                .build()
        })?;
        let version = inner.version().await?;

        Ok(Self { inner, version })
    }
}

pub struct MetadataClient {
    /// Built on first use. A failed build is not kept: the next call
    /// builds again.
    client: Option<LazyMetadataClient>,
    /// The tunnel-up signal, kept so that the client can be rebuilt.
    tun_data: Option<TunUpSendData>,
    lazy_client_retries: usize,
    lazy_client_timeout: Duration,
    gateway_id: NodeIdentity,
    base_url: Url,
    bind_ip: IpAddr,
    signal_channel: Option<TunUpReceiver>,
}

impl MetadataClient {
    /// Cancel-safe: the signal channel is only borrowed while awaited, and
    /// the signal is stored before the client is built.
    async fn lazy_client(&mut self) -> Result<&LazyMetadataClient> {
        match self.client {
            Some(ref client) => Ok(client),
            None => {
                let data = self.tun_up_data().await?;
                let client = LazyMetadataClient::new(
                    self.base_url.clone(),
                    self.bind_ip,
                    self.lazy_client_retries,
                    self.lazy_client_timeout,
                    data,
                )
                .await?;
                Ok(self.client.insert(client))
            }
        }
    }

    async fn tun_up_data(&mut self) -> Result<TunUpSendData> {
        if let Some(data) = &self.tun_data {
            return Ok(data.clone());
        }
        let never_sent =
            || MetadataClientError::Internal("interface up signal never sent".to_string());
        let signal_channel = self.signal_channel.as_mut().ok_or_else(never_sent)?;
        let received = signal_channel.await;
        // A resolved oneshot receiver must not be polled again.
        self.signal_channel = None;
        let data = received.map_err(|_| never_sent())?;
        self.tun_data = Some(data.clone());
        Ok(data)
    }

    pub fn new(
        base_url: Url,
        gateway_id: NodeIdentity,
        bind_ip: IpAddr,
        signal_channel: TunUpReceiver,
        lazy_client_retries: usize,
        lazy_client_timeout: Duration,
    ) -> Self {
        Self {
            client: None,
            tun_data: None,
            lazy_client_retries,
            lazy_client_timeout,
            gateway_id,
            bind_ip,
            base_url,
            signal_channel: Some(signal_channel),
        }
    }

    pub fn gateway_id(&self) -> NodeIdentity {
        self.gateway_id
    }

    fn print_remaining_bandwidth(
        gateway_id: NodeIdentity,
        available_bandwidth: AvailableBandwidth,
    ) {
        let bytes = available_bandwidth.bandwidth_bytes;
        let upgrade_mode = available_bandwidth.upgrade_mode == Some(true);

        let remaining_pretty = if bytes > 1024 * 1024 {
            format!("{:.2} MB", bytes as f64 / 1024.0 / 1024.0)
        } else {
            format!("{} KB", bytes / 1024)
        };
        tracing::debug!(
            "Remaining wireguard bandwidth with gateway {} for today: {}",
            gateway_id,
            remaining_pretty
        );
        if upgrade_mode {
            tracing::debug!("Bandwidth is not metered as the system is undergoing an upgrade")
        }
    }

    pub async fn query_bandwidth(&mut self) -> Result<AvailableBandwidth> {
        let client = self.lazy_client().await?;
        let request = match client.version {
            Version::V1 => v1::AvailableBandwidthRequest {}.try_into()?,
            Version::V2 => v2::AvailableBandwidthRequest {}.try_into()?,
        };
        let response = client.inner.available_bandwidth(&request).await?;
        let available_bandwidth = match client.version {
            Version::V1 => v1::AvailableBandwidthResponse::try_from(response)?.into(),
            Version::V2 => v2::AvailableBandwidthResponse::try_from(response)?.into(),
        };
        Self::print_remaining_bandwidth(self.gateway_id, available_bandwidth);
        Ok(available_bandwidth)
    }

    pub async fn topup_bandwidth(
        &mut self,
        credential: CredentialSpendingData,
    ) -> Result<AvailableBandwidth> {
        let client = self.lazy_client().await?;
        let request = match client.version {
            Version::V1 => v1::TopUpRequest { credential }.try_into()?,
            Version::V2 => v2::TopUpRequest {
                credential: credential.into(),
            }
            .try_into()?,
        };
        let response = client.inner.topup_bandwidth(&request).await?;
        let available_bandwidth = match client.version {
            Version::V1 => v1::TopUpResponse::try_from(response)?.into(),
            Version::V2 => v2::TopUpResponse::try_from(response)?.into(),
        };
        Self::print_remaining_bandwidth(self.gateway_id, available_bandwidth);
        Ok(available_bandwidth)
    }

    pub async fn check_upgrade_mode(&mut self, upgrade_mode_jwt: String) -> Result<bool> {
        let client = self.lazy_client().await?;

        let request = match client.version {
            Version::V1 => return Err(MetadataClientError::UnsupportedMetadataEndpointVersion),
            Version::V2 => v2::UpgradeModeCheckRequest {
                request_type: v2::UpgradeModeCheckRequestType::UpgradeModeJwt {
                    token: upgrade_mode_jwt,
                },
            }
            .try_into()?,
        };
        let response = client.inner.request_upgrade_mode_check(&request).await?;
        let upgrade_mode_enabled = match client.version {
            Version::V1 => return Err(MetadataClientError::UnsupportedMetadataEndpointVersion),
            Version::V2 => v2::UpgradeModeCheckResponse::try_from(response)?.upgrade_mode,
        };

        Ok(upgrade_mode_enabled)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, TcpListener};

    use tokio::sync::oneshot;

    use super::*;

    /// A client pointed at a loopback port nothing listens on.
    fn client_for_closed_port(signal_channel: TunUpReceiver) -> MetadataClient {
        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .and_then(|listener| listener.local_addr())
            .expect("bind an ephemeral port")
            .port();
        let identity =
            NodeIdentity::from_base58_string("7CWjY3QFoA9dgE535u9bQiXCfzgMZvSpJu842GA1Wn42")
                .expect("valid test identity");
        MetadataClient::new(
            Url::parse(&format!("http://127.0.0.1:{port}")).expect("valid url"),
            identity,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            signal_channel,
            0,
            Duration::from_secs(2),
        )
    }

    #[tokio::test]
    async fn failed_init_is_retried() {
        let (tx, rx) = oneshot::channel();
        let mut client = client_for_closed_port(rx);
        tx.send(TunUpSendData::Signal).ok();

        for attempt in 0..2 {
            let err = client.query_bandwidth().await.unwrap_err();
            assert!(
                matches!(err, MetadataClientError::HttpClientError(_)),
                "attempt {attempt}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn cancelled_wait_keeps_the_signal_channel() {
        let (tx, rx) = oneshot::channel();
        let mut client = client_for_closed_port(rx);

        let wait = tokio::time::timeout(Duration::from_millis(10), client.query_bandwidth());
        assert!(wait.await.is_err(), "no signal yet, the query must wait");

        tx.send(TunUpSendData::Signal).ok();
        let err = client.query_bandwidth().await.unwrap_err();
        assert!(
            matches!(err, MetadataClientError::HttpClientError(_)),
            "{err}"
        );
    }

    #[tokio::test]
    async fn dropped_signal_fails_every_call() {
        let (tx, rx) = oneshot::channel();
        let mut client = client_for_closed_port(rx);
        drop(tx);

        for _ in 0..2 {
            let err = client.query_bandwidth().await.unwrap_err();
            assert!(matches!(err, MetadataClientError::Internal(_)), "{err}");
        }
    }
}
