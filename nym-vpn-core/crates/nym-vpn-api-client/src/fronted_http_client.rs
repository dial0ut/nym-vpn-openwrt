use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc, Once,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use crate::{ResolverOverrides, error::VpnApiClientError};
use nym_http_api_client::{
    ApiClientCore, Client, ClientBuilder, HickoryDnsResolver, Url, UserAgent,
};
use nym_network_defaults::ApiUrl;

pub use nym_http_api_client::FrontPolicy;

/// Every fronting-capable client follows the http-api-client's process-wide
/// policy, so a change reaches existing clients; but the library only fronts
/// through the *current* base URL, so long-lived clients must call
/// [`prefer_fronted_base_url`] before each request. The library's own
/// default is `Off`; seed `OnRetry` on first touch, from either side.
static SHARED_FRONT_POLICY_INIT: Once = Once::new();

pub const DEFAULT_FRONT_POLICY: FrontPolicy = FrontPolicy::OnRetry;

fn init_shared_front_policy() {
    SHARED_FRONT_POLICY_INIT.call_once(|| Client::set_shared_front_policy(DEFAULT_FRONT_POLICY));
}

/// Mirror of "shared policy is `Always`" (the library keeps it private).
/// Only correct while every change goes through [`set_shared_front_policy`];
/// a direct `Client::set_shared_front_policy` call silently desynchronises it.
static FRONT_ALWAYS: AtomicBool = AtomicBool::new(false);

/// Sets the fronting policy for every fronting-capable client, existing and
/// future. `Always` is what the apps call "Stealth API connect".
pub fn set_shared_front_policy(policy: FrontPolicy) {
    init_shared_front_policy();
    FRONT_ALWAYS.store(policy == FrontPolicy::Always, Ordering::Relaxed);
    Client::set_shared_front_policy(policy);
}

/// Under `Always`, step `client` onto a base URL that has cover domains. The
/// discovery lists the plain host first and the library only rotates after a
/// failed request, so a fresh client would otherwise go direct. No-op under
/// any other policy.
pub fn prefer_fronted_base_url(client: &Client) {
    if FRONT_ALWAYS.load(Ordering::Relaxed)
        && !client.current_url().has_front()
        && client.base_urls().iter().any(Url::has_front)
    {
        // With fronting enabled, rotation picks the next base URL with fronts.
        client.maybe_rotate_hosts(None);
        tracing::debug!(
            "Stealth API: using fronted base URL {}",
            client.current_url()
        );
    }
}

pub async fn fronted_http_client(
    urls: Vec<Url>,
    user_agent: Option<UserAgent>,
    timeout: Option<Duration>,
    resolver_overrides: Option<&ResolverOverrides>,
) -> Result<Client, VpnApiClientError> {
    let builder =
        fronted_http_client_builder(urls, user_agent, timeout, resolver_overrides).await?;

    let client = builder
        .build()
        .map_err(Box::new)
        .map_err(VpnApiClientError::CreateVpnApiClient)?;

    prefer_fronted_base_url(&client);

    Ok(client)
}

pub async fn fronted_http_client_builder(
    urls: Vec<Url>,
    user_agent: Option<UserAgent>,
    timeout: Option<Duration>,
    resolver_overrides: Option<&ResolverOverrides>,
) -> Result<ClientBuilder, VpnApiClientError> {
    let has_front = urls.iter().any(|url| url.has_front());

    let mut builder = ClientBuilder::new_with_urls(urls)
        .map_err(Box::new)
        .map_err(VpnApiClientError::CreateVpnApiClient)?;

    if let Some(user_agent) = user_agent {
        builder = builder.with_user_agent(user_agent.clone());
    }

    if let Some(timeout) = timeout {
        builder = builder.with_timeout(timeout);
    }

    if has_front {
        // `None` selects the shared policy (see `set_shared_front_policy`).
        init_shared_front_policy();
        builder = builder.with_fronting(None);
    }

    // Static pre-resolve map: overrides the listed domains, real DNS otherwise.
    if let Some(resolver_overrides) = resolver_overrides.as_ref()
        && !resolver_overrides.is_empty()
    {
        let mut preresolve: HashMap<String, Vec<IpAddr>> = HashMap::new();
        for domain in resolver_overrides.domains() {
            if let Some(addrs) = resolver_overrides.addresses(&domain) {
                tracing::info!(
                    "Enabling Resolver override for {domain}: {}",
                    addrs
                        .iter()
                        .map(|addr| addr.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                preresolve.insert(domain, addrs.iter().map(|addr| addr.ip()).collect());
            }
        }
        if !preresolve.is_empty() {
            let mut resolver = HickoryDnsResolver::default();
            resolver.set_static_preresolve(preresolve);
            builder = builder.dns_resolver(Arc::new(resolver));
        }
    }

    Ok(builder)
}

pub fn api_url_to_url(api_url: &ApiUrl) -> Result<Url, VpnApiClientError> {
    let url = parse_url(&api_url.url)?;

    let fronts: Option<Vec<url::Url>> = api_url
        .front_hosts
        .as_ref()
        .map(|hosts| {
            hosts
                .iter()
                .map(|host| parse_url(host))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;

    let http_url = Url::new(url, fronts).map_err(|_e| VpnApiClientError::InvalidUrl {
        url: api_url.url.to_string(),
    })?;

    Ok(http_url)
}

pub fn api_urls_to_urls(api_urls: &[ApiUrl]) -> Result<Vec<Url>, VpnApiClientError> {
    api_urls
        .iter()
        .map(api_url_to_url)
        .collect::<Result<Vec<_>, _>>()
}

// Returns (url, Some(domain))
pub fn api_url_to_url_and_domain(
    api_url: &ApiUrl,
) -> Result<(Url, Option<String>), VpnApiClientError> {
    let url = parse_url(&api_url.url)?;

    // For URLs like "http://127.0.0.1:49675", `domain()` returns `None`.
    let domain = url.domain().map(|s| s.to_string());

    let fronts: Option<Vec<url::Url>> = api_url
        .front_hosts
        .as_ref()
        .map(|hosts| {
            hosts
                .iter()
                .map(|api_url| parse_url(api_url))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;

    let http_url = Url::new(url, fronts).map_err(|_e| VpnApiClientError::InvalidUrl {
        url: api_url.url.to_string(),
    })?;

    Ok((http_url, domain))
}

fn parse_url(s: &str) -> Result<url::Url, VpnApiClientError> {
    match url::Url::parse(s) {
        Ok(url) => Ok(url),
        Err(_) => {
            let with_scheme = format!("https://{s}");
            url::Url::parse(&with_scheme)
                .map_err(|_e| VpnApiClientError::InvalidUrl { url: s.to_string() })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nym_http_api_client::{ApiClient, NO_PARAMS, PathSegments};
    use tokio::sync::Mutex;

    // Serialises the tests driving the process-wide policy. tokio's Mutex: held
    // across awaits, and a failing test must not poison it.
    static POLICY_LOCK: Mutex<()> = Mutex::const_new(());

    /// Same shape as the mainnet discovery: plain host first, fronted
    /// fallback second.
    fn discovery_shaped_urls() -> Vec<Url> {
        api_urls_to_urls(&[
            ApiUrl {
                url: "https://api.example.com/api/".to_string(),
                front_hosts: None,
            },
            ApiUrl {
                url: "https://frontdoor.example.net/api/".to_string(),
                front_hosts: Some(vec!["cover.example.org".to_string()]),
            },
        ])
        .unwrap()
    }

    /// (host the TLS connection goes to, HTTP Host header).
    fn first_request_target(client: &Client) -> (String, Option<String>) {
        let path: PathSegments<'_> = &["v1", "ping"];
        let req = client
            .create_get_request(path, NO_PARAMS)
            .unwrap()
            .build()
            .unwrap();
        (
            req.url().host_str().unwrap().to_owned(),
            req.headers()
                .get("host")
                .map(|v| v.to_str().unwrap().to_owned()),
        )
    }

    #[tokio::test]
    async fn always_policy_fronts_from_the_first_request() {
        let _guard = POLICY_LOCK.lock().await;
        set_shared_front_policy(FrontPolicy::Always);

        // Built while the policy is on: fronted straight away.
        let client = fronted_http_client(discovery_shaped_urls(), None, None, None)
            .await
            .unwrap();
        let (connect_host, host_header) = first_request_target(&client);
        assert_eq!(connect_host, "cover.example.org");
        assert_eq!(host_header.as_deref(), Some("frontdoor.example.net"));

        // Built before the policy was switched on: follows on its next request.
        set_shared_front_policy(DEFAULT_FRONT_POLICY);
        let client = fronted_http_client(discovery_shaped_urls(), None, None, None)
            .await
            .unwrap();
        assert_eq!(first_request_target(&client).0, "api.example.com");
        set_shared_front_policy(FrontPolicy::Always);
        prefer_fronted_base_url(&client);
        assert_eq!(first_request_target(&client).0, "cover.example.org");

        set_shared_front_policy(DEFAULT_FRONT_POLICY);
    }

    /// The per-request step is what moves an existing client onto the cover domain.
    #[tokio::test]
    async fn runtime_toggle_reaches_an_existing_client_before_its_next_request() {
        let _guard = POLICY_LOCK.lock().await;
        set_shared_front_policy(DEFAULT_FRONT_POLICY);

        let client = fronted_http_client(discovery_shaped_urls(), None, None, None)
            .await
            .unwrap();
        assert_eq!(first_request_target(&client).0, "api.example.com");

        set_shared_front_policy(FrontPolicy::Always);
        // Without the step the client would still send direct.
        assert_eq!(first_request_target(&client).0, "api.example.com");
        prefer_fronted_base_url(&client);
        let (connect_host, host_header) = first_request_target(&client);
        assert_eq!(connect_host, "cover.example.org");
        assert_eq!(host_header.as_deref(), Some("frontdoor.example.net"));

        set_shared_front_policy(DEFAULT_FRONT_POLICY);
    }

    #[tokio::test]
    async fn default_policy_starts_direct() {
        let _guard = POLICY_LOCK.lock().await;
        set_shared_front_policy(DEFAULT_FRONT_POLICY);

        let client = fronted_http_client(discovery_shaped_urls(), None, None, None)
            .await
            .unwrap();
        prefer_fronted_base_url(&client);
        let (connect_host, host_header) = first_request_target(&client);
        assert_eq!(connect_host, "api.example.com");
        // No fronting, so no explicit Host header: reqwest derives it from the URL.
        assert!(host_header.is_none());
    }

    #[test]
    fn test_api_url_to_url_domain() {
        let api_url = ApiUrl {
            url: "example.com/api".to_string(),
            front_hosts: Some(vec!["front1.com".to_string(), "front2.com".to_string()]),
        };
        let (url, domain) = api_url_to_url_and_domain(&api_url).unwrap();
        assert_eq!(url.as_str(), "https://example.com/api");
        assert_eq!(domain, Some("example.com".to_string()));
    }

    #[test]
    fn test_api_url_to_url_ipaddr() {
        let api_url = ApiUrl {
            url: "http://127.0.0.1:49675".to_string(),
            front_hosts: Some(vec!["front1.com".to_string(), "front2.com".to_string()]),
        };
        let (url, domain) = api_url_to_url_and_domain(&api_url).unwrap();
        assert_eq!(url.as_str(), "http://127.0.0.1:49675/");
        assert!(domain.is_none());
    }
}
