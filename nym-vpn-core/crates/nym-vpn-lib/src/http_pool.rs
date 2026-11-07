// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! No idle connections in the nym HTTP clients.
//!
//! Most nym HTTP clients share one connection pool for the life of the
//! daemon, and the rest are built from the same defaults. A pooled
//! connection stays bound to the address of the path it was opened on,
//! usually a tunnel device. After a reconnect that address is gone: the
//! socket's packets go nowhere, TCP reports nothing, and a request sent on
//! it hangs until the 30 s request timeout. The daemon makes a few API
//! calls an hour, so each request opens its own connection instead.

use nym_http_api_client::{ReqwestClientBuilder, inventory, registry::ConfigRecord};

fn no_idle_connections(builder: ReqwestClientBuilder) -> ReqwestClientBuilder {
    builder.pool_max_idle_per_host(0)
}

inventory::submit! {
    ConfigRecord { priority: 0, apply: no_idle_connections }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    /// A keep-alive server that answers every request on a connection and
    /// counts the connections it accepts.
    async fn keep_alive_server() -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    loop {
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                        while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            buf.drain(..end + 4);
                            let reply = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
                            if sock.write_all(reply).await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });
        (url, accepted)
    }

    #[tokio::test]
    async fn every_request_opens_a_connection() {
        let (url, accepted) = keep_alive_server().await;
        let client = nym_http_api_client::registry::build_client().unwrap();
        for _ in 0..3 {
            client.get(&url).send().await.unwrap();
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 3);
    }
}
