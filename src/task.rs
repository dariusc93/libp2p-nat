//TODO: Use rust directly for port mapping natpmp (and eventually PCP) so we can avoid the need for FFI from natffi

use std::{net::IpAddr, sync::Arc, time::Duration};

use futures::{
    channel::{
        mpsc::{unbounded, UnboundedSender},
        oneshot,
    },
    StreamExt,
};
use igd_next::{aio, SearchOptions};
use libp2p::Multiaddr;

use crate::utils::multiaddr_to_socket_port;

#[allow(dead_code)]
#[derive(Debug)]
pub enum NatCommands {
    ForwardPort(Multiaddr, Duration, oneshot::Sender<anyhow::Result<()>>),
    IdgExternalAddr(oneshot::Sender<anyhow::Result<IpAddr>>),
    NatpmpExternalAddr(oneshot::Sender<anyhow::Result<IpAddr>>),
}

//TODO: Implement sync version for when tokio or async-std isnt in use
#[inline]
pub async fn port_forwarding_task() -> anyhow::Result<UnboundedSender<NatCommands>> {
    let (tx, mut rx) = unbounded();
    #[cfg(feature = "tokio")]
    let nat_handle = Arc::new(natpmp::new_tokio_natpmp().await?);

    #[cfg(feature = "async-std")]
    let nat_handle = Arc::new(natpmp::new_async_std_natpmp().await?);

    let fut = async move {
        while let Some(cmd) = rx.next().await {
            match cmd {
                NatCommands::ForwardPort(addr, duration, res) => {
                    let Some((addr, protocol)) = multiaddr_to_socket_port(&addr) else {
                        let _ = res.send(Err(anyhow::anyhow!("address is invalid")));
                        continue;
                    };
                    let opts = SearchOptions {
                        timeout: Some(Duration::from_secs(2)),
                        ..Default::default()
                    };

                    match aio::search_gateway(opts).await {
                        Ok(gateway) => {
                            match gateway
                                .add_port(
                                    protocol.into(),
                                    addr.port(),
                                    addr,
                                    duration.as_secs() as _,
                                    "libp2p",
                                )
                                .await
                            {
                                Ok(_) => {
                                    let _ = res.send(Ok(()));
                                    continue;
                                }
                                Err(e) => {
                                    log::warn!("Error with igd: {e}");
                                }
                            };
                        }
                        Err(e) => {
                            log::warn!("Error with igd: {e}");
                        }
                    };

                    // In case igd fails, we will attempt with nat-pmp before returning an error
                    // TODO: Determine if we should have it in separate events
                    if let Err(e) = nat_handle
                        .send_port_mapping_request(
                            protocol.into(),
                            addr.port(),
                            addr.port(),
                            duration.as_secs() as _,
                        )
                        .await
                    {
                        let _ = res.send(Err(anyhow::Error::from(e)));
                        continue;
                    }
                    match nat_handle.read_response_or_retry().await {
                        Ok(natpmp::Response::TCP(_)) | Ok(natpmp::Response::UDP(_)) => {
                            let _ = res.send(Ok(()));
                        }
                        Ok(_) => {
                            let _ = res.send(Err(anyhow::anyhow!("Unsupported result")));
                        }
                        Err(e) => {
                            let _ = res.send(Err(anyhow::anyhow!("Error with nat pmp: {e}")));
                        }
                    }
                }
                NatCommands::IdgExternalAddr(res) => {
                    let gateway = match aio::search_gateway(SearchOptions::default()).await {
                        Ok(n) => n,
                        Err(e) => {
                            let _ = res.send(Err(anyhow::Error::from(e)));
                            continue;
                        }
                    };
                    match gateway.get_external_ip().await {
                        Ok(addr) => {
                            let _ = res.send(Ok(addr));
                        }
                        Err(e) => {
                            let _ = res.send(Err(anyhow::Error::from(e)));
                        }
                    };
                }
                NatCommands::NatpmpExternalAddr(res) => {
                    //Note: Because the function contains a mutable reference, we cannot call it behind an arc. So we create
                    //      a new instance until dep is patched upstream
                    #[cfg(feature = "tokio")]
                    let mut handler = match natpmp::new_tokio_natpmp().await {
                        Ok(n) => n,
                        Err(e) => {
                            let _ = res.send(Err(anyhow::Error::from(e)));
                            continue;
                        }
                    };

                    #[cfg(feature = "async-std")]
                    let mut handler = match natpmp::new_async_std_natpmp().await {
                        Ok(n) => n,
                        Err(e) => {
                            let _ = res.send(Err(anyhow::Error::from(e)));
                            continue;
                        }
                    };

                    if let Err(e) = handler.send_public_address_request().await {
                        let _ = res.send(Err(anyhow::Error::from(e)));
                        continue;
                    }
                    match handler.read_response_or_retry().await {
                        Ok(natpmp::Response::Gateway(gr)) => {
                            let addr = IpAddr::V4(*gr.public_address());
                            let _ = res.send(Ok(addr));
                        }
                        Ok(_) => {
                            let _ = res.send(Err(anyhow::anyhow!("Cannot get external address")));
                        }
                        Err(e) => {
                            let _ = res.send(Err(anyhow::anyhow!("Error with nat pmp: {e}")));
                        }
                    }
                }
            }
        }
    };

    #[cfg(feature = "tokio")]
    tokio::spawn(fut);

    #[cfg(feature = "async-std")]
    async_std::task::spawn(fut);

    Ok(tx)
}
