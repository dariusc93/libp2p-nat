//TODO: Use rust directly for port mapping natpmp (and eventually PCP) so we can avoid the need for FFI from natffi

use std::{net::IpAddr, time::Duration};

use futures::{
    channel::{
        mpsc::{unbounded, UnboundedSender},
        oneshot,
    },
    StreamExt,
};
#[cfg(any(feature = "tokio", feature = "async-std"))]
use igd_next::aio;

use igd_next::SearchOptions;
use libp2p::Multiaddr;

use crate::utils::multiaddr_to_socket_port;

#[allow(dead_code)]
#[derive(Debug)]
pub enum NatCommands {
    ForwardPort(Multiaddr, Duration, oneshot::Sender<anyhow::Result<()>>),
    IdgExternalAddr(oneshot::Sender<anyhow::Result<IpAddr>>),
    #[cfg(not(target_os = "ios"))]
    NatpmpExternalAddr(oneshot::Sender<anyhow::Result<IpAddr>>),
}

#[inline]
#[cfg(any(feature = "tokio", feature = "async-std"))]
pub fn port_forwarding_task() -> oneshot::Receiver<anyhow::Result<UnboundedSender<NatCommands>>> {
    let (tx, mut rx) = unbounded();
    let (result_tx, result_rx) = oneshot::channel::<anyhow::Result<UnboundedSender<NatCommands>>>();

    let fut = async move {
        #[cfg(feature = "tokio")]
        #[cfg(not(target_os = "ios"))]
        let nat_handle = match natpmp::new_tokio_natpmp().await {
            Ok(handle) => std::sync::Arc::new(handle),
            Err(e) => {
                let _ = result_tx.send(Err(anyhow::Error::from(e)));
                return;
            }
        };

        #[cfg(feature = "async-std")]
        #[cfg(not(target_os = "ios"))]
        let nat_handle = match natpmp::new_async_std_natpmp().await {
            Ok(handle) => std::sync::Arc::new(handle),
            Err(e) => {
                let _ = result_tx.send(Err(anyhow::Error::from(e)));
                return;
            }
        };

        let _ = result_tx.send(Ok(tx));

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

                    #[cfg(target_os = "ios")]
                    {
                        let _ = res.send(Err(anyhow::anyhow!("Unable to port forward")));
                        continue;
                    }

                    #[cfg(not(target_os = "ios"))]
                    {
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
                #[cfg(not(target_os = "ios"))]
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

    result_rx
}

#[inline]
#[cfg(not(any(feature = "tokio", feature = "async-std")))]
pub fn port_forwarding_task() -> anyhow::Result<UnboundedSender<NatCommands>> {
    let (tx, mut rx) = unbounded();

    std::thread::spawn(move || {
        #[cfg(not(target_os = "ios"))]
        let mut nat_handle = natpmp::Natpmp::new().expect("Unable to use natpmp");
        while let Some(cmd) = futures::executor::block_on(rx.next()) {
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

                    match igd_next::search_gateway(opts) {
                        Ok(gateway) => {
                            match gateway.add_port(
                                protocol.into(),
                                addr.port(),
                                addr,
                                duration.as_secs() as _,
                                "libp2p",
                            ) {
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

                    #[cfg(target_os = "ios")]
                    {
                        let _ = res.send(Err(anyhow::anyhow!("Unable to port forward")));
                        continue;
                    }

                    #[cfg(not(target_os = "ios"))]
                    {
                        // In case igd fails, we will attempt with nat-pmp before returning an error
                        // TODO: Determine if we should have it in separate events
                        if let Err(e) = nat_handle.send_port_mapping_request(
                            protocol.into(),
                            addr.port(),
                            addr.port(),
                            duration.as_secs() as _,
                        ) {
                            let _ = res.send(Err(anyhow::Error::from(e)));
                            continue;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                        match nat_handle.read_response_or_retry() {
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
                }
                NatCommands::IdgExternalAddr(res) => {
                    let gateway = match igd_next::search_gateway(SearchOptions::default()) {
                        Ok(n) => n,
                        Err(e) => {
                            let _ = res.send(Err(anyhow::Error::from(e)));
                            continue;
                        }
                    };
                    match gateway.get_external_ip() {
                        Ok(addr) => {
                            let _ = res.send(Ok(addr));
                        }
                        Err(e) => {
                            let _ = res.send(Err(anyhow::Error::from(e)));
                        }
                    };
                }
                #[cfg(not(target_os = "ios"))]
                NatCommands::NatpmpExternalAddr(res) => {
                    //Note: Because the function contains a mutable reference, we cannot call it behind an arc. So we create
                    //      a new instance until dep is patched upstream

                    let mut handler = match natpmp::Natpmp::new() {
                        Ok(n) => n,
                        Err(e) => {
                            let _ = res.send(Err(anyhow::Error::from(e)));
                            continue;
                        }
                    };

                    if let Err(e) = handler.send_public_address_request() {
                        let _ = res.send(Err(anyhow::Error::from(e)));
                        continue;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                    match handler.read_response_or_retry() {
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
    });

    Ok(tx)
}
