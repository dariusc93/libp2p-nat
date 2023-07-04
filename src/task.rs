//TODO: Use rust directly for port mapping natpmp (and eventually PCP) so we can avoid the need for FFI from nat-pmp

use std::time::Duration;

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
use libp2p::{multiaddr::Protocol, Multiaddr};

use crate::utils::multiaddr_to_socket_port;

#[derive(thiserror::Error, Debug)]
pub enum ForwardingError {
    #[error("Address provided is either local or invalid")]
    InvalidAddress { address: Multiaddr },
    #[error("Unable to port forward")]
    PortForwardingFailed,
    #[error(transparent)]
    Any(anyhow::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    Igd,
    #[cfg(feature = "nat_pmp_fallback")]
    #[cfg(not(target_os = "ios"))]
    Natpmp,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum NatCommands {
    ForwardPort(
        Multiaddr,
        Duration,
        oneshot::Sender<Result<(Multiaddr, NatType), ForwardingError>>,
    ),
    DisableForwardPort(
        Multiaddr,
        NatType,
        oneshot::Sender<Result<(), ForwardingError>>,
    ),
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum QuicType {
    Draft29,
    V1,
}

impl From<QuicType> for Protocol<'_> {
    fn from(qty: QuicType) -> Self {
        match qty {
            QuicType::Draft29 => Protocol::Quic,
            QuicType::V1 => Protocol::QuicV1,
        }
    }
}

#[inline]
#[cfg(any(feature = "tokio", feature = "async-std"))]
pub fn port_forwarding_task() -> UnboundedSender<NatCommands> {
    use crate::utils::to_multipaddr;

    let (tx, mut rx) = unbounded();

    let fut = async move {
        while let Some(cmd) = rx.next().await {
            match cmd {
                NatCommands::ForwardPort(multiaddr, duration, res) => {
                    let Some((addr, protocol, qty)) = multiaddr_to_socket_port(&multiaddr) else {
                        let _ = res.send(Err(ForwardingError::InvalidAddress{ address: multiaddr }));
                        continue;
                    };

                    let igd_fut = async {
                        let gateway = aio::search_gateway(SearchOptions::default()).await?;

                        gateway
                            .add_port(
                                protocol.into(),
                                addr.port(),
                                addr,
                                duration.as_secs() as _,
                                "libp2p",
                            )
                            .await?;

                        let ext_addr = gateway.get_external_ip().await?;

                        let multiaddr = to_multipaddr((ext_addr, addr.port()), protocol, qty);

                        Ok::<_, igd_next::Error>(multiaddr)
                    };

                    match igd_fut.await {
                        Ok(addr) => {
                            let _ = res.send(Ok((addr, NatType::Igd)));
                            continue;
                        }
                        Err(e) => {
                            log::error!("Error opening port with igd: {e}");
                        }
                    };

                    #[cfg(any(target_os = "ios", not(feature = "nat_pmp_fallback")))]
                    {
                        let _ = res.send(Err(ForwardingError::PortForwardingFailed));
                        continue;
                    }

                    #[cfg(feature = "nat_pmp_fallback")]
                    #[cfg(not(target_os = "ios"))]
                    {
                        #[cfg(all(feature = "tokio"))]
                        let mut nat_handle = match natpmp::new_tokio_natpmp().await {
                            Ok(handle) => handle,
                            Err(e) => {
                                log::error!("Error obtaining nat-pmp handle: {e}");
                                let _ = res.send(Err(ForwardingError::PortForwardingFailed));
                                continue;
                            }
                        };

                        #[cfg(all(feature = "async-std"))]
                        let mut nat_handle = match natpmp::new_async_std_natpmp().await {
                            Ok(handle) => handle,
                            Err(e) => {
                                log::error!("Error obtaining nat-pmp handle: {e}");
                                let _ = res.send(Err(ForwardingError::PortForwardingFailed));
                                continue;
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
                            log::error!("Error opening port with nat-pmp: {e}");
                            let _ = res.send(Err(ForwardingError::PortForwardingFailed));
                            continue;
                        }

                        let response = match nat_handle.read_response_or_retry().await {
                            Ok(response) => response,
                            Err(e) => {
                                let _ = res.send(Err(ForwardingError::Any(anyhow::anyhow!(
                                    "Error with nat pmp: {e}"
                                ))));
                                continue;
                            }
                        };

                        if !matches!(
                            response,
                            natpmp::Response::TCP(_) | natpmp::Response::UDP(_)
                        ) {
                            let _ = res.send(Err(ForwardingError::Any(anyhow::anyhow!(
                                "Unsupported result"
                            ))));
                            continue;
                        }

                        if let Err(e) = nat_handle.send_public_address_request().await {
                            let _ = res.send(Err(ForwardingError::Any(anyhow::anyhow!("{e}"))));
                            continue;
                        }

                        let gateway = match nat_handle.read_response_or_retry().await {
                            Ok(natpmp::Response::Gateway(gr)) => gr,
                            Ok(_) => {
                                let _ = res.send(Err(ForwardingError::Any(anyhow::anyhow!(
                                    "Cannot get external address"
                                ))));
                                continue;
                            }
                            Err(e) => {
                                let _ = res.send(Err(ForwardingError::Any(anyhow::anyhow!(
                                    "Error with nat pmp: {e}"
                                ))));
                                continue;
                            }
                        };

                        let ext_addr = *gateway.public_address();
                        let multiaddr = to_multipaddr((ext_addr, addr.port()), protocol, qty);

                        let _ = res.send(Ok((multiaddr, NatType::Natpmp)));
                    }
                }
                NatCommands::DisableForwardPort(addr, NatType::Igd, ret) => {
                    let Some((addr, protocol, _)) = multiaddr_to_socket_port(&addr) else {
                        let _ = ret.send(Err(ForwardingError::InvalidAddress{ address: addr }));
                        continue;
                    };

                    let opts = SearchOptions {
                        timeout: Some(Duration::from_secs(2)),
                        ..Default::default()
                    };

                    let gateway = match aio::search_gateway(opts).await {
                        Ok(gateway) => gateway,
                        Err(e) => {
                            log::warn!("Error with igd: {e}");
                            let _ = ret.send(Err(ForwardingError::Any(anyhow::anyhow!("{e}"))));
                            continue;
                        }
                    };

                    let _ = ret.send(
                        gateway
                            .remove_port(protocol.into(), addr.port())
                            .await
                            .map_err(|e| ForwardingError::Any(anyhow::anyhow!("{e}"))),
                    );
                }

                #[cfg(feature = "nat_pmp_fallback")]
                #[cfg(not(target_os = "ios"))]
                NatCommands::DisableForwardPort(_, NatType::Natpmp, ret) => {
                    //This implementation does not have a way to remove the port at this time
                    let _ = ret.send(Ok(()));
                }
            }
        }
    };

    #[cfg(feature = "tokio")]
    tokio::spawn(fut);

    #[cfg(feature = "async-std")]
    async_std::task::spawn(fut);

    tx
}
