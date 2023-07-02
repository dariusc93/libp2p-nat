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
pub async fn port_forwarding_task() -> anyhow::Result<UnboundedSender<NatCommands>> {
    use igd_next::AddPortError;

    use crate::utils::to_multipaddr;

    let (tx, mut rx) = unbounded();
    let (result_tx, result_rx) = oneshot::channel::<anyhow::Result<UnboundedSender<NatCommands>>>();

    let fut = async move {
        #[cfg(all(feature = "tokio", feature = "nat_pmp_fallback"))]
        #[cfg(not(target_os = "ios"))]
        let nat_handle = match natpmp::new_tokio_natpmp().await {
            Ok(handle) => std::sync::Arc::new(handle),
            Err(e) => {
                let _ = result_tx.send(Err(anyhow::Error::from(e)));
                return;
            }
        };

        #[cfg(all(feature = "async-std", feature = "nat_pmp_fallback"))]
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
                NatCommands::ForwardPort(multiaddr, duration, res) => {
                    let Some((addr, protocol, qty)) = multiaddr_to_socket_port(&multiaddr) else {
                        let _ = res.send(Err(ForwardingError::InvalidAddress{ address: multiaddr }));
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
                                    let ext_addr = match gateway.get_external_ip().await {
                                        Ok(addr) => addr,
                                        Err(e) => {
                                            let _ = res.send(Err(ForwardingError::Any(
                                                anyhow::anyhow!("{e}"),
                                            )));
                                            continue;
                                        }
                                    };

                                    let multiaddr =
                                        to_multipaddr((ext_addr, addr.port()), protocol, qty);

                                    let _ = res.send(Ok((multiaddr, NatType::Igd)));
                                    continue;
                                }
                                Err(e) if matches!(e, AddPortError::PortInUse) => {}
                                Err(e) => {
                                    log::warn!("Error with igd: {e}");
                                }
                            };
                        }
                        Err(e) => {
                            log::warn!("Error with igd: {e}");
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
                            log::error!("Error port mapping: {e}");
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

                        #[cfg(feature = "tokio")]
                        let mut handler = match natpmp::new_tokio_natpmp().await {
                            Ok(n) => n,
                            Err(e) => {
                                let _ = res.send(Err(ForwardingError::Any(anyhow::anyhow!("{e}"))));
                                continue;
                            }
                        };

                        #[cfg(feature = "async-std")]
                        let mut handler = match natpmp::new_async_std_natpmp().await {
                            Ok(n) => n,
                            Err(e) => {
                                let _ = res.send(Err(ForwardingError::Any(anyhow::anyhow!("{e}"))));
                                continue;
                            }
                        };
                        if let Err(e) = handler.send_public_address_request().await {
                            let _ = res.send(Err(ForwardingError::Any(anyhow::anyhow!("{e}"))));
                            continue;
                        }

                        let gateway = match handler.read_response_or_retry().await {
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

                        let multi_proto = Protocol::Ip4(*gateway.public_address());
                        let multiaddr = multiaddr
                            .iter()
                            .map(|p| match p {
                                Protocol::Ip4(_) => multi_proto.clone(),
                                p => p,
                            })
                            .collect();

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

    result_rx.await?
}
