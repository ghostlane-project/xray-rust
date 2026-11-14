//! The DNS outbound's `forward` rule: one query, unchanged, to the rule's
//! server through the outbound the rule names, as a flow of its own.
//!
//! The query is dispatched as Xray-core's DNS sends a query to a tagged
//! server: a new flow to the server's address through the outbound, not a
//! dialer chain under the DNS outbound. So any outbound that carries a flow
//! will do, REALITY included.
//!
//! Resources: one flow per query, opened here and closed when the answer is
//! read, the deadline passes or the caller drops the future. Nothing is
//! spawned and nothing is queued; the caller holds one DNS operation permit
//! for the whole exchange, so the flows open at once never exceed the DNS
//! runtime's operation limit. Each holds at most one answer (64 KiB).

use std::io;
use std::net::SocketAddr;

use tokio::io::AsyncWriteExt;
use tokio::time::{timeout_at, Instant};
use xray_config::DnsForwardTarget;
use xray_proxy::vless::{
    encode_udp_packet, encode_xudp_new_packet, read_udp_packet, read_xudp_packet,
};
use xray_routing::{Network as RoutingNetwork, Target, TargetAddr};

use crate::dns::{
    direct_dns_response_matches_query, exchange_correlated_dns_tcp_message, exchange_freedom_udp,
    exchange_masked_freedom_udp, open_routed_freedom_dns_tcp_stream,
};
use crate::dns_outbound_runtime::DnsDirectExecutor;
use crate::outbound::{
    open_tcp_stream_with_resolver_and_dialer, open_vless_udp_stream_with_resolver_and_dialer,
    OutboundNode, OutboundNodeId, OutboundNodeKind, TcpOutbound, UdpOutbound, VlessUdpFraming,
};
use crate::OutboundRouter;

/// TC in the second byte of the flags.
const DNS_FLAG_TC_BYTE: u8 = 0x02;

/// Datagrams on a forwarded flow that are not the answer, before the flow
/// is given up. The flow is the query's own, so there should be none.
const MAX_UNRELATED_ANSWERS: usize = 8;

/// Sends `query` to the forward rule's server through its outbound and
/// returns the answer, unchanged.
///
/// Over UDP when `prefer_udp` and the outbound carries UDP; over TCP when it
/// does not, when the client itself asked over TCP, or when the UDP answer is
/// truncated. Everything ends by `deadline`: past it the exchange fails,
/// except that a truncated UDP answer whose TCP retry did not finish in time
/// is returned as it is, for the client to retry.
pub(crate) async fn exchange(
    router: &OutboundRouter,
    executor: &DnsDirectExecutor,
    forward: &DnsForwardTarget,
    query: &[u8],
    prefer_udp: bool,
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    let node = carrier_node(router, &forward.outbound_tag)?;
    let server = SocketAddr::new(forward.address, forward.port);
    if executor.refuses_server(server) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "dns forward server is a runtime-local address",
        ));
    }

    let udp = prefer_udp
        .then(|| router.factory().cached_udp_outbound(node).ok())
        .flatten();
    let Some(udp) = udp else {
        return timeout_at(
            deadline,
            exchange_tcp(router, node, server, query, executor),
        )
        .await
        .map_err(|_| timed_out())?;
    };
    let answer = timeout_at(deadline, exchange_udp(udp, server, query, executor))
        .await
        .map_err(|_| timed_out())??;
    if !is_truncated(&answer) {
        return Ok(answer);
    }
    match timeout_at(
        deadline,
        exchange_tcp(router, node, server, query, executor),
    )
    .await
    {
        Ok(Ok(full)) => Ok(full),
        Ok(Err(_)) | Err(_) => Ok(answer),
    }
}

/// The outbound a forward rule names, if it carries flows. The parser
/// refuses the others; this keeps a config built in code from reaching them.
fn carrier_node(router: &OutboundRouter, tag: &str) -> io::Result<OutboundNodeId> {
    let graph = router.graph();
    let node = graph.node_for_tag(tag).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "dns forward outbound was not found",
        )
    })?;
    match graph.node(node).map(OutboundNode::kind) {
        Some(
            OutboundNodeKind::Dns
            | OutboundNodeKind::Blackhole
            | OutboundNodeKind::Loopback
            | OutboundNodeKind::Selector,
        )
        | None => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "dns forward outbound does not carry flows",
        )),
        Some(_) => Ok(node),
    }
}

fn is_truncated(answer: &[u8]) -> bool {
    answer
        .get(2)
        .is_some_and(|flags| flags & DNS_FLAG_TC_BYTE != 0)
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "dns forward timed out")
}

async fn exchange_udp(
    outbound: UdpOutbound,
    server: SocketAddr,
    query: &[u8],
    executor: &DnsDirectExecutor,
) -> io::Result<Vec<u8>> {
    let target = Target::new(
        TargetAddr::Ip(server.ip()),
        server.port(),
        RoutingNetwork::Udp,
    );
    match outbound {
        UdpOutbound::Freedom(freedom) => {
            // Direct DNS and dns.servers share this budget of UDP sockets.
            let _udp_exchange_permit = executor.try_reserve_udp_exchange()?;
            let dialer = freedom.dialer(executor.dialer());
            if freedom.has_udp_masks() {
                return exchange_masked_freedom_udp(&freedom, server, query, &dialer).await;
            }
            exchange_freedom_udp(server, query, dialer.socket_protector(), false).await
        }
        UdpOutbound::Vless(outbound) if !outbound.udp_uses_mux(&target) => {
            let (mut stream, framing) = open_vless_udp_stream_with_resolver_and_dialer(
                &outbound,
                &target,
                executor.bootstrap(),
                executor.dialer(),
            )
            .await
            .map_err(io::Error::other)?;
            let frame = match framing {
                VlessUdpFraming::LengthPrefixed => {
                    encode_udp_packet(query).map_err(io::Error::other)?
                }
                VlessUdpFraming::Xudp => {
                    encode_xudp_new_packet(&target, query, [0; 8]).map_err(io::Error::other)?
                }
            };
            stream.write_all(&frame).await?;
            stream.flush().await?;
            for _ in 0..=MAX_UNRELATED_ANSWERS {
                let answer = match framing {
                    VlessUdpFraming::LengthPrefixed => read_udp_packet(&mut stream).await?,
                    VlessUdpFraming::Xudp => read_xudp_packet(&mut stream).await?.payload,
                };
                if direct_dns_response_matches_query(query, &answer) {
                    return Ok(answer.to_vec());
                }
            }
            Err(unrelated_answers())
        }
        // Connection-oriented outbounds, and VLESS flows its Mux pool owns.
        outbound => {
            let session = Box::pin(crate::outbound::datagram::open(
                &outbound,
                &target,
                executor.bootstrap(),
                executor.bootstrap(),
                executor.dialer(),
                [0; 8],
            ))
            .await
            .map_err(io::Error::other)?;
            session
                .send(&target, query)
                .await
                .map_err(io::Error::other)?;
            for _ in 0..=MAX_UNRELATED_ANSWERS {
                let datagram = session.recv().await.map_err(io::Error::other)?;
                if direct_dns_response_matches_query(query, &datagram.payload) {
                    return Ok(datagram.payload);
                }
            }
            Err(unrelated_answers())
        }
    }
}

async fn exchange_tcp(
    router: &OutboundRouter,
    node: OutboundNodeId,
    server: SocketAddr,
    query: &[u8],
    executor: &DnsDirectExecutor,
) -> io::Result<Vec<u8>> {
    let outbound = router
        .factory()
        .cached_tcp_outbound(node)
        .map_err(io::Error::other)?;
    let target = Target::new(
        TargetAddr::Ip(server.ip()),
        server.port(),
        RoutingNetwork::Tcp,
    );
    let mut stream = match &outbound {
        TcpOutbound::Freedom(_) => {
            open_routed_freedom_dns_tcp_stream(
                &outbound.freedom_dialer(executor.dialer()),
                &target,
                &[server],
                outbound.freedom_happy_eyeballs(),
            )
            .await?
        }
        _ => open_tcp_stream_with_resolver_and_dialer(
            &outbound,
            &target,
            executor.bootstrap(),
            executor.dialer(),
        )
        .await
        .map_err(io::Error::other)?,
    };
    exchange_correlated_dns_tcp_message(&mut stream, query).await
}

fn unrelated_answers() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "too many unrelated answers on a dns forward flow",
    )
}
