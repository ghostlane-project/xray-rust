//! The DNS outbound's `forward` rule through a SOCKS inbound, as the app
//! sends its tunnel's DNS: the queries the core cannot fake go to 1.1.1.1:53
//! through the VLESS line, or for Bypass Russia's names to the network's own
//! resolver, and A/AAAA stay fake.
#[path = "dns_forward/support.rs"]
mod support;

use std::time::Duration;

use serde_json::json;
use support::*;
use tokio::time::Instant;
use xray_core_rs::TunRuntimeProfile;

const WAIT: Duration = Duration::from_secs(5);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn txt_and_srv_come_back_through_the_line() {
    let line = LineServer::spawn(Mode::Answer).await;
    let (mut core, socks) = start(&global_config(line.addr), TunRuntimeProfile::Mobile).await;

    let txt = tcp_dns(socks, &query(0x1601, "example.com", QTYPE_TXT), WAIT)
        .await
        .expect("TXT over TCP answered");
    let srv = udp_dns(
        socks,
        &query(0x3301, "_xmpp-client._tcp.example.com", QTYPE_SRV),
        WAIT,
    )
    .await
    .expect("SRV over UDP answered");
    let udp_txt = udp_dns(socks, &query(0x1602, "example.org", QTYPE_TXT), WAIT)
        .await
        .expect("TXT over UDP answered");
    core.stop().await.unwrap();

    let txt = Answer::parse(&txt);
    assert_eq!((txt.id, txt.rcode, txt.count), (0x1601, RCODE_NOERROR, 1));
    assert_eq!(txt.txt(), Some(VIA_LINE));
    let srv = Answer::parse(&srv);
    assert_eq!((srv.id, srv.rcode), (0x3301, RCODE_NOERROR));
    assert_eq!(srv.srv(), Some((SRV_PORT, SRV_TARGET.to_owned())));
    assert_eq!(Answer::parse(&udp_txt).txt(), Some(VIA_LINE));
    // The client's transport picks the line's: DNS over TCP stays TCP, a
    // UDP query goes as VLESS UDP.
    assert_eq!(
        line.seen(),
        vec![
            ("1.1.1.1:53".to_owned(), "tcp"),
            ("1.1.1.1:53".to_owned(), "udp"),
            ("1.1.1.1:53".to_owned(), "udp"),
        ]
    );
    assert!(
        eventually(WAIT, || line.active() == 0).await,
        "each flow closes"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn addresses_stay_fake_and_https_stays_refused() {
    let line = LineServer::spawn(Mode::Answer).await;
    let (mut core, socks) = start(&global_config(line.addr), TunRuntimeProfile::Mobile).await;

    let a = Answer::parse(
        &tcp_dns(socks, &query(1, "example.com", QTYPE_A), WAIT)
            .await
            .unwrap(),
    );
    let udp_a = Answer::parse(
        &udp_dns(socks, &query(2, "example.net", QTYPE_A), WAIT)
            .await
            .unwrap(),
    );
    let aaaa = Answer::parse(
        &tcp_dns(socks, &query(3, "example.com", QTYPE_AAAA), WAIT)
            .await
            .unwrap(),
    );
    let https = Answer::parse(
        &udp_dns(socks, &query(4, "example.com", QTYPE_HTTPS), WAIT)
            .await
            .unwrap(),
    );
    core.stop().await.unwrap();

    assert!(a.is_fake(), "A is fake: {a:?}");
    assert!(udp_a.is_fake(), "A over UDP is fake: {udp_a:?}");
    assert_eq!((aaaa.rcode, aaaa.count), (RCODE_NOERROR, 0), "AAAA empty");
    assert_eq!(https.rcode, RCODE_REFUSED, "HTTPS refused by its rule");
    assert!(line.seen().is_empty(), "no address query took the line");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_truncated_answer_is_asked_again_over_tcp() {
    let line = LineServer::spawn(Mode::TruncateUdp).await;
    let (mut core, socks) = start(&global_config(line.addr), TunRuntimeProfile::Mobile).await;

    let answer = udp_dns(socks, &query(0x7c01, "example.com", QTYPE_TXT), WAIT)
        .await
        .expect("answered");
    core.stop().await.unwrap();

    let answer = Answer::parse(&answer);
    assert!(!answer.truncated, "the whole answer: {answer:?}");
    assert_eq!(answer.txt(), Some(VIA_LINE));
    assert_eq!(
        line.seen(),
        vec![
            ("1.1.1.1:53".to_owned(), "udp"),
            ("1.1.1.1:53".to_owned(), "tcp"),
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bypass_asks_the_network_for_russian_names_and_the_line_for_the_rest() {
    let line = LineServer::spawn(Mode::Answer).await;
    let resolver = DirectResolver::spawn().await;
    let (mut core, socks) = start(
        &bypass_config(line.addr, resolver.addr),
        TunRuntimeProfile::Mobile,
    )
    .await;

    let ru_txt = udp_dns(socks, &query(1, "example.ru", QTYPE_TXT), WAIT)
        .await
        .unwrap();
    let ru_tcp_txt = tcp_dns(socks, &query(2, "sberbank.ru", QTYPE_TXT), WAIT)
        .await
        .unwrap();
    let ru_a = udp_dns(socks, &query(3, "sberbank.ru", QTYPE_A), WAIT)
        .await
        .unwrap();
    let other_txt = udp_dns(socks, &query(4, "example.com", QTYPE_TXT), WAIT)
        .await
        .unwrap();
    let other_a = udp_dns(socks, &query(5, "example.com", QTYPE_A), WAIT)
        .await
        .unwrap();
    let other_https = tcp_dns(socks, &query(6, "example.com", QTYPE_HTTPS), WAIT)
        .await
        .unwrap();
    core.stop().await.unwrap();

    assert_eq!(Answer::parse(&ru_txt).txt(), Some(VIA_DIRECT));
    assert_eq!(Answer::parse(&ru_tcp_txt).txt(), Some(VIA_DIRECT));
    assert_eq!(
        Answer::parse(&ru_a).a(),
        Some(DIRECT_A),
        "a Russian A is real"
    );
    assert_eq!(resolver.asked(), 3);
    assert_eq!(Answer::parse(&other_txt).txt(), Some(VIA_LINE));
    assert!(Answer::parse(&other_a).is_fake());
    assert_eq!(Answer::parse(&other_https).rcode, RCODE_REFUSED);
    assert_eq!(line.seen(), vec![("1.1.1.1:53".to_owned(), "udp")]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_line_gives_servfail_at_the_deadline_and_closes_its_flows() {
    let line = LineServer::spawn(Mode::Stall).await;
    let mut config = global_config(line.addr);
    // The DNS outbound's operation deadline is min(connIdle, 5 s).
    config["policy"] = json!({"levels": {"0": {"connIdle": 2}}});
    let (mut core, socks) = start(&config, TunRuntimeProfile::Mobile).await;

    let tcp_query = query(0x5e01, "example.com", QTYPE_TXT);
    let udp_query = query(0x5e02, "example.com", QTYPE_SRV);
    let started = Instant::now();
    let (tcp, udp) = tokio::join!(
        tcp_dns(socks, &tcp_query, WAIT),
        udp_dns(socks, &udp_query, WAIT),
    );
    let elapsed = started.elapsed();
    let all_closed = eventually(Duration::from_secs(2), || {
        line.active() == 0 && line.closed() == 2
    })
    .await;
    core.stop().await.unwrap();

    let tcp = Answer::parse(&tcp.expect("TCP answered, not hung"));
    let udp = Answer::parse(&udp.expect("UDP answered, not hung"));
    assert_eq!((tcp.id, tcp.rcode), (0x5e01, RCODE_SERVFAIL));
    assert_eq!((udp.id, udp.rcode), (0x5e02, RCODE_SERVFAIL));
    assert!(
        elapsed >= Duration::from_millis(1_800) && elapsed < Duration::from_millis(3_500),
        "answered at the 2 s deadline, after {elapsed:?}"
    );
    assert_eq!(line.seen().len(), 2);
    assert!(all_closed, "the line saw both flows close");
}
