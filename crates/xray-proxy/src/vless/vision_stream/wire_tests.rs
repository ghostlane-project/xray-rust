//! The bytes a Vision stream hands its carrier, pinned for fixed padding
//! draws: every carrier call in order, with what it was offered and what it
//! took, every flush and every wait. A TLS session seals each write it takes
//! into its own records, and a gathered write into the records of the same
//! bytes written at once (xray-transport's `tls_send` tests,
//! `a_gathered_write_seals_the_records_of_one_write`), so the same calls
//! with the same bytes are the same records on the wire.
//!
//! The digests were taken from the stream as it was before its padded writes
//! stopped copying their input (`2c7ade20` and `70d90396`, which copied each
//! frame whole into one buffer and wrote that). A carrier that gathers
//! vectored writes and one that does not must both see what that stream
//! wrote. The later digests also count each read the stream makes of its
//! carrier, so that a frame's bytes stay on the same side of a read.

use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use bytes::BytesMut;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{VisionStream, VisionStreamIo, USER_ID_LEN};
use crate::vless::vision::seeded;
use crate::vless::{VisionCommand, VisionPadding, DEFAULT_VISION_SEED};

const USER_ID: [u8; USER_ID_LEN] = [
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
];

/// What the carrier does at its `call`th write: `None` waits, `Some(cap)`
/// takes at most `cap` bytes.
type Plan = fn(usize) -> Option<usize>;

fn takes_all(_: usize) -> Option<usize> {
    Some(usize::MAX)
}

fn takes_100(_: usize) -> Option<usize> {
    Some(100)
}

fn waits_every_other(call: usize) -> Option<usize> {
    (call % 2 == 1).then_some(usize::MAX)
}

fn one_record_waits_every_third(call: usize) -> Option<usize> {
    (!call.is_multiple_of(3)).then_some(16 * 1024)
}

fn uneven(call: usize) -> Option<usize> {
    (call % 5 != 4).then_some(1 + (call * 7919) % 20_000)
}

/// Takes `K` bytes, waits, then takes what it is offered, and again: each
/// frame's head split after `K` of its bytes before a wait. A first frame's
/// head is 21 bytes (the user ID and 5), a later one's 5.
fn splits<const K: usize>(call: usize) -> Option<usize> {
    match call % 3 {
        0 => Some(K),
        1 => None,
        _ => Some(usize::MAX),
    }
}

/// The splits: a first frame's head at every offset, and at its end.
const SPLITS: [Plan; 21] = [
    splits::<1>,
    splits::<2>,
    splits::<3>,
    splits::<4>,
    splits::<5>,
    splits::<6>,
    splits::<7>,
    splits::<8>,
    splits::<9>,
    splits::<10>,
    splits::<11>,
    splits::<12>,
    splits::<13>,
    splits::<14>,
    splits::<15>,
    splits::<16>,
    splits::<17>,
    splits::<18>,
    splits::<19>,
    splits::<20>,
    splits::<21>,
];

const PLANS: [(&str, Plan); 5] = [
    ("takes all", takes_all),
    ("takes 100", takes_100),
    ("waits every other", waits_every_other),
    (
        "one record, waits every third",
        one_record_waits_every_third,
    ),
    ("uneven", uneven),
];

/// A carrier that answers by `plan`, waits at every other flush, and hashes
/// what it sees: with `count_reads`, each read too.
struct Scripted {
    vectored: bool,
    plan: Plan,
    count_reads: bool,
    writes: usize,
    flushes: usize,
    seen: Sha256,
    reads: Vec<u8>,
    read: usize,
}

impl Scripted {
    fn new(vectored: bool, plan: Plan, count_reads: bool, reads: Vec<u8>) -> Self {
        Self {
            vectored,
            plan,
            count_reads,
            writes: 0,
            flushes: 0,
            seen: Sha256::new(),
            reads,
            read: 0,
        }
    }

    fn write(&mut self, kind: u8, offered: &[&[u8]]) -> Poll<io::Result<usize>> {
        let len: usize = offered.iter().map(|part| part.len()).sum();
        let call = self.writes;
        self.writes += 1;
        self.seen.update([kind]);
        self.seen.update((len as u64).to_be_bytes());
        let Some(cap) = (self.plan)(call) else {
            self.seen.update(b"wait");
            return Poll::Pending;
        };
        let take = len.min(cap);
        self.seen.update((take as u64).to_be_bytes());
        let mut left = take;
        for part in offered {
            let len = left.min(part.len());
            self.seen.update(&part[..len]);
            left -= len;
        }
        Poll::Ready(Ok(take))
    }

    fn flush(&mut self, kind: u8) -> Poll<io::Result<()>> {
        let call = self.flushes;
        self.flushes += 1;
        self.seen.update([kind]);
        if call.is_multiple_of(2) {
            self.seen.update(b"wait");
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

impl AsyncRead for Scripted {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let len = output.remaining().min(this.reads.len() - this.read);
        output.put_slice(&this.reads[this.read..this.read + len]);
        this.read += len;
        if this.count_reads {
            this.seen.update(b"R");
            this.seen.update((len as u64).to_be_bytes());
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Scripted {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().write(b'W', &[input])
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        inputs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        assert!(
            this.vectored,
            "a vectored write to a carrier that does not gather"
        );
        let parts: Vec<&[u8]> = inputs.iter().map(|input| &**input).collect();
        this.write(b'W', &parts)
    }

    fn is_write_vectored(&self) -> bool {
        self.vectored
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().flush(b'F')
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().seen.update(b"S");
        Poll::Ready(Ok(()))
    }
}

impl VisionStreamIo for Scripted {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().write(b'X', &[input])
    }

    fn poll_flush_direct(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().flush(b'G')
    }

    fn poll_shutdown_direct(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().seen.update(b"H");
        Poll::Ready(Ok(()))
    }
}

enum Op {
    /// Written whole, as `write_all` writes: the rest again after a short
    /// write, the same bytes again after a wait.
    Write(Vec<u8>),
    Flush,
    /// Read this many decoded bytes.
    Read(usize),
    /// What the first-payload deadline queues when no payload came.
    EmptyFrame,
    Shutdown,
}

struct Scenario {
    name: &'static str,
    seed: [u32; 4],
    draws: u64,
    reads: Vec<u8>,
    ops: Vec<Op>,
}

/// Polls until ready; a carrier that waits answers its next call.
fn ready<T>(mut poll: impl FnMut(&mut Context<'_>) -> Poll<io::Result<T>>) -> T {
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..100_000 {
        if let Poll::Ready(result) = poll(&mut cx) {
            return result.expect("the stream fails no call");
        }
    }
    panic!("the stream never got ready");
}

fn run(scenario: &Scenario, vectored: bool, plan: Plan, count_reads: bool) -> String {
    let _draws = seeded::seed(scenario.draws);
    let carrier = Scripted::new(vectored, plan, count_reads, scenario.reads.clone());
    let mut stream = VisionStream::new(carrier, USER_ID, scenario.seed);
    for op in &scenario.ops {
        match op {
            Op::Write(bytes) => {
                let mut written = 0;
                while written < bytes.len() {
                    let len = ready(|cx| Pin::new(&mut stream).poll_write(cx, &bytes[written..]));
                    assert_ne!(len, 0, "{}: a write took nothing", scenario.name);
                    written += len;
                }
            }
            Op::Flush => ready(|cx| Pin::new(&mut stream).poll_flush(cx)),
            Op::Read(len) => {
                let mut bytes = vec![0; *len];
                let mut filled = 0;
                while filled < *len {
                    let read = ready(|cx| {
                        let mut output = ReadBuf::new(&mut bytes[filled..]);
                        Pin::new(&mut stream)
                            .poll_read(cx, &mut output)
                            .map_ok(|()| output.filled().len())
                    });
                    assert_ne!(read, 0, "{}: the read ended early", scenario.name);
                    filled += read;
                }
            }
            Op::EmptyFrame => stream.queue_empty_padding_frame().unwrap(),
            Op::Shutdown => ready(|cx| Pin::new(&mut stream).poll_shutdown(cx)),
        }
    }
    let seen = stream.into_inner().seen.finalize();
    seen.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn pattern(len: usize, salt: u8) -> Vec<u8> {
    (0..len)
        .map(|at| (at as u8).wrapping_mul(31).wrapping_add(salt))
        .collect()
}

fn record(content_type: u8, len: usize, salt: u8) -> Vec<u8> {
    let mut record = vec![content_type, 0x03, 0x03];
    record.extend_from_slice(&(len as u16).to_be_bytes());
    record.extend_from_slice(&pattern(len, salt));
    record
}

fn client_hello() -> Vec<u8> {
    let mut hello = vec![0x16, 0x03, 0x01, 0x02, 0x00, 0x01];
    hello.extend_from_slice(&pattern(512 - 1, 9));
    hello
}

/// A TLS 1.3 ServerHello with `cipher`, as the server's Vision pads it.
fn padded_server_hello(cipher: u16) -> (Vec<u8>, usize) {
    let mut body = vec![0x02, 0x00, 0x00, 0x00, 0x03, 0x03];
    body.extend_from_slice(&[0x5a; 32]);
    body.push(32);
    body.extend_from_slice(&[0xa5; 32]);
    body.extend_from_slice(&cipher.to_be_bytes());
    body.push(0);
    body.extend_from_slice(&[0x00, 0x06, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    let body_len = body.len() - 4;
    body[1..4].copy_from_slice(&(body_len as u32).to_be_bytes()[1..]);
    let mut hello = vec![0x16, 0x03, 0x03];
    hello.extend_from_slice(&(body.len() as u16).to_be_bytes());
    hello.extend_from_slice(&body);
    let padded = VisionPadding::new(USER_ID, [0, 0, 0, 0])
        .pad(BytesMut::from(&hello[..]), VisionCommand::Continue, 0)
        .unwrap();
    (padded.to_vec(), hello.len())
}

fn plain(
    name: &'static str,
    seed: [u32; 4],
    draws: u64,
    sizes: &[usize],
    flush_each: bool,
) -> Scenario {
    let mut ops = Vec::new();
    for (at, len) in sizes.iter().enumerate() {
        ops.push(Op::Write(pattern(*len, at as u8)));
        if flush_each {
            ops.push(Op::Flush);
        }
    }
    ops.push(Op::Flush);
    ops.push(Op::Shutdown);
    Scenario {
        name,
        seed,
        draws,
        reads: Vec::new(),
        ops,
    }
}

fn tls(name: &'static str, cipher: u16, draws: u64) -> Scenario {
    tls_flushed(name, cipher, draws, true)
}

/// A TLS 1.3 client's first bytes: its ClientHello, the server's hello read,
/// then its Finished, application data whose frame ends padding (`Direct`,
/// or `End` with CCM_8), flushed after it with `flush_switch`, and more.
fn tls_flushed(name: &'static str, cipher: u16, draws: u64, flush_switch: bool) -> Scenario {
    let (reads, hello_len) = padded_server_hello(cipher);
    let mut finished = record(0x14, 1, 1);
    finished.extend_from_slice(&record(0x17, 53, 2));
    let mut data = Vec::new();
    for at in 0..3 {
        data.extend_from_slice(&record(0x17, 1000 + at, 3 + at as u8));
    }
    let mut ops = vec![
        Op::Write(client_hello()),
        Op::Read(hello_len),
        Op::Write(finished),
        Op::Write(data),
    ];
    if flush_switch {
        ops.push(Op::Flush);
    }
    ops.extend([
        Op::Write(record(0x17, 300, 7)),
        Op::Write(pattern(40_000, 8)),
        Op::Flush,
        Op::Shutdown,
    ]);
    Scenario {
        name,
        seed: DEFAULT_VISION_SEED,
        draws,
        reads,
        ops,
    }
}

fn scenarios() -> Vec<Scenario> {
    let reads = [1, 70_000, 1024, 2048, 4096, 8192, 16_384, 32_768, 65_535, 5];
    vec![
        plain(
            "plain, flushed after each write",
            DEFAULT_VISION_SEED,
            1,
            &reads,
            true,
        ),
        plain(
            "plain, flushed at the end",
            DEFAULT_VISION_SEED,
            2,
            &reads,
            false,
        ),
        plain(
            "plain, short writes",
            DEFAULT_VISION_SEED,
            3,
            &[1, 5, 899, 900, 901, 30, 2],
            true,
        ),
        plain(
            "plain, long padding",
            [4000, 65_535, 65_535, 65_535],
            4,
            &[10, 3000, 70_000, 20],
            true,
        ),
        tls("TLS 1.3, direct", 0x1301, 5),
        tls("TLS 1.3 with CCM_8, end", 0x1305, 6),
        Scenario {
            name: "no payload in time",
            seed: DEFAULT_VISION_SEED,
            draws: 7,
            reads: Vec::new(),
            ops: vec![
                Op::EmptyFrame,
                Op::Flush,
                Op::Write(pattern(300, 1)),
                Op::Write(pattern(5000, 2)),
                Op::Flush,
                Op::Shutdown,
            ],
        },
    ]
}

/// Taken from `2c7ade20`'s stream, a row per scenario and a column per plan.
const BEFORE: [[&str; PLANS.len()]; 7] = [
    [
        "be3a8115d94b602c6b24e4acbcf8400ab93f9ca375a7895e6a59d91270781d0e",
        "7c19c09e1b6ccd409702b4ef1dfd097650c2690f7c5665dbe93bd977368a9188",
        "8274bc18e290bab3fea99796cd84ac303e778967cca09a64cbeb331050e7b2b9",
        "e64a2e16c82f88937aeeeb87bea5ca750ec1db8962f7b8ba9b4c76687cb9d0aa",
        "11c412d88b609cf0dcebd8c12c66eb09ca6eca2339c91bfe1c025ab5ea71220d",
    ],
    [
        "09d59a08c750dc75846c9bf2d704d169fbc0e443a8185167a2b350b84a8d2bec",
        "e5dac799bcf10efa173a988adc79fc9bd7bcb7a70e15f605d89396886e97150f",
        "fcbd0e93b331889bf5edf419722bed6bf0540d9732cbcb24f3f14a91df58355e",
        "5080ee8b840de4efda222f233a4ed1ec4e53b3fd65f3a0205715a41d949e84ba",
        "07917e71ec5d6fc93a37ac42fda6686e76fca8644f0c13f4d62a250854f889e4",
    ],
    [
        "d602b142b0d5b328382232f7b060a243ff65cdb58bfe31de0ca11c717c98ed26",
        "71e0b302e6ba889c55cde220bde1dc72dffbbf05dda3b64ab259d5a778710186",
        "a3391978e209dbb83586bc64ce3ded151409a98f85ac6d077c15fab7b5e7f715",
        "bf358bc0bc71f521ecc11628db49d63337b999be93daf764a312c58dcbc6f524",
        "c58b0017bedf2cf2ce9059844e220c6cb185fa4d8f36c6460b33c0f81588b604",
    ],
    [
        "cd66f99ea047dc61cb460866bfab610445c2d7a3c003a54bccd0feb09bdd1043",
        "36291f6bb76f080d5edbd800f7ff2b34525dea185a7691daff61ebdfdb65cac8",
        "3eb94c4f1418ec79b00ebd6900461afcd1efe1bf446a7dcc247886d00856c649",
        "8e48692c5de37bc8a9fa332e330df0055f43c5c80aef58050fa81c52c4441f1b",
        "07ac2bfea32503c26c7fbad1006d807659e5c959539bcf60f47acdd026c1de1d",
    ],
    [
        "b50a2ad00972834686642dffd153270bd07f41cfbcc14462c2d1ef4b8839da67",
        "adc12d03b0a8d8d5464e234fbfffa76562b04a282a2e1bbfb6da5b07a9fbc7d4",
        "8e9566e767e09b55468bb5264a217ec751cb720240df8ef5acc292bb9c861c2f",
        "c1300f9c886108fc9e4ee6148688e6bfb08b2860780f2b05c1950cb8bdc1f1b0",
        "d870ed222edf2573da671ff15f63ffc3ee97da9994f743a6ff58a58a9395d53d",
    ],
    [
        "3bdea8324e1f5e7a5babf50670c156f7c19213ec21edae19d7972cf956a05fe3",
        "66f0087a8cf8e93d24a7adb3b7324c9d8d23c1b22720a79035d114e5b43f2a19",
        "a8baca4f64815e93ae7aceecfe3fad0c532e23ae4f119126d7384acfe22ab8e8",
        "e911eac880b625a7238fa77a38a250be867a65c06c7ccfc44520e9d3baab1333",
        "508483320e04c9f623ed7541af60272aba3647497386fafb27ac2188efb5193f",
    ],
    [
        "8ae5646c050a8c14a366aad06dbfd1f560d41bfb3a6348400dc1d9870dff6135",
        "7934c0e65140fa472cc6945ca5d8fbb3c01f17bbadf0265f99231fb36a9d4f3a",
        "00c5a514fcadcae6af4526013ddfd4751f6ca2e92c6511542b5f8d7e0e2bd00e",
        "5c5a65c338cedb45f18192553f0d7fc85780d2a9bc6304217c515c30f51f1f34",
        "841e0a57d9f3e9a1dd6e8f7bf7d85f01620b5154fa898e057506f716d5a3866c",
    ],
];

#[test]
fn a_carrier_sees_the_bytes_it_saw_before_for_the_same_draws() {
    let mut differ = Vec::new();
    let mut table = String::new();
    for (row, scenario) in scenarios().iter().enumerate() {
        for (column, (plan_name, plan)) in PLANS.iter().enumerate() {
            let expected = BEFORE[row][column];
            for vectored in [false, true] {
                let seen = run(scenario, vectored, *plan, false);
                if !vectored {
                    table.push_str(&format!("{}: {plan_name}: \"{seen}\"\n", scenario.name));
                }
                if seen != expected {
                    differ.push(format!(
                        "{}, {plan_name}, vectored {vectored}: saw {seen}, before {expected}",
                        scenario.name
                    ));
                }
            }
        }
    }
    assert!(
        differ.is_empty(),
        "the carrier saw other bytes:\n{}\n\nwhat it saw:\n{table}",
        differ.join("\n")
    );
}

/// The scenarios whose reads the later digests count: a ClientHello's frame
/// before the server's hello is read, and a frame that ends padding with no
/// flush after it.
fn read_scenarios() -> Vec<Scenario> {
    vec![
        tls("TLS 1.3, direct", 0x1301, 5),
        tls("TLS 1.3 with CCM_8, end", 0x1305, 6),
        tls_flushed("TLS 1.3, direct, not flushed after", 0x1301, 8, false),
        tls_flushed(
            "TLS 1.3 with CCM_8, end, not flushed after",
            0x1305,
            9,
            false,
        ),
    ]
}

/// The scenarios the splits run.
fn split_scenarios() -> Vec<Scenario> {
    let mut all = scenarios();
    let no_payload = all.pop().expect("the scenario with no payload");
    let short = all.swap_remove(2);
    vec![short, tls("TLS 1.3, direct", 0x1301, 5), no_payload]
}

/// Taken from `70d90396`'s stream, its reads counted: a row per scenario of
/// `read_scenarios` and a column per plan.
const BEFORE_WITH_READS: [[&str; PLANS.len()]; 4] = [
    // TLS 1.3, direct
    [
        "22e6ee5279b6829364d6e5a027dd6d2cf8127e5fa6f65f3114b4da1ab58d6975",
        "214b6c899fe586f7afbc81ce5dd9b879bae1ff5dcdc087d46edec78cfe257851",
        "9d6c358fc36eecb884994a6614ce3a7cb7752cdfe103aaf80b529bfc3b1c5829",
        "878c2acd8c11ece7b30afa15560500203f3b171209fe18aa58348aba8a1bb497",
        "2e59a0f5cf7f8c6e110bd8a346586fa181285efdbf1a7b8bdae9bf0911ebe324",
    ],
    // TLS 1.3 with CCM_8, end
    [
        "45ea8eec694815221b901196d732696e1064d174ae707cc153e56154984f3c75",
        "c415feb9f9d6ebd42166c1c89392ff80d7d2f1967c327650999800001c4acf59",
        "8d411a039ca6cc0ba43dac3e1e66ee6d06340d9681c553c6ca54fc31e3dd5847",
        "e11a4c141243f0278b04436dbec2d6f20376f0ad7675cf38365add75c1bc45da",
        "dbea563ef68df3ebdc488ae0f8ea5c5b05424176c5c7e1f526af7c2902feb36d",
    ],
    // TLS 1.3, direct, not flushed after
    [
        "1f0853bfa17f027aadf3c1147098df990e1e2e580a0730b63508b732c905f2a8",
        "315204306566d6118624fb6a1d7152956df7a7a2b25aedc0d30a825cd878c594",
        "a639f52d9383cb488d1c05b1e84eef2368feb3349621831a2f94c271aac23de5",
        "39456c793023089ea2e1cfb8c7ee1e965d1dc570a603a93c0e9b667fb3c3961d",
        "fffce1e9fac35c04e84766021cad5984681ccec7e6be7ddefb7e50ead67375c5",
    ],
    // TLS 1.3 with CCM_8, end, not flushed after
    [
        "15e330796f8d8141aa7bfa0f0d93a3cfd11c7bdb41cdcdf01ae4b086c48f8fc1",
        "26082b1c109d6f589d72a48ac2d9e0cdc10c5f113c3716d9863cc884c8196118",
        "d64475ed2b3888a100add76e8457d6f6c976d41100fc0db23a95cba715651dfd",
        "424521f29c6b657c4d3dfa0b85dd7ec9694fc9ec748e6267fbe4ca4aacabb45d",
        "6bcf6c0e24adaed32dfb2d9c945f56d64e572c115ee302f049e3cca4a4ec46f0",
    ],
];

/// Taken from `70d90396`'s stream, its reads counted: a row per scenario of
/// `split_scenarios` and a column per split.
const BEFORE_SPLIT: [[&str; SPLITS.len()]; 3] = [
    // plain, short writes
    [
        "6654fdb6918a0c90824dceb5e5dd3daef1bfb1c47c649b7d79ee6a97544cc593",
        "ebd9926a497f88c89c1b9480d255952e77d00f8f5ce96598775fc78a53fdd6e8",
        "046e154c22528500ffceac6887762776e768b0e8b7950a1f874cb50e9523bd2c",
        "3f995ef964d5409fc1077e6d4c45cfe0be7d51b341bf870838b8e03f39ff6c26",
        "cfbd6faa9550fa01bba21e814d61adc95c2cc0e3cffb691d3333ef94b0c190d9",
        "4adbc51bdba1d37223409c70de14aaa57112c0cec7d0034815acde2300934daf",
        "5aee1ed96f12b243c0dbe4830fc9162e5f3a03fc82ac10b2b6b311d0d0770fd2",
        "022f2c65bd254ba45f6b2842d51c1a06cd002244f14957a833e63fe2f87a0b89",
        "244f70f4365ed8e8fa7e7ea922630d4fc487a54199d6c5d909abbc5ab3e68346",
        "fdb46f28650b7f2b4dfe36401a8580b10bc9a575a4a76313bca099db8cdd0e81",
        "6f973867b6b9a225b91cbc2b1553f3bd23c9b84d25fe74670889e227983eb271",
        "7fbcc32084c6425bfe61e174c700d1d1999823d20b0604b14330050a68a9a360",
        "6df12b37a0c8d9ae2a364e589de76e72af6d8307b6cfdcfdaa9dd9cc9444a5f8",
        "2ebc113e4194b7320c93292f08f098560c13117a8c9daf9b46920c13f2e261a1",
        "9cd60b3837143bee78f6013abf1ec8daf6a8d227caa4ed102c949c22321ab17e",
        "c6e050b9e732b8cd1811cb0c11d93d818c4c570e53937bda2cd9ac77ebc54faa",
        "de320c64ca72ab7e1760690fcf6e57e856d484c699e424d9a4d56e6f0d572804",
        "ca6a794fa9e3b47b5bfd9da1c2da7001c6cb214c6ba7e266e20e95ada37caa48",
        "108d206310f63e74592305c6d41bb5ed0851c36b483248d81eaf9391d09ef96d",
        "33ee5cb0178d3fdcb9fda22762dd20817b4326ef6d2edb9196e8614da87da790",
        "d6a101608309770ce60c186a4b2ce0a6cb45c9c9cd2e47985670824ad7091b2f",
    ],
    // TLS 1.3, direct
    [
        "97b5991d7c10410bedd98fbdf7fdb8cfa9313611004bf416b0eb6310c6438079",
        "e13be332e320537ce35562d66f45a4f9bdfef534c979e1514e421b614fd51f49",
        "130a7472c9daf81d6b5c5bc7ec3791e365eb5c79c07f9a4803ab06bf7aa26d8a",
        "4bc36c4e34ece5cb44458bc646ad05ee0d8e27003819f5e998ea1872100bd8a6",
        "941e49fc14bd2f8e961eff8513365be29d751711e48579b972e3e657070f6baa",
        "d8aa928cd8432d16ceb0cbbf6199544f125a80b7c47d433c407bac87b55decd3",
        "89200714e727da3735498952aa45cb08c07fbe18ddd5000dd7c2763e7584d727",
        "bb929841c04d8b05b33568e50f1b97f1e001d178af28068d9f8928a6081f3c9c",
        "c3f9dc7d44acb6088738af1705704de22fe271b4787e1e1b4576065fe6803249",
        "1636ce8bf4b4d7e009da0f1b3bc2a384117dc66e0f20d2a4397ccf4912a7cebc",
        "e44c41b8e7fa5afab35ef8caf7f60ddf1bbedc4062d1dc4c30af35f070bad975",
        "8a0650a8585287a884791172a4004fb46f75a72fc81a5df44a227deb2d471c38",
        "b6ddd0e62b9a41a2f2a57af8fb202c2b2537f215c2f4fa5b7ddafacdae5a1df8",
        "5cdc26c2a9b5bd2b024d162e54eefc06e02afd78800aa32593498e29d989c45d",
        "5042efdbafd4fa7fbf464e5a9c7696491cdbe89b8fff721b2f719a0a6e3c88ed",
        "f2e1205c18ed456c73914f6de25b6be99bedbed896378c5b23b6adedb7c6858c",
        "047e518a403c5b0eccae684a5676ebc3d6b1c585c26de62e7d47fbfc5e98e156",
        "b593ebf6d3de238c643114f96ac0d3c26d0169e19542dcd03aa184ae9ca7a5d5",
        "1cde021201dbd84166c5ed13ec10d4c677aa29114379164accc03f00b1d6f31a",
        "b9d0384d65a178020afa0445dd65f9907d5589c19bbcfd19fdebddff60060bb1",
        "254ad0051e03fdbdbc7a23c600c03ca2db10db785cf6f1acf2d7b362e928964a",
    ],
    // no payload in time
    [
        "cf4d2ce8f9b56f06db7f0fd3cacfeadb52a1038dd3a283b713f214686411189d",
        "0f2793809fca0a5acd12940e392923afe0c50e4813a8e86e86eb0565b909e20f",
        "3bc753215a211db96f14c4cf327e8974728129fd40d7dc485f3a7daa0b290228",
        "274f52a6635a9a9277e5f1ea99aee001cff3e2c4631f60205aaad864a3910cf2",
        "5fff7abe688b5067fb15ec6133d1cd7a0680a625f4e3a7ed2df074cbe6b4a28d",
        "22baae98e7a4e24557721abff93f11ac5b50d29325e5ee0f43194800390e20ec",
        "2f259e6d07a97df59e5c75c6a8f915c3f4e463fed47bf59b08db2f21828f7cd7",
        "265ded142d8d88db69c9cbce23fc6e33353c47423ce48d9d39b4d4cd3eafecab",
        "ab7379d35aa24b4ad9e640eb9c22ef8a1e4d5d97379f763616e4709876d87da0",
        "53b1a06fb8aeeb93ce3fe1da81a2e7f1388f2b40a0899b8e127045a334b92b4d",
        "c9b8c81c1f8b48366fea29908fe31fead2d4c4913424d64709c8bab2a6c4e611",
        "b83a86b1852f2a874875d5cb814546f777ddf831a9b44880003f744a23770ef8",
        "a83d8a392d3d3858bac488549aa0880b234a06dd71604ff1618a812527ebf978",
        "93699746485891acb8732565c68fb1f4ea82df290781be7dbdd178fa0127a5bf",
        "50f7d58940f4ff9c081fab1d77facf0019b275f934184cdd8b32f47e2a2c66c2",
        "1d44e4af2b424a8b06cbcff544ad84598fc2a5593f68f04f7766946524604732",
        "6a8c64549771cd283f99999dd21a2220dfccdf600da8e2fc015cca175b0340d6",
        "a9e3815373f7b8bac77a77b1283feb271dd957ead98a5265276d2db64910ea5c",
        "02bad906c5688f07836d08d8423041dddbf25a7bb22b2f3804ed482a319ce54c",
        "f917402a5f251bc6e43807a5049e91b45d9c2e4cafa8d8f3827a441300b4b9b3",
        "56a61f1747f83597e5e0b99ccd38410a189d0fc6c7b5973229cbe87331d1f244",
    ],
];

/// Runs `scenarios` under `plans` with reads counted, gathering and not,
/// against `expected`; the table of what it saw goes into the failure.
fn check_with_reads<const N: usize>(
    scenarios: &[Scenario],
    plans: &[(String, Plan)],
    expected: &[[&str; N]],
) {
    let mut differ = Vec::new();
    let mut table = String::new();
    for (row, scenario) in scenarios.iter().enumerate() {
        table.push_str(&format!("    // {}\n    [\n", scenario.name));
        for (column, (plan_name, plan)) in plans.iter().enumerate() {
            let expected = expected[row][column];
            for vectored in [false, true] {
                let seen = run(scenario, vectored, *plan, true);
                if !vectored {
                    table.push_str(&format!("        \"{seen}\",\n"));
                }
                if seen != expected {
                    differ.push(format!(
                        "{}, {plan_name}, vectored {vectored}: saw {seen}, before {expected}",
                        scenario.name
                    ));
                }
            }
        }
        table.push_str("    ],\n");
    }
    assert!(
        differ.is_empty(),
        "the carrier saw other bytes or reads:\n{}\n\nwhat it saw:\n{table}",
        differ.join("\n")
    );
}

#[test]
fn a_carrier_sees_its_reads_where_it_saw_them_before() {
    let plans: Vec<(String, Plan)> = PLANS
        .iter()
        .map(|(name, plan)| ((*name).to_owned(), *plan))
        .collect();
    check_with_reads(&read_scenarios(), &plans, &BEFORE_WITH_READS);
}

#[test]
fn a_head_split_before_a_wait_goes_on_as_before() {
    let plans: Vec<(String, Plan)> = SPLITS
        .iter()
        .enumerate()
        .map(|(at, plan)| (format!("takes {}, waits", at + 1), *plan))
        .collect();
    check_with_reads(&split_scenarios(), &plans, &BEFORE_SPLIT);
}

/// Once its carrier has taken a frame's payload, the frame's padding goes on
/// in the same call while the carrier takes it, as the old stream's whole
/// frame did: a read, or the writer's wait for its next bytes, comes after
/// the frame. A ClientHello's frame is long-padded, 388 B at least here.
#[test]
fn a_frame_whose_payload_went_ends_while_its_carrier_takes() {
    let _draws = seeded::seed(10);
    let carrier = Scripted::new(false, takes_100, false, Vec::new());
    let mut stream = VisionStream::new(carrier, USER_ID, DEFAULT_VISION_SEED);
    let hello = client_hello();
    let mut cx = Context::from_waker(Waker::noop());
    let mut written = 0;
    while written < hello.len() {
        match Pin::new(&mut stream).poll_write(&mut cx, &hello[written..]) {
            Poll::Ready(Ok(len)) => written += len,
            other => panic!("the write did not go: {other:?}"),
        }
    }
    assert!(
        stream.frame.is_none(),
        "the carrier took the payload and goes on taking, and the frame still owes {:?}",
        stream.frame
    );
}
