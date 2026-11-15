//! The bytes a Vision stream hands its carrier, pinned for fixed padding
//! draws: every carrier call in order, with what it was offered and what it
//! took, every flush and every wait. A TLS session seals each write it takes
//! into its own records, and a gathered write into the records of the same
//! bytes written at once (xray-transport's `tls_send` tests,
//! `a_gathered_write_seals_the_records_of_one_write`), so the same calls
//! with the same bytes are the same records on the wire.
//!
//! The digests were taken from the stream as it was before its padded writes
//! stopped copying their input (`2c7ade20`, which copied each frame whole
//! into one buffer and wrote that). A carrier that gathers vectored writes
//! and one that does not must both see what that stream wrote.

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
/// what it sees.
struct Scripted {
    vectored: bool,
    plan: Plan,
    writes: usize,
    flushes: usize,
    seen: Sha256,
    reads: Vec<u8>,
    read: usize,
}

impl Scripted {
    fn new(vectored: bool, plan: Plan, reads: Vec<u8>) -> Self {
        Self {
            vectored,
            plan,
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

fn run(scenario: &Scenario, vectored: bool, plan: Plan) -> String {
    let _draws = seeded::seed(scenario.draws);
    let carrier = Scripted::new(vectored, plan, scenario.reads.clone());
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
    let (reads, hello_len) = padded_server_hello(cipher);
    let mut finished = record(0x14, 1, 1);
    finished.extend_from_slice(&record(0x17, 53, 2));
    let mut data = Vec::new();
    for at in 0..3 {
        data.extend_from_slice(&record(0x17, 1000 + at, 3 + at as u8));
    }
    Scenario {
        name,
        seed: DEFAULT_VISION_SEED,
        draws,
        reads,
        ops: vec![
            Op::Write(client_hello()),
            Op::Read(hello_len),
            Op::Write(finished),
            Op::Write(data),
            Op::Flush,
            Op::Write(record(0x17, 300, 7)),
            Op::Write(pattern(40_000, 8)),
            Op::Flush,
            Op::Shutdown,
        ],
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
                let seen = run(scenario, vectored, *plan);
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
