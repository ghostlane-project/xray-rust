// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Golden frames: the bytes smux v1.5.57 writes in four fixed scenarios
//! (olc/interop/smux/go/golden.go, captured in olc/interop/smux/golden/),
//! and the same scenarios run with olc-smux on both ends.
//!
//! The Rust run uses tokio's paused clock: a 50 ms `quiet()` resolves only
//! once every task is idle, which is what Go's 50 ms of real quiet stands for.

mod common;

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use common::pattern;
use olc_smux::frame::{self, decode_upd, Cmd, Header};
use olc_smux::{Config, Error, Session, Stream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../interop/smux/golden")
}

fn golden(name: &str) -> Vec<u8> {
    let p = golden_dir().join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// golden.go's `goldenCfg`: version 2, keepalive off.
fn golden_cfg(frame: usize, recv: usize, stream: usize) -> Config {
    let mut c = Config::go_default();
    c.keep_alive = None;
    c.max_frame_size = frame;
    c.max_receive_buffer = recv;
    c.max_stream_buffer = stream;
    c.max_stream_send_buffer = 2 * frame;
    c.max_send_buffer = 16 * frame;
    c.verify().unwrap();
    c
}

/// golden.go's `recConn`: records every byte written.
struct Rec {
    inner: DuplexStream,
    out: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for Rec {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Rec {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            self.out.lock().unwrap().extend_from_slice(&buf[..*n]);
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn quiet() {
    tokio::time::sleep(Duration::from_millis(50)).await;
}

async fn read_exactly(st: &mut Stream, n: usize, buf_size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; buf_size];
    let mut out = Vec::new();
    while out.len() < n {
        let k = st.read(&mut buf).await.expect("read");
        assert!(k > 0, "EOF after {} of {n}", out.len());
        out.extend_from_slice(&buf[..k]);
    }
    out
}

async fn expect_eof(st: &mut Stream) {
    let mut b = [0u8; 16];
    assert_eq!(st.read(&mut b).await.expect("read"), 0, "want EOF");
}

type Scenario = fn(Session, Session) -> Pin<Box<dyn std::future::Future<Output = ()>>>;

async fn run(client: Config, server: Config, scenario: Scenario) -> (Vec<u8>, Vec<u8>) {
    common::watchdog();
    let (a, b) = tokio::io::duplex(1 << 20);
    let (c2s, s2c) = (
        Arc::new(Mutex::new(Vec::new())),
        Arc::new(Mutex::new(Vec::new())),
    );
    let (c, cd) = Session::client(
        Rec {
            inner: a,
            out: c2s.clone(),
        },
        client,
    )
    .unwrap();
    let (s, sd) = Session::server(
        Rec {
            inner: b,
            out: s2c.clone(),
        },
        server,
    )
    .unwrap();
    let cd = tokio::spawn(cd);
    let sd = tokio::spawn(sd);
    scenario(c.clone(), s.clone()).await;
    quiet().await;
    c.close().unwrap();
    s.close().unwrap();
    drop((c, s));
    let _ = cd.await;
    let _ = sd.await;
    let c2s = c2s.lock().unwrap().clone();
    let s2c = s2c.lock().unwrap().clone();
    (c2s, s2c)
}

/// golden.go's scenarioBasic, step for step.
fn basic(c: Session, s: Session) -> Pin<Box<dyn std::future::Future<Output = ()>>> {
    Box::pin(async move {
        // 1. The client opens sid 3.
        let mut cs = c.open_stream().await.unwrap();
        assert_eq!(cs.id(), 3);
        let mut ss = s.accept_stream().await.unwrap();
        quiet().await;
        // 2. A zero-length write sends nothing.
        assert_eq!(cs.write(&[]).await.unwrap(), 0);
        // 3. "hello\n"; the server's first read sends UPD(6, 65536).
        cs.write_all(b"hello\n").await.unwrap();
        assert_eq!(read_exactly(&mut ss, 6, 65536).await, b"hello\n");
        quiet().await;
        // 4. 100 bytes back; the client's first read sends UPD(100, 524288).
        ss.write_all(&pattern(100, 1)).await.unwrap();
        assert_eq!(read_exactly(&mut cs, 100, 65536).await, pattern(100, 1));
        quiet().await;
        // 5. One 70000-byte write against the server's 65536 window.
        let w = tokio::spawn(async move {
            cs.write_all(&pattern(70000, 2)).await.unwrap();
            cs
        });
        assert_eq!(read_exactly(&mut ss, 70000, 65536).await, pattern(70000, 2));
        let mut cs = w.await.unwrap();
        quiet().await;
        // 6. The client half-closes; the server reads EOF.
        cs.shutdown().await.unwrap();
        expect_eof(&mut ss).await;
        quiet().await;
        // 7. The server still writes; the client reads it before the server's FIN.
        ss.write_all(&pattern(10, 3)).await.unwrap();
        assert_eq!(read_exactly(&mut cs, 10, 65536).await, pattern(10, 3));
        quiet().await;
        ss.shutdown().await.unwrap();
        expect_eof(&mut cs).await;
        quiet().await;
        // 8. Both FINs are out: both streams are gone, and Close sends nothing.
        assert_eq!(ss.close().await, Err(Error::ClosedPipe));
        assert_eq!(cs.close().await, Err(Error::ClosedPipe));
        quiet().await;
        // 9. sid 5: write and Close before the server reads.
        let mut cs5 = c.open_stream().await.unwrap();
        assert_eq!(cs5.id(), 5);
        cs5.write_all(b"abc").await.unwrap();
        cs5.close().await.unwrap();
        let mut ss5 = s.accept_stream().await.unwrap();
        assert_eq!(read_exactly(&mut ss5, 3, 65536).await, b"abc");
        expect_eof(&mut ss5).await;
        ss5.close().await.unwrap();
        quiet().await;
        // 10. sid 7: CloseWrite then Close sends FIN twice.
        let mut cs7 = c.open_stream().await.unwrap();
        cs7.shutdown().await.unwrap();
        cs7.close().await.unwrap();
        let mut ss7 = s.accept_stream().await.unwrap();
        expect_eof(&mut ss7).await;
        ss7.close().await.unwrap();
        quiet().await;
        // 11. The server opens sid 2.
        let mut ss2 = s.open_stream().await.unwrap();
        assert_eq!(ss2.id(), 2);
        let mut cs2 = c.accept_stream().await.unwrap();
        ss2.write_all(&pattern(5, 4)).await.unwrap();
        assert_eq!(read_exactly(&mut cs2, 5, 65536).await, pattern(5, 4));
        quiet().await;
        cs2.close().await.unwrap();
        expect_eof(&mut ss2).await;
        ss2.close().await.unwrap();
        drop((cs, ss, cs5, ss5, cs7, ss7, cs2, ss2));
    })
}

/// golden.go's scenarioWindow.
fn window(c: Session, s: Session) -> Pin<Box<dyn std::future::Future<Output = ()>>> {
    Box::pin(async move {
        let mut cs = c.open_stream().await.unwrap();
        let mut ss = s.accept_stream().await.unwrap();
        cs.write_all(&[0x5a]).await.unwrap();
        read_exactly(&mut ss, 1, 1000).await;
        quiet().await;
        let w = tokio::spawn(async move {
            cs.write_all(&pattern(1000, 5)).await.unwrap();
            cs
        });
        assert_eq!(read_exactly(&mut ss, 1000, 1000).await, pattern(1000, 5));
        let mut cs = w.await.unwrap();
        quiet().await;
        cs.shutdown().await.unwrap();
        expect_eof(&mut ss).await;
        ss.close().await.unwrap();
        quiet().await;
        assert_eq!(cs.close().await, Err(Error::ClosedPipe));
    })
}

/// golden.go's scenarioMaxFrame.
fn maxframe(c: Session, s: Session) -> Pin<Box<dyn std::future::Future<Output = ()>>> {
    Box::pin(async move {
        let mut cs = c.open_stream().await.unwrap();
        let mut ss = s.accept_stream().await.unwrap();
        cs.write_all(&pattern(65536, 6)).await.unwrap();
        assert_eq!(read_exactly(&mut ss, 65536, 70000).await, pattern(65536, 6));
        quiet().await;
        cs.close().await.unwrap();
        expect_eof(&mut ss).await;
        ss.close().await.unwrap();
    })
}

/// golden.go's scenarioBigRead.
fn bigread(c: Session, s: Session) -> Pin<Box<dyn std::future::Future<Output = ()>>> {
    Box::pin(async move {
        let mut cs = c.open_stream().await.unwrap();
        let mut ss = s.accept_stream().await.unwrap();
        ss.write_all(&pattern(100000, 7)).await.unwrap();
        assert_eq!(
            read_exactly(&mut cs, 100000, 65536).await,
            pattern(100000, 7)
        );
        quiet().await;
        ss.shutdown().await.unwrap();
        expect_eof(&mut cs).await;
        quiet().await;
        cs.shutdown().await.unwrap();
        expect_eof(&mut ss).await;
        quiet().await;
        assert_eq!(cs.close().await, Err(Error::ClosedPipe));
        assert_eq!(ss.close().await, Err(Error::ClosedPipe));
    })
}

const MIB: usize = 1 << 20;
const KIB: usize = 1 << 10;

fn scenarios() -> Vec<(&'static str, Config, Config, Scenario)> {
    vec![
        (
            "basic",
            golden_cfg(32768, 4 * MIB, 512 * KIB),
            golden_cfg(32768, 4 * MIB, 64 * KIB),
            basic,
        ),
        (
            "window",
            golden_cfg(100, 4096, 1000),
            golden_cfg(100, 4096, 300),
            window,
        ),
        (
            "maxframe",
            golden_cfg(65535, 4 * MIB, 512 * KIB),
            golden_cfg(65535, 4 * MIB, 4 * MIB),
            maxframe,
        ),
        (
            "bigread",
            golden_cfg(32768, 4 * MIB, 64 * KIB),
            golden_cfg(32768, 4 * MIB, 512 * KIB),
            bigread,
        ),
    ]
}

fn describe(bytes: &[u8]) -> Vec<String> {
    let mut it = frame::frames(bytes);
    let mut out = Vec::new();
    for f in it.by_ref() {
        let h = f.header;
        let name = match Cmd::from_u8(h.cmd) {
            Some(Cmd::Syn) => "SYN",
            Some(Cmd::Fin) => "FIN",
            Some(Cmd::Psh) => "PSH",
            Some(Cmd::Nop) => "NOP",
            Some(Cmd::Upd) => "UPD",
            None => "???",
        };
        out.push(match Cmd::from_u8(h.cmd) {
            Some(Cmd::Psh) => format!("PSH{}({})", h.sid, h.length),
            Some(Cmd::Upd) => {
                let (c, w) = decode_upd(f.data.try_into().unwrap());
                format!("UPD{}({c},{w})", h.sid)
            }
            _ => format!("{name}{}", h.sid),
        });
    }
    assert!(it.remainder().is_empty(), "trailing bytes");
    out
}

/// The Rust sessions write what smux v1.5.57 writes, byte for byte.
#[tokio::test(start_paused = true)]
async fn rust_writes_the_golden_bytes() {
    for (name, client, server, scenario) in scenarios() {
        let (c2s, s2c) = run(client, server, scenario).await;
        let (want_c2s, want_s2c) = (
            golden(&format!("{name}.c2s")),
            golden(&format!("{name}.s2c")),
        );
        assert_eq!(
            describe(&c2s),
            describe(&want_c2s),
            "{name}.c2s frames differ from smux v1.5.57"
        );
        assert_eq!(
            describe(&s2c),
            describe(&want_s2c),
            "{name}.s2c frames differ from smux v1.5.57"
        );
        assert!(c2s == want_c2s, "{name}.c2s bytes differ");
        assert!(s2c == want_s2c, "{name}.s2c bytes differ");
        eprintln!(
            "GOLDEN {name}: c2s {} bytes, s2c {} bytes identical",
            c2s.len(),
            s2c.len()
        );
    }
}

/// The Go captures parse into valid frames, re-encode to the same bytes,
/// and hold the frames smux's source says they should
/// (smux/stream.go:260-297,533-697, smux/session.go:169-219).
#[test]
fn the_go_captures_parse_and_say_what_smux_does() {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let want = [
        (
            "basic.c2s",
            s(&[
                "SYN3",
                "PSH3(6)",
                "UPD3(100,524288)",
                "PSH3(32768)",
                "PSH3(32768)",
                "PSH3(4464)",
                "FIN3",
                "SYN5",
                "PSH5(3)",
                "FIN5",
                "SYN7",
                "FIN7",
                "FIN7",
                "UPD2(5,524288)",
                "FIN2",
            ]),
        ),
        (
            "basic.s2c",
            s(&[
                "UPD3(6,65536)",
                "PSH3(100)",
                "UPD3(32774,65536)",
                "UPD3(65542,65536)",
                "PSH3(10)",
                "FIN3",
                "UPD5(3,65536)",
                "FIN5",
                "FIN7",
                "SYN2",
                "PSH2(5)",
                "FIN2",
            ]),
        ),
        ("window.c2s", {
            let mut v = s(&["SYN3", "PSH3(1)"]);
            v.extend(std::iter::repeat_n("PSH3(100)".to_string(), 10));
            v.push("FIN3".into());
            v
        }),
        (
            "window.s2c",
            s(&[
                "UPD3(1,300)",
                "UPD3(201,300)",
                "UPD3(401,300)",
                "UPD3(601,300)",
                "UPD3(801,300)",
                "UPD3(1001,300)",
                "FIN3",
            ]),
        ),
        (
            "maxframe.c2s",
            s(&["SYN3", "PSH3(65535)", "PSH3(1)", "FIN3"]),
        ),
        ("maxframe.s2c", s(&["UPD3(65535,4194304)", "FIN3"])),
        (
            "bigread.c2s",
            s(&[
                "SYN3",
                "UPD3(32768,65536)",
                "UPD3(65536,65536)",
                "UPD3(98304,65536)",
                "FIN3",
            ]),
        ),
        (
            "bigread.s2c",
            s(&[
                "PSH3(32768)",
                "PSH3(32768)",
                "PSH3(32768)",
                "PSH3(1696)",
                "FIN3",
            ]),
        ),
    ];
    for (file, frames) in want {
        let bytes = golden(file);
        assert_eq!(describe(&bytes), frames, "{file}");
        let mut again = Vec::new();
        for f in frame::frames(&bytes) {
            f.header
                .validate()
                .unwrap_or_else(|e| panic!("{file}: {e}"));
            assert_eq!(Header::decode(f.header.encode()), f.header);
            f.encode_into(&mut again);
        }
        assert_eq!(again, bytes, "{file} re-encodes to the same bytes");
    }
    // The payloads are the pattern golden.go wrote.
    let c2s = golden("basic.c2s");
    let mut psh = frame::frames(&c2s).filter(|f| f.header.cmd == Cmd::Psh as u8);
    assert_eq!(psh.next().unwrap().data, b"hello\n");
    let big: Vec<u8> = psh.by_ref().take(3).flat_map(|f| f.data.to_vec()).collect();
    assert_eq!(big, pattern(70000, 2));
}
