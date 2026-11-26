//! REALITY and uTLS-shaped TLS ClientHello generation and handshakes when
//! `SYS_getrandom` fails with `ENOSYS` and `/dev/urandom`'s kernel entropy
//! estimate stays below 256 bits, as on Linux kernels older than 3.17
//! (Android 6 and 7, API 23 and 24).
//!
//! On Linux, each end-to-end test spawns a child process that installs a
//! seccomp-BPF filter before starting Tokio or touching AWS-LC:
//! - `SYS_getrandom` returns `ENOSYS`;
//! - `SYS_madvise(..., MADV_WIPEONFORK)` returns `EINVAL` (added in Linux 4.14);
//! - `SYS_ioctl(..., RNDGETENTCNT, &bits)` traps to `SIGSYS`, writing `160` bits
//!   and returning `0`, reproducing Linux 3.10 where `entropy_avail` stays in
//!   the 130..190 range while modern CI kernels (>= 5.18) hardcode `256`.
//!
//! The child must write its `ClientHello` over a loopback TCP socket, complete
//! the TLS 1.3 handshake with post-quantum hybrid key shares, and produce
//! `ClientHello` bytes whose wire structure, key shares, extensions, and
//! ordering match a process with working `SYS_getrandom`.

#[path = "support/client_hello_draws.rs"]
mod client_hello_draws;

use xray_transport::{
    browser_tls_client_hello_bytes, plain_tls_client_hello_bytes,
    reality_connector::{RealityClientHelloRequest, RealityTlsSessionProvider},
    RustlsRealityTlsSessionProvider, TlsClientConfig,
};

const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
const GROUP_GREASE_CANONICAL: u16 = 0x0a0a;
const GROUP_X25519: u16 = 0x001d;
const GROUP_SECP256R1: u16 = 0x0017;
const GROUP_X25519_MLKEM768: u16 = 0x11ec;
const GROUP_X25519_KYBER768_DRAFT00: u16 = 0x6399;

fn tls_config(fingerprint: &str, alpn: &[&str]) -> TlsClientConfig {
    TlsClientConfig {
        server_name: "www.example.com".to_owned(),
        allow_insecure: false,
        pinned_peer_cert_sha256: Vec::new(),
        verify_peer_cert_by_name: Vec::new(),
        alpn: alpn.iter().map(|proto| (*proto).to_owned()).collect(),
        fingerprint: Some(fingerprint.to_owned()),
    }
}

/// Strips the 5-byte TLS record header after checking record framing.
fn handshake_from_record(record: &[u8]) -> &[u8] {
    assert!(
        record.len() >= 9,
        "TLS record too short: {} bytes",
        record.len()
    );
    assert_eq!(record[0], TLS_RECORD_HANDSHAKE, "expected handshake record");
    assert_eq!(record[1], 0x03, "expected TLS major version 3");
    let body_len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    assert_eq!(
        5 + body_len,
        record.len(),
        "single-record first flight length mismatch"
    );
    let handshake = &record[5..];
    assert_eq!(
        handshake[0], TLS_HANDSHAKE_CLIENT_HELLO,
        "expected ClientHello handshake message"
    );
    let hs_len = (usize::from(handshake[1]) << 16)
        | (usize::from(handshake[2]) << 8)
        | usize::from(handshake[3]);
    assert_eq!(4 + hs_len, handshake.len(), "ClientHello length mismatch");
    handshake
}

/// Extracts `(group, key_exchange_len)` pairs from a ClientHello handshake
/// message, rewriting any GREASE group to `0x0a0a`.
fn key_share_layout(hello: &[u8]) -> Vec<(u16, usize)> {
    let body = client_hello_draws::extension_body(hello, EXT_KEY_SHARE)
        .expect("ClientHello must carry key_share extension");
    assert!(body.len() >= 2, "key_share body too short");
    let shares_len = usize::from(u16::from_be_bytes([body[0], body[1]]));
    assert_eq!(2 + shares_len, body.len(), "key_share list length mismatch");
    let mut cursor = 2;
    let mut out = Vec::new();
    while cursor < body.len() {
        let raw_group = u16::from_be_bytes([body[cursor], body[cursor + 1]]);
        let group = if client_hello_draws::is_grease(raw_group) {
            GROUP_GREASE_CANONICAL
        } else {
            raw_group
        };
        let ke_len = usize::from(u16::from_be_bytes([body[cursor + 2], body[cursor + 3]]));
        cursor += 4 + ke_len;
        assert!(cursor <= body.len(), "truncated key_share entry");
        out.push((group, ke_len));
    }
    out
}

/// Extracts raw `(group, key_exchange_bytes)` for non-GREASE key shares.
fn non_grease_key_shares(hello: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let body = client_hello_draws::extension_body(hello, EXT_KEY_SHARE)
        .expect("ClientHello must carry key_share extension");
    let mut cursor = 2;
    let mut out = Vec::new();
    while cursor < body.len() {
        let group = u16::from_be_bytes([body[cursor], body[cursor + 1]]);
        let ke_len = usize::from(u16::from_be_bytes([body[cursor + 2], body[cursor + 3]]));
        let ke = &body[cursor + 4..cursor + 4 + ke_len];
        cursor += 4 + ke_len;
        if !client_hello_draws::is_grease(group) {
            out.push((group, ke.to_vec()));
        }
    }
    out
}

/// Zeroes only per-connection random material (`random`, `session_id`,
/// `key_share` key-exchange bytes, and outer ECH GREASE random fields) inside a
/// ClientHello handshake message, leaving every type, length, cipher suite,
/// group, signature scheme, and extension position untouched.
fn zero_ephemeral_fields(hello: &[u8]) -> Vec<u8> {
    let mut out = hello.to_vec();
    assert_eq!(out[0], TLS_HANDSHAKE_CLIENT_HELLO);
    // Zero 32-byte random.
    out[6..38].fill(0);
    let session_id_len = usize::from(out[38]);
    let mut cursor = 39;
    out[cursor..cursor + session_id_len].fill(0);
    cursor += session_id_len;

    let cipher_len = usize::from(u16::from_be_bytes([out[cursor], out[cursor + 1]]));
    cursor += 2 + cipher_len;
    let comp_len = usize::from(out[cursor]);
    cursor += 1 + comp_len;
    let ext_total = usize::from(u16::from_be_bytes([out[cursor], out[cursor + 1]]));
    cursor += 2;
    let end = cursor + ext_total;
    assert_eq!(end, out.len());

    while cursor < end {
        let ext_type = u16::from_be_bytes([out[cursor], out[cursor + 1]]);
        let ext_len = usize::from(u16::from_be_bytes([out[cursor + 2], out[cursor + 3]]));
        let body_start = cursor + 4;
        let body_end = body_start + ext_len;
        match ext_type {
            EXT_KEY_SHARE => {
                let mut share = body_start + 2;
                while share < body_end {
                    let ke_len = usize::from(u16::from_be_bytes([out[share + 2], out[share + 3]]));
                    out[share + 4..share + 4 + ke_len].fill(0);
                    share += 4 + ke_len;
                }
                assert_eq!(share, body_end);
            }
            EXT_ENCRYPTED_CLIENT_HELLO if out.get(body_start) == Some(&0) => {
                // Outer ClientHello ECH GREASE:
                // [0]: type=0, [1..3]: kdf_id, [3..5]: aead_id (Firefox coin-flips),
                // [5]: config_id, [6..8]: enc_len, [8..8+enc_len]: enc,
                // [8+enc_len..10+enc_len]: payload_len, [..]: payload.
                out[body_start + 3..body_start + 5].copy_from_slice(&[0x00, 0x01]);
                out[body_start + 5] = 0;
                let enc_len = usize::from(u16::from_be_bytes([
                    out[body_start + 6],
                    out[body_start + 7],
                ]));
                let enc_start = body_start + 8;
                let enc_end = enc_start + enc_len;
                out[enc_start..enc_end].fill(0);
                let payload_len = usize::from(u16::from_be_bytes([out[enc_end], out[enc_end + 1]]));
                let payload_start = enc_end + 2;
                assert_eq!(payload_start + payload_len, body_end);
                out[payload_start..body_end].fill(0);
            }
            _ => {}
        }
        cursor = body_end;
    }
    out
}

/// Asserts that `actual` and `expected` ClientHello handshake messages have
/// identical key share layouts, identical extension sets, non-zero random key
/// material, and identical wire bytes once per-connection draws are normalized.
/// For fixed-order profiles (`!shuffles(fingerprint)`), extension order and
/// wire offsets are asserted without sorting or removing extensions.
fn assert_hello_shape_unchanged(fingerprint: &str, actual: &[u8], expected: &[u8]) {
    assert_eq!(
        key_share_layout(actual),
        key_share_layout(expected),
        "{fingerprint}: key_share groups or lengths changed"
    );
    for (group, ke) in non_grease_key_shares(actual) {
        assert!(
            ke.iter().any(|&b| b != 0),
            "{fingerprint}: key_share 0x{group:04x} is all-zero"
        );
    }
    assert!(
        actual[6..38].iter().any(|&b| b != 0),
        "{fingerprint}: ClientHello.random is all-zero"
    );

    let shuffles = client_hello_draws::shuffles(fingerprint);
    let actual_zeroed = zero_ephemeral_fields(actual);
    let expected_zeroed = zero_ephemeral_fields(expected);

    if !shuffles {
        // Fixed extension order and fixed ECH length: every byte in wire order
        // must match once random fields are zeroed and GREASE is canonicalized.
        let actual_canon = client_hello_draws::canonical_client_hello(&actual_zeroed, false);
        let expected_canon = client_hello_draws::canonical_client_hello(&expected_zeroed, false);
        assert_eq!(
            actual_canon, expected_canon,
            "{fingerprint}: fixed-order ClientHello wire bytes changed"
        );
    } else {
        if client_hello_draws::CHROME_ECH_FINGERPRINTS.contains(&fingerprint) {
            let ech_len = client_hello_draws::ech_length(actual)
                .expect("Chrome profile must carry ECH GREASE");
            assert!(
                client_hello_draws::CHROME_ECH_LENGTHS.contains(&ech_len),
                "{fingerprint}: unexpected ECH GREASE length {ech_len}"
            );
        }
        let actual_types = client_hello_draws::extension_types(
            &client_hello_draws::canonical_client_hello(&actual_zeroed, false),
        );
        let expected_types = client_hello_draws::extension_types(
            &client_hello_draws::canonical_client_hello(&expected_zeroed, false),
        );
        assert_eq!(
            actual_types.first(),
            Some(&GROUP_GREASE_CANONICAL),
            "{fingerprint}: leading GREASE extension moved"
        );
        let mut actual_sorted = actual_types.clone();
        let mut expected_sorted = expected_types.clone();
        actual_sorted.sort_unstable();
        expected_sorted.sort_unstable();
        assert_eq!(
            actual_sorted, expected_sorted,
            "{fingerprint}: extension multiset changed"
        );

        let actual_canon = client_hello_draws::without_drawn_lengths(
            &client_hello_draws::canonical_client_hello(&actual_zeroed, true),
        );
        let expected_canon = client_hello_draws::without_drawn_lengths(
            &client_hello_draws::canonical_client_hello(&expected_zeroed, true),
        );
        assert_eq!(
            actual_canon, expected_canon,
            "{fingerprint}: canonical ClientHello bytes changed"
        );
    }
}

#[test]
fn reality_and_shaped_tls_post_quantum_hello_layouts_match_profiles() {
    let provider = RustlsRealityTlsSessionProvider::new();

    for (fp, expected_shares) in [
        (
            "chrome",
            vec![
                (GROUP_GREASE_CANONICAL, 1),
                (GROUP_X25519_MLKEM768, 1216),
                (GROUP_X25519, 32),
            ],
        ),
        (
            "safari",
            vec![
                (GROUP_GREASE_CANONICAL, 1),
                (GROUP_X25519_MLKEM768, 1216),
                (GROUP_X25519, 32),
            ],
        ),
        (
            "firefox",
            vec![
                (GROUP_X25519_MLKEM768, 1216),
                (GROUP_X25519, 32),
                (GROUP_SECP256R1, 65),
            ],
        ),
        (
            "hellochrome_120_pq",
            vec![
                (GROUP_GREASE_CANONICAL, 1),
                (GROUP_X25519_KYBER768_DRAFT00, 1216),
                (GROUP_X25519, 32),
            ],
        ),
    ] {
        let first = provider
            .create_session(RealityClientHelloRequest {
                server_name: "www.example.com",
                fingerprint: fp,
            })
            .expect("create first REALITY session")
            .prepared_client_hello()
            .expect("first prepared REALITY ClientHello");
        let second = provider
            .create_session(RealityClientHelloRequest {
                server_name: "www.example.com",
                fingerprint: fp,
            })
            .expect("create second REALITY session")
            .prepared_client_hello()
            .expect("second prepared REALITY ClientHello");

        assert_eq!(key_share_layout(&first.raw_client_hello), expected_shares);
        assert_hello_shape_unchanged(fp, &first.raw_client_hello, &second.raw_client_hello);
        assert_ne!(
            first.hello_random, second.hello_random,
            "{fp}: consecutive REALITY hellos reused random"
        );
        assert_ne!(
            non_grease_key_shares(&first.raw_client_hello),
            non_grease_key_shares(&second.raw_client_hello),
            "{fp}: consecutive REALITY hellos reused key shares"
        );

        let tls_cfg = tls_config(fp, &["h2", "http/1.1"]);
        let plain_a = plain_tls_client_hello_bytes(&tls_cfg).expect("plain TLS hello A");
        let plain_b = plain_tls_client_hello_bytes(&tls_cfg).expect("plain TLS hello B");
        let hs_a = handshake_from_record(&plain_a);
        let hs_b = handshake_from_record(&plain_b);
        assert_eq!(key_share_layout(hs_a), expected_shares);
        assert_hello_shape_unchanged(fp, hs_a, hs_b);

        let browser_a = browser_tls_client_hello_bytes(&tls_cfg).expect("browser TLS hello A");
        let browser_b = browser_tls_client_hello_bytes(&tls_cfg).expect("browser TLS hello B");
        assert_hello_shape_unchanged(
            fp,
            handshake_from_record(&browser_a),
            handshake_from_record(&browser_b),
        );
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux_enosys {
    use super::*;
    use std::{
        env, io,
        io::Read as _,
        net::{Ipv4Addr, SocketAddr},
        pin::Pin,
        process::{Command, Stdio},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        task::{Context, Poll},
        thread,
        time::{Duration, Instant},
    };

    use hmac::{Hmac, KeyInit, Mac};
    use rustls::{
        pki_types::{CertificateDer, PrivateKeyDer},
        SignatureScheme,
    };
    use sha2::{Digest, Sha256, Sha512};
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
        net::{TcpListener, TcpStream},
        sync::oneshot,
    };
    use tokio_rustls::TlsAcceptor;
    use x25519_dalek::{PublicKey, StaticSecret};
    use xray_routing::{Network, Target, TargetAddr};
    use xray_transport::{
        reality::derive_reality_auth_key, stream::TransportLayer, ConnectorConfig,
        RealityClientConfig, TlsConnector, TransportDialer,
    };

    const CHILD_MODE_ENV: &str = "XRAY_GETRANDOM_ENOSYS_CHILD";
    const CHILD_ADDR_ENV: &str = "XRAY_GETRANDOM_ENOSYS_ADDR";
    const CHILD_PIN_ENV: &str = "XRAY_GETRANDOM_ENOSYS_PIN";
    const CHILD_DEADLINE: Duration = Duration::from_secs(4);
    const SERVER_SECRET: [u8; 32] = [0x42; 32];
    const SHORT_ID: [u8; 4] = [0x01, 0x02, 0x03, 0x04];

    // Linux seccomp-BPF and random ioctl constants (<linux/seccomp.h>,
    // <linux/filter.h>, <linux/audit.h>, <linux/random.h>).
    const SECCOMP_MODE_FILTER: libc::c_int = 2;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const RNDGETENTCNT_IOCTL: u32 = 0x8004_5200;
    const MADV_WIPEONFORK_ADVICE: u32 = 18;
    const LOW_ENTROPY_BITS: libc::c_int = 160;

    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH_CURRENT: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH_CURRENT: u32 = 0xc000_00b7;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[repr(C)]
    struct SockFprog {
        len: libc::c_ushort,
        filter: *const SockFilter,
    }

    static RNDGETENTCNT_TRAPS: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn sigsys_rndgetentcnt_handler(
        _sig: libc::c_int,
        _info: *mut libc::siginfo_t,
        uctx: *mut libc::c_void,
    ) {
        RNDGETENTCNT_TRAPS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: kernel delivers valid ucontext_t for SECCOMP_RET_TRAP on
        // ioctl(fd, RNDGETENTCNT, &entropy_bits), where arg2 holds a valid
        // int* in the caller's stack frame.
        unsafe {
            let uc = &mut *(uctx as *mut libc::ucontext_t);
            #[cfg(target_arch = "x86_64")]
            {
                let ptr = uc.uc_mcontext.gregs[libc::REG_RDX as usize] as usize as *mut libc::c_int;
                ptr.write(LOW_ENTROPY_BITS);
                uc.uc_mcontext.gregs[libc::REG_RAX as usize] = 0;
            }
            #[cfg(target_arch = "aarch64")]
            {
                let ptr = uc.uc_mcontext.regs[2] as usize as *mut libc::c_int;
                ptr.write(LOW_ENTROPY_BITS);
                uc.uc_mcontext.regs[0] = 0;
            }
        }
    }

    /// Emulates a Linux 3.10 kernel for the current single-threaded child
    /// process and all threads it later spawns:
    /// - `SYS_getrandom` fails with `ENOSYS`;
    /// - `SYS_madvise` with `MADV_WIPEONFORK` fails with `EINVAL`;
    /// - `SYS_ioctl` with `RNDGETENTCNT` writes `160` bits (< 256) and returns 0.
    fn install_kernel_3_10_entropy_seccomp() {
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGSYS);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()),
                0,
                "unblock SIGSYS"
            );

            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = sigsys_rndgetentcnt_handler as *const () as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            sa.sa_flags = libc::SA_SIGINFO | libc::SA_NODEFER;
            assert_eq!(
                libc::sigaction(libc::SIGSYS, &sa, std::ptr::null_mut()),
                0,
                "install SIGSYS handler"
            );

            assert_eq!(
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
                0,
                "PR_SET_NO_NEW_PRIVS failed"
            );

            // seccomp_data layout (little-endian 64-bit):
            //   offset 0:  nr (u32)
            //   offset 4:  arch (u32)
            //   offset 24: args[1] low 32 bits (ioctl request)
            //   offset 32: args[2] low 32 bits (madvise advice)
            let filter = [
                // [0] Load arch; if != AUDIT_ARCH_CURRENT, jump to ALLOW [10].
                SockFilter {
                    code: BPF_LD_W_ABS,
                    jt: 0,
                    jf: 0,
                    k: 4,
                },
                SockFilter {
                    code: BPF_JMP_JEQ_K,
                    jt: 0,
                    jf: 8,
                    k: AUDIT_ARCH_CURRENT,
                },
                // [2] Load syscall nr.
                SockFilter {
                    code: BPF_LD_W_ABS,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                // [3] If nr == SYS_getrandom -> return ENOSYS [4].
                SockFilter {
                    code: BPF_JMP_JEQ_K,
                    jt: 0,
                    jf: 1,
                    k: libc::SYS_getrandom as u32,
                },
                // [4] ENOSYS
                SockFilter {
                    code: BPF_RET_K,
                    jt: 0,
                    jf: 0,
                    k: SECCOMP_RET_ERRNO | (libc::ENOSYS as u32),
                },
                // [5] If nr == SYS_ioctl -> check request [6], else jump to [8].
                SockFilter {
                    code: BPF_JMP_JEQ_K,
                    jt: 0,
                    jf: 2,
                    k: libc::SYS_ioctl as u32,
                },
                // [6] Load low 32 bits of args[1]; if RNDGETENTCNT -> TRAP [7], else ALLOW [10].
                SockFilter {
                    code: BPF_LD_W_ABS,
                    jt: 0,
                    jf: 0,
                    k: 24,
                },
                SockFilter {
                    code: BPF_JMP_JEQ_K,
                    jt: 4,
                    jf: 2,
                    k: RNDGETENTCNT_IOCTL,
                },
                // [8] If nr == SYS_madvise -> check advice [9], else ALLOW [10].
                SockFilter {
                    code: BPF_JMP_JEQ_K,
                    jt: 0,
                    jf: 1,
                    k: libc::SYS_madvise as u32,
                },
                // [9] Load low 32 bits of args[2]; if MADV_WIPEONFORK -> EINVAL [11], else ALLOW [10].
                SockFilter {
                    code: BPF_LD_W_ABS,
                    jt: 0,
                    jf: 0,
                    k: 32,
                },
                SockFilter {
                    code: BPF_JMP_JEQ_K,
                    jt: 2,
                    jf: 0,
                    k: MADV_WIPEONFORK_ADVICE,
                },
                // [11] ALLOW
                SockFilter {
                    code: BPF_RET_K,
                    jt: 0,
                    jf: 0,
                    k: SECCOMP_RET_ALLOW,
                },
                // [12] TRAP (SIGSYS) for RNDGETENTCNT
                SockFilter {
                    code: BPF_RET_K,
                    jt: 0,
                    jf: 0,
                    k: SECCOMP_RET_TRAP,
                },
                // [13] EINVAL for MADV_WIPEONFORK
                SockFilter {
                    code: BPF_RET_K,
                    jt: 0,
                    jf: 0,
                    k: SECCOMP_RET_ERRNO | (libc::EINVAL as u32),
                },
            ];
            let prog = SockFprog {
                len: filter.len() as libc::c_ushort,
                filter: filter.as_ptr(),
            };
            assert_eq!(
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    SECCOMP_MODE_FILTER,
                    &prog as *const SockFprog
                ),
                0,
                "PR_SET_SECCOMP failed"
            );

            // Self-verify the emulated kernel 3.10 environment before any TLS call.
            let mut probe = 0u8;
            let gr = libc::syscall(libc::SYS_getrandom, &mut probe as *mut u8, 1usize, 0usize);
            assert_eq!(gr, -1, "SYS_getrandom must fail under seccomp");
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ENOSYS),
                "SYS_getrandom must fail with ENOSYS"
            );

            let fd = libc::open(c"/dev/urandom".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
            assert!(fd >= 0, "open /dev/urandom");
            let mut bits: libc::c_int = -1;
            let rc = libc::ioctl(fd, RNDGETENTCNT_IOCTL as libc::c_ulong, &mut bits);
            libc::close(fd);
            assert_eq!(rc, 0, "RNDGETENTCNT ioctl must succeed via SIGSYS trap");
            assert_eq!(
                bits, LOW_ENTROPY_BITS,
                "RNDGETENTCNT must report < 256 bits"
            );
            // Reset trap counter after the self-check so tests can observe
            // whether AWS-LC itself ever entered ensure_dev_urandom_is_initialized.
            RNDGETENTCNT_TRAPS.store(0, Ordering::SeqCst);
        }
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write as _;
            let _ = write!(&mut out, "{b:02x}");
        }
        out
    }

    fn hex_decode(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0, "hex string must have even length");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex byte"))
            .collect()
    }

    /// Reads one TLS record (5-byte header + payload) from `stream`.
    async fn read_tls_record(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
        let mut record = vec![0u8; 5];
        stream.read_exact(&mut record).await?;
        let len = usize::from(u16::from_be_bytes([record[3], record[4]]));
        record.resize(5 + len, 0);
        stream.read_exact(&mut record[5..]).await?;
        Ok(record)
    }

    struct Replayed<S> {
        head: Vec<u8>,
        at: usize,
        rest: S,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for Replayed<S> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.at < this.head.len() {
                let take = (this.head.len() - this.at).min(output.remaining());
                output.put_slice(&this.head[this.at..this.at + take]);
                this.at += take;
                return Poll::Ready(Ok(()));
            }
            Pin::new(&mut this.rest).poll_read(cx, output)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for Replayed<S> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().rest).poll_write(cx, input)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().rest).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().rest).poll_shutdown(cx)
        }
    }

    #[derive(Debug)]
    struct SignsEd25519(Arc<dyn rustls::sign::SigningKey>);

    impl rustls::sign::SigningKey for SignsEd25519 {
        fn choose_scheme(
            &self,
            _offered: &[SignatureScheme],
        ) -> Option<Box<dyn rustls::sign::Signer>> {
            self.0.choose_scheme(&[SignatureScheme::ED25519])
        }

        fn algorithm(&self) -> rustls::SignatureAlgorithm {
            self.0.algorithm()
        }
    }

    fn reality_server_config(secret: [u8; 32], client_hello: &[u8]) -> Arc<rustls::ServerConfig> {
        let random: [u8; 32] = client_hello[6..38].try_into().expect("32-byte random");
        let shares = non_grease_key_shares(client_hello);
        let client_x25519: [u8; 32] = shares
            .iter()
            .find(|(g, _)| *g == GROUP_X25519)
            .and_then(|(_, ke)| ke.as_slice().try_into().ok())
            .or_else(|| {
                shares
                    .iter()
                    .find(|(g, _)| *g == GROUP_X25519_MLKEM768)
                    .and_then(|(_, ke)| ke.last_chunk::<32>().copied())
            })
            .expect("ClientHello must include X25519 or X25519MLKEM768 key share");

        let shared = StaticSecret::from(secret)
            .diffie_hellman(&PublicKey::from(client_x25519))
            .to_bytes();
        let auth_key = derive_reality_auth_key(&shared, &random).expect("derive REALITY auth key");

        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("Ed25519 key");
        let mut cert_der = rcgen::CertificateParams::new(vec!["www.example.com".to_owned()])
            .expect("cert params")
            .self_signed(&key)
            .expect("self-signed cert")
            .der()
            .to_vec();
        let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(&auth_key).expect("HMAC key");
        mac.update(key.public_key_raw());
        let tag = mac.finalize().into_bytes();
        let sig_offset = cert_der.len() - tag.len();
        cert_der[sig_offset..].copy_from_slice(&tag);

        let signer = rustls::crypto::aws_lc_rs::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
            key.serialize_der().into(),
        ))
        .expect("Ed25519 signer");

        Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("TLS versions")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                rustls::sign::CertifiedKey::new(
                    vec![CertificateDer::from(cert_der)],
                    Arc::new(SignsEd25519(signer)),
                ),
            ))),
        )
    }

    fn run_reality_child() {
        install_kernel_3_10_entropy_seccomp();
        let addr: SocketAddr = env::var(CHILD_ADDR_ENV)
            .expect("child server addr")
            .parse()
            .expect("parse server addr");
        let server_pub = PublicKey::from(&StaticSecret::from(SERVER_SECRET)).to_bytes();

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build child Tokio runtime");

        rt.block_on(async move {
            let dialer = TransportDialer::system().expect("system dialer");
            let target = Target::new(
                TargetAddr::Domain("www.example.com".to_owned()),
                addr.port(),
                Network::Tcp,
            );
            let config = ConnectorConfig::Reality(RealityClientConfig {
                server_name: "www.example.com".to_owned(),
                fingerprint: "chrome".to_owned(),
                public_key: server_pub,
                short_id: SHORT_ID.to_vec(),
                spider_x: "/".to_owned(),
                mldsa65_verify: None,
            });
            let mut stream = dialer
                .connect_stream(&config, &TransportLayer::Raw, &target, &[addr], None)
                .await
                .expect("REALITY dial and handshake must succeed under SYS_getrandom=ENOSYS");
            stream
                .write_all(b"reality-ping")
                .await
                .expect("write REALITY payload");
            stream.flush().await.expect("flush REALITY payload");
            let mut reply = [0u8; 12];
            stream
                .read_exact(&mut reply)
                .await
                .expect("read REALITY reply");
            assert_eq!(&reply, b"reality-pong");
        });

        let provider = RustlsRealityTlsSessionProvider::new();
        for fp in ["chrome", "safari", "firefox", "hellochrome_120_pq"] {
            let first = provider
                .create_session(RealityClientHelloRequest {
                    server_name: "www.example.com",
                    fingerprint: fp,
                })
                .expect("child REALITY session A")
                .prepared_client_hello()
                .expect("child REALITY hello A");
            let second = provider
                .create_session(RealityClientHelloRequest {
                    server_name: "www.example.com",
                    fingerprint: fp,
                })
                .expect("child REALITY session B")
                .prepared_client_hello()
                .expect("child REALITY hello B");
            assert_ne!(first.hello_random, second.hello_random);
            assert_ne!(
                non_grease_key_shares(&first.raw_client_hello),
                non_grease_key_shares(&second.raw_client_hello)
            );
            println!("HELLO:{fp}:{}", hex_encode(&first.raw_client_hello));
        }
        println!(
            "RNDGETENTCNT_TRAPS:{}",
            RNDGETENTCNT_TRAPS.load(Ordering::SeqCst)
        );
    }

    fn run_shaped_tls_child() {
        install_kernel_3_10_entropy_seccomp();
        let addr: SocketAddr = env::var(CHILD_ADDR_ENV)
            .expect("child server addr")
            .parse()
            .expect("parse server addr");
        let pin_bytes = hex_decode(&env::var(CHILD_PIN_ENV).expect("child cert pin"));
        let pin: [u8; 32] = pin_bytes.try_into().expect("32-byte SHA-256 pin");

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build child Tokio runtime");

        rt.block_on(async move {
            let connector = TlsConnector::system().expect("system TLS connector");
            let cfg = TlsClientConfig {
                server_name: "www.example.com".to_owned(),
                allow_insecure: false,
                pinned_peer_cert_sha256: vec![pin],
                verify_peer_cert_by_name: Vec::new(),
                alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
                fingerprint: Some("chrome".to_owned()),
            };
            let mut stream = connector
                .connect_socket_addr(addr, &cfg)
                .await
                .expect("shaped TLS dial and handshake must succeed under SYS_getrandom=ENOSYS");
            stream
                .write_all(b"tls-ping")
                .await
                .expect("write TLS payload");
            stream.flush().await.expect("flush TLS payload");
            let mut reply = [0u8; 8];
            stream.read_exact(&mut reply).await.expect("read TLS reply");
            assert_eq!(&reply, b"tls-pong");
        });

        for fp in ["chrome", "safari", "firefox", "hellochrome_120_pq"] {
            let cfg = tls_config(fp, &["h2", "http/1.1"]);
            let plain_a = plain_tls_client_hello_bytes(&cfg).expect("child plain TLS hello A");
            let plain_b = plain_tls_client_hello_bytes(&cfg).expect("child plain TLS hello B");
            let hs_a = handshake_from_record(&plain_a);
            let hs_b = handshake_from_record(&plain_b);
            assert_ne!(&hs_a[6..38], &hs_b[6..38]);
            assert_ne!(non_grease_key_shares(hs_a), non_grease_key_shares(hs_b));
            println!("PLAIN:{fp}:{}", hex_encode(hs_a));

            let browser = browser_tls_client_hello_bytes(&cfg).expect("child browser TLS hello");
            println!(
                "BROWSER:{fp}:{}",
                hex_encode(handshake_from_record(&browser))
            );
        }
        println!(
            "RNDGETENTCNT_TRAPS:{}",
            RNDGETENTCNT_TRAPS.load(Ordering::SeqCst)
        );
    }

    fn wait_for_child(
        mut child: std::process::Child,
        label: &str,
    ) -> (std::process::ExitStatus, String, String) {
        let mut stdout_pipe = child.stdout.take().expect("child stdout pipe");
        let mut stderr_pipe = child.stderr.take().expect("child stderr pipe");
        let out_handle = thread::spawn(move || {
            let mut s = String::new();
            let _ = stdout_pipe.read_to_string(&mut s);
            s
        });
        let err_handle = thread::spawn(move || {
            let mut s = String::new();
            let _ = stderr_pipe.read_to_string(&mut s);
            s
        });

        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().expect("poll child status") {
                break status;
            }
            if start.elapsed() >= CHILD_DEADLINE {
                let _ = child.kill();
                let _ = child.wait();
                let stdout = out_handle.join().unwrap_or_default();
                let stderr = err_handle.join().unwrap_or_default();
                panic!(
                    "{label} child timed out after {:?} under SYS_getrandom=ENOSYS \
                     and RNDGETENTCNT={LOW_ENTROPY_BITS} bits.\nstdout:\n{stdout}\nstderr:\n{stderr}",
                    CHILD_DEADLINE
                );
            }
            thread::sleep(Duration::from_millis(25));
        };

        let stdout = out_handle.join().unwrap_or_default();
        let stderr = err_handle.join().unwrap_or_default();
        (status, stdout, stderr)
    }

    #[test]
    fn reality_hello_and_handshake_work_without_getrandom() {
        if env::var(CHILD_MODE_ENV).as_deref() == Ok("reality") {
            run_reality_child();
            return;
        }

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("parent Tokio runtime");

        let (addr, rx) = rt.block_on(async {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind loopback REALITY listener");
            let addr = listener.local_addr().expect("listener addr");
            let (tx, rx) = oneshot::channel::<Vec<u8>>();
            tokio::spawn(async move {
                let Ok((mut tcp, _)) = listener.accept().await else {
                    return;
                };
                let Ok(record) = read_tls_record(&mut tcp).await else {
                    return;
                };
                let client_hello = handshake_from_record(&record).to_vec();
                let server_cfg = reality_server_config(SERVER_SECRET, &client_hello);
                let _ = tx.send(client_hello);
                let replayed = Replayed {
                    head: record,
                    at: 0,
                    rest: tcp,
                };
                if let Ok(mut tls) = TlsAcceptor::from(server_cfg).accept(replayed).await {
                    let mut req = [0u8; 12];
                    if tls.read_exact(&mut req).await.is_ok() && &req == b"reality-ping" {
                        let _ = tls.write_all(b"reality-pong").await;
                        let _ = tls.shutdown().await;
                    }
                }
            });
            (addr, rx)
        });

        let child = Command::new(env::current_exe().expect("current test binary"))
            .env(CHILD_MODE_ENV, "reality")
            .env(CHILD_ADDR_ENV, addr.to_string())
            .args([
                "--exact",
                "linux_enosys::reality_hello_and_handshake_work_without_getrandom",
                "--nocapture",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn REALITY ENOSYS child");

        let (status, stdout, stderr) = wait_for_child(child, "REALITY");
        assert!(
            status.success(),
            "REALITY ENOSYS child failed with {status}:\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );

        let wire_hello = rt
            .block_on(async { tokio::time::timeout(Duration::from_secs(1), rx).await })
            .expect("server must receive REALITY ClientHello")
            .expect("REALITY ClientHello channel");

        // Compare wire ClientHello and every profile hello from the ENOSYS child
        // against hellos built in this normal SYS_getrandom parent process.
        let parent_provider = RustlsRealityTlsSessionProvider::new();
        let parent_chrome = parent_provider
            .create_session(RealityClientHelloRequest {
                server_name: "www.example.com",
                fingerprint: "chrome",
            })
            .expect("parent REALITY chrome session")
            .prepared_client_hello()
            .expect("parent REALITY chrome hello");
        assert_eq!(
            key_share_layout(&wire_hello),
            vec![
                (GROUP_GREASE_CANONICAL, 1),
                (GROUP_X25519_MLKEM768, 1216),
                (GROUP_X25519, 32),
            ]
        );
        assert_hello_shape_unchanged("chrome", &wire_hello, &parent_chrome.raw_client_hello);

        let mut seen_profiles = Vec::new();
        let mut traps = None;
        for line in stdout.lines() {
            if let Some(rest) = line.strip_prefix("HELLO:") {
                let (fp, hex) = rest.split_once(':').expect("HELLO:<fp>:<hex>");
                let child_hello = hex_decode(hex);
                let parent_hello = parent_provider
                    .create_session(RealityClientHelloRequest {
                        server_name: "www.example.com",
                        fingerprint: fp,
                    })
                    .expect("parent REALITY session")
                    .prepared_client_hello()
                    .expect("parent REALITY hello");
                assert_hello_shape_unchanged(fp, &child_hello, &parent_hello.raw_client_hello);
                seen_profiles.push(fp.to_owned());
            } else if let Some(n) = line.strip_prefix("RNDGETENTCNT_TRAPS:") {
                traps = Some(n.parse::<usize>().expect("trap count"));
            }
        }
        assert_eq!(
            seen_profiles,
            ["chrome", "safari", "firefox", "hellochrome_120_pq"]
        );
        assert_eq!(
            traps,
            Some(0),
            "AWS-LC must not enter ensure_dev_urandom_is_initialized when getrandom is ENOSYS"
        );
    }

    #[test]
    fn shaped_tls_hello_and_handshake_work_without_getrandom() {
        if env::var(CHILD_MODE_ENV).as_deref() == Ok("shaped_tls") {
            run_shaped_tls_child();
            return;
        }

        let certified = rcgen::generate_simple_self_signed(vec!["www.example.com".to_owned()])
            .expect("generate self-signed server cert");
        let cert_der = certified.cert.der().clone();
        let pin: [u8; 32] = Sha256::digest(cert_der.as_ref()).into();
        let key_der = PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into());
        let mut server_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("server TLS versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server TLS config");
        server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let server_cfg = Arc::new(server_cfg);

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("parent Tokio runtime");

        let (addr, rx) = rt.block_on(async {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind loopback TLS listener");
            let addr = listener.local_addr().expect("listener addr");
            let (tx, rx) = oneshot::channel::<Vec<u8>>();
            tokio::spawn(async move {
                let Ok((mut tcp, _)) = listener.accept().await else {
                    return;
                };
                let Ok(record) = read_tls_record(&mut tcp).await else {
                    return;
                };
                let client_hello = handshake_from_record(&record).to_vec();
                let _ = tx.send(client_hello);
                let replayed = Replayed {
                    head: record,
                    at: 0,
                    rest: tcp,
                };
                if let Ok(mut tls) = TlsAcceptor::from(server_cfg).accept(replayed).await {
                    let (_, conn) = tls.get_ref();
                    assert_eq!(
                        conn.negotiated_key_exchange_group()
                            .map(|kx| u16::from(kx.name())),
                        Some(GROUP_X25519_MLKEM768),
                        "server must negotiate X25519MLKEM768 with shaped TLS client"
                    );
                    let mut req = [0u8; 8];
                    if tls.read_exact(&mut req).await.is_ok() && &req == b"tls-ping" {
                        let _ = tls.write_all(b"tls-pong").await;
                        let _ = tls.shutdown().await;
                    }
                }
            });
            (addr, rx)
        });

        let child = Command::new(env::current_exe().expect("current test binary"))
            .env(CHILD_MODE_ENV, "shaped_tls")
            .env(CHILD_ADDR_ENV, addr.to_string())
            .env(CHILD_PIN_ENV, hex_encode(&pin))
            .args([
                "--exact",
                "linux_enosys::shaped_tls_hello_and_handshake_work_without_getrandom",
                "--nocapture",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn shaped TLS ENOSYS child");

        let (status, stdout, stderr) = wait_for_child(child, "shaped TLS");
        assert!(
            status.success(),
            "shaped TLS ENOSYS child failed with {status}:\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );

        let wire_hello = rt
            .block_on(async { tokio::time::timeout(Duration::from_secs(1), rx).await })
            .expect("server must receive shaped TLS ClientHello")
            .expect("shaped TLS ClientHello channel");

        let parent_chrome_cfg = tls_config("chrome", &["h2", "http/1.1"]);
        let parent_chrome =
            plain_tls_client_hello_bytes(&parent_chrome_cfg).expect("parent plain TLS hello");
        assert_eq!(
            key_share_layout(&wire_hello),
            vec![
                (GROUP_GREASE_CANONICAL, 1),
                (GROUP_X25519_MLKEM768, 1216),
                (GROUP_X25519, 32),
            ]
        );
        assert_hello_shape_unchanged("chrome", &wire_hello, handshake_from_record(&parent_chrome));

        let mut seen_plain = Vec::new();
        let mut seen_browser = Vec::new();
        let mut traps = None;
        for line in stdout.lines() {
            if let Some(rest) = line.strip_prefix("PLAIN:") {
                let (fp, hex) = rest.split_once(':').expect("PLAIN:<fp>:<hex>");
                let child_hs = hex_decode(hex);
                let parent_rec = plain_tls_client_hello_bytes(&tls_config(fp, &["h2", "http/1.1"]))
                    .expect("parent plain TLS hello");
                assert_hello_shape_unchanged(fp, &child_hs, handshake_from_record(&parent_rec));
                seen_plain.push(fp.to_owned());
            } else if let Some(rest) = line.strip_prefix("BROWSER:") {
                let (fp, hex) = rest.split_once(':').expect("BROWSER:<fp>:<hex>");
                let child_hs = hex_decode(hex);
                let parent_rec =
                    browser_tls_client_hello_bytes(&tls_config(fp, &["h2", "http/1.1"]))
                        .expect("parent browser TLS hello");
                assert_hello_shape_unchanged(fp, &child_hs, handshake_from_record(&parent_rec));
                seen_browser.push(fp.to_owned());
            } else if let Some(n) = line.strip_prefix("RNDGETENTCNT_TRAPS:") {
                traps = Some(n.parse::<usize>().expect("trap count"));
            }
        }
        assert_eq!(
            seen_plain,
            ["chrome", "safari", "firefox", "hellochrome_120_pq"]
        );
        assert_eq!(
            seen_browser,
            ["chrome", "safari", "firefox", "hellochrome_120_pq"]
        );
        assert_eq!(
            traps,
            Some(0),
            "AWS-LC must not enter ensure_dev_urandom_is_initialized when getrandom is ENOSYS"
        );
    }
}
