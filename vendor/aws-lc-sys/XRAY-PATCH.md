# aws-lc-sys 0.45.0: wait for kernel entropy on old Linux kernels

Canonical archive: https://static.crates.io/crates/aws-lc-sys/aws-lc-sys-0.45.0.crate

SHA256: `9bff6c3b54fad79a2e60b8102caf565819711497c1f5f092f49508e2f5c31b27`. Upstream licenses and complete source are retained, including every CMakeLists.txt, the fiat MIT license and the published manifest and lockfile.

One file differs: `aws-lc/crypto/rand_extra/urandom.c`.

Upstream's `ensure_dev_urandom_is_initialized` polls `entropy_avail` with `ioctl(RNDGETENTCNT)` until it reports at least 256 bits. On Linux 3.10, the kernel of Android 6 and 7 and the API 23 and 24 emulators, that count stays between 130 and 190 after the blocking pool is seeded. The loop never ends, so AWS-LC never returns entropy and no ClientHello is written.

The patched function waits for `/dev/random` to become readable instead, the same readiness check `getrandom` 0.2 uses when `SYS_getrandom` is `ENOSYS`. Once that pool is seeded, reading `/dev/urandom` is safe. The wait retries `EINTR` on open and `EINTR` or `EAGAIN` on poll, uses `O_CLOEXEC`, and closes the descriptor. Like upstream, the patch aborts when `/dev/random` cannot be opened or polled: it never seeds a DRBG from an unchecked pool. Other platforms and kernels with `getrandom` keep upstream's behavior.

All other source is unchanged. Apply XRAY-PATCH.diff with zero fuzz.
