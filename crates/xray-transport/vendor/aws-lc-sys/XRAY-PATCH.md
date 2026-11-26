# xray-rust patch of aws-lc-sys 0.45.0

Source: crates.io `aws-lc-sys` 0.45.0 (AWS-LC commit
`02561621ffa4cf17c0c4f70bc11a82df36b42ae9`), with the files Cargo includes
in the published crate only.

One file differs: `aws-lc/crypto/rand_extra/urandom.c`.

Upstream's `ensure_dev_urandom_is_initialized` polls `entropy_avail` with
`ioctl(RNDGETENTCNT)` until it reports at least 256 bits. On Linux 3.10,
the kernel of Android 6 and 7 and the API 23 and 24 emulators, that count
stays between 130 and 190 after the blocking pool is seeded. The loop never
ends, so AWS-LC never returns entropy and no ClientHello is written.

The patched function waits for `/dev/random` to become readable instead, the
same readiness check `getrandom` 0.2 uses when `SYS_getrandom` is `ENOSYS`.
Once that pool is seeded, reading `/dev/urandom` is safe. Nothing in the RNG
algorithm, the key shares, or the ClientHello changed: only the wait for
kernel entropy readiness did.
