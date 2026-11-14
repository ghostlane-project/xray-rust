#!/usr/bin/env python3
"""Shapes of STUN binding requests and DTLS ClientHellos, from pcaps or from the probes' logs.

  wire.py stun  <file>...          the attribute order of every distinct binding request
  wire.py hello <file>...          each first ClientHello: version, suites, groups, extensions
  wire.py compare <label=file[:TX|:RX]>...  both, side by side per label, extensions as sets

A file is a pcap/pcapng (UDP payloads are read, any link type tcpdump -i any writes) or a text
log holding the probes' lines `STUN_TX <conn> [<shape>] <hex>`, `STUN_RX ...`,
`DTLS_CH_TX <conn> <hex>`, `DTLS_CH_RX ...`. Prints, never judges: what differs is read off.
"""
import struct
import sys

MAGIC = b"\x21\x12\xa4\x42"
STUN_NAMES = {
    0x0006: "USERNAME", 0x0008: "MESSAGE-INTEGRITY", 0x0020: "XOR-MAPPED-ADDRESS",
    0x0024: "PRIORITY", 0x0025: "USE-CANDIDATE", 0x8028: "FINGERPRINT",
    0x8029: "ICE-CONTROLLED", 0x802A: "ICE-CONTROLLING", 0xC057: "GOOG-NETWORK-INFO",
    0xC058: "GOOG-LAST-ICE-CHECK-RECEIVED", 0xC059: "GOOG-NOMINATION",
    0xC05A: "GOOG-DELTA", 0xC05B: "GOOG-DELTA-ACK", 0xC060: "GOOG-MISC-INFO",
    0xC070: "META-DTLS-IN-STUN", 0xC071: "META-DTLS-IN-STUN-ACK",
}
EXT_NAMES = {
    0x0000: "server_name", 0x000A: "supported_groups", 0x000B: "ec_point_formats",
    0x000D: "signature_algorithms", 0x000E: "use_srtp", 0x0010: "alpn",
    0x0017: "extended_master_secret", 0x001C: "record_size_limit", 0x0023: "session_ticket",
    0x002B: "supported_versions", 0x002C: "cookie", 0x002D: "psk_key_exchange_modes",
    0x0033: "key_share", 0xFF01: "renegotiation_info", 0x0029: "pre_shared_key",
    0x0015: "padding", 0x0005: "status_request", 0x0012: "sct",
}
GROUPS = {0x001D: "X25519", 0x0017: "P-256", 0x0018: "P-384", 0x0019: "P-521",
          0x11EC: "X25519MLKEM768", 0x6399: "X25519Kyber768Draft00"}
SRTP = {0x0001: "AES128_CM_SHA1_80", 0x0002: "AES128_CM_SHA1_32",
        0x0007: "AEAD_AES_128_GCM", 0x0008: "AEAD_AES_256_GCM"}
VERS = {0xFEFF: "DTLS1.0", 0xFEFD: "DTLS1.2", 0xFEFC: "DTLS1.3"}


# ---- input ---------------------------------------------------------------------------------

def pcap_packets(data):
    """(linktype, frame) for every packet of a pcap or pcapng."""
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        e = "<" if data[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
        i, links = 0, []
        while i + 12 <= len(data):
            bt, bl = struct.unpack(e + "II", data[i:i + 8])
            if bl < 12:
                break
            b = data[i + 8:i + bl - 4]
            if bt == 1:
                links.append(struct.unpack(e + "H", b[0:2])[0])
            elif bt == 6:
                iid, _, _, cl, _ = struct.unpack(e + "IIIII", b[0:20])
                yield links[iid], b[20:20 + cl]
            i += bl
        return
    e = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    lt = struct.unpack(e + "I", data[20:24])[0]
    i = 24
    while i + 16 <= len(data):
        _, _, incl, _ = struct.unpack(e + "IIII", data[i:i + 16])
        i += 16
        yield lt, data[i:i + incl]
        i += incl


def udp(lt, p):
    """(src, dst, payload) of a UDP frame, or None."""
    if lt == 1:
        off = 14
    elif lt == 113:
        off = 16
    elif lt == 276:
        off = 20
    elif lt == 0:
        off = 4
    elif lt == 101:
        off = 0
    else:
        return None
    ip = p[off:]
    if not ip:
        return None
    if ip[0] >> 4 == 4:
        ihl = (ip[0] & 15) * 4
        if ip[9] != 17:
            return None
        src, dst, l4 = ".".join(map(str, ip[12:16])), ".".join(map(str, ip[16:20])), ip[ihl:]
    elif ip[0] >> 4 == 6:
        if ip[6] != 17:
            return None
        src, dst, l4 = ip[8:24].hex(), ip[24:40].hex(), ip[40:]
    else:
        return None
    sp, dp = struct.unpack(">HH", l4[0:4])
    return f"{src}:{sp}", f"{dst}:{dp}", l4[8:]


def datagrams(path):
    """(direction-label, payload) for every UDP payload or logged datagram in a file."""
    data = open(path, "rb").read()
    if data[:4] in (b"\x0a\x0d\x0d\x0a", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        for lt, p in pcap_packets(data):
            u = udp(lt, p)
            if u:
                yield f"{u[0]}>{u[1]}", u[2]
        return
    for line in data.decode("utf-8", "replace").splitlines():
        parts = line.split()
        for k, w in enumerate(parts):
            if w in ("STUN_TX", "STUN_RX", "DTLS_CH_TX", "DTLS_CH_RX") and k + 2 < len(parts):
                try:
                    yield f"{w[-2:]}:{parts[k + 1]}", bytes.fromhex(parts[-1])
                except ValueError:
                    pass
                break


# ---- STUN ----------------------------------------------------------------------------------

def stun_shape(b):
    if len(b) < 20 or b[0:2] != b"\x00\x01" or b[4:8] != MAGIC:
        return None
    out, i = [], 20
    while i + 4 <= len(b):
        t, ln = struct.unpack(">HH", b[i:i + 4])
        v = b[i + 4:i + 4 + ln]
        name = STUN_NAMES.get(t, f"0x{t:04x}")
        if t == 0xC057 and ln == 4:
            name += "{id=%d,cost=%d}" % struct.unpack(">HH", v)
        out.append(f"{name}({ln})")
        i += 4 + ((ln + 3) & ~3)
    return " ".join(out)


def side(d):
    """TX (the probe's own) or RX (its peer's) for a logged datagram; the flow for a pcap."""
    return d[:2] if d[:3] in ("TX:", "RX:") else "pcap"


def cmd_stun(paths):
    for path in paths:
        seen = {}
        for d, b in datagrams(path):
            s = stun_shape(b)
            if s:
                seen.setdefault((side(d), s), set()).add(d)
        print(f"== {path}")
        for (k, s), ds in sorted(seen.items()):
            print(f"  {k} {s}    [{len(ds)} flow(s)]")


# ---- DTLS ClientHello ----------------------------------------------------------------------

def first_hellos(path, want=None):
    """{flow: reassembled first ClientHello body} (message_seq 0, type 1); `want` keeps one
    side (TX or RX) of a probe log."""
    frags = {}
    for d, u in datagrams(path):
        if want is not None and side(d) != want:
            continue
        j = 0
        while j + 13 <= len(u):
            ct = u[j]
            ln = struct.unpack(">H", u[j + 11:j + 13])[0]
            body = u[j + 13:j + 13 + ln]
            j += 13 + ln
            if ct != 22 or len(body) < 12 or body[0] != 1:
                continue
            total = int.from_bytes(body[1:4], "big")
            seq = int.from_bytes(body[4:6], "big")
            fo = int.from_bytes(body[6:9], "big")
            fl = int.from_bytes(body[9:12], "big")
            if seq != 0:
                continue
            f = frags.setdefault(d, {"len": total, "parts": {}, "records": 0})
            f["parts"][fo] = body[12:12 + fl]
            f["records"] += 1
    out = {}
    for d, f in frags.items():
        buf = bytearray(f["len"])
        got = 0
        for fo, b in f["parts"].items():
            buf[fo:fo + len(b)] = b
            got += len(b)
        if got >= f["len"]:
            out[d] = (bytes(buf), f["records"])
    return out


def parse_hello(h):
    r = {"legacy_version": VERS.get(int.from_bytes(h[0:2], "big"), h[0:2].hex()), "len": len(h)}
    i = 2 + 32
    sl = h[i]
    r["session_id_len"] = sl
    i += 1 + sl
    cl = h[i]
    r["cookie_len"] = cl
    i += 1 + cl
    csl = int.from_bytes(h[i:i + 2], "big")
    i += 2
    r["suites"] = [f"{int.from_bytes(h[i + k:i + k + 2], 'big'):04x}" for k in range(0, csl, 2)]
    i += csl
    i += 1 + h[i]
    el = int.from_bytes(h[i:i + 2], "big")
    i += 2
    end = i + el
    exts = []
    while i + 4 <= end:
        t = int.from_bytes(h[i:i + 2], "big")
        ln = int.from_bytes(h[i + 2:i + 4], "big")
        v = h[i + 4:i + 4 + ln]
        name = EXT_NAMES.get(t, f"0x{t:04x}")
        if t & 0x0F0F == 0x0A0A:
            name = "GREASE"
        detail = ""
        if t == 0x000A:
            detail = ",".join(GROUPS.get(int.from_bytes(v[k:k + 2], "big"), v[k:k + 2].hex()) for k in range(2, len(v), 2))
        elif t == 0x0033:
            k, ks = 2, []
            while k + 4 <= len(v):
                g, gl = int.from_bytes(v[k:k + 2], "big"), int.from_bytes(v[k + 2:k + 4], "big")
                ks.append(f"{GROUPS.get(g, hex(g))}:{gl}")
                k += 4 + gl
            detail = ",".join(ks)
        elif t == 0x002B:
            detail = ",".join(VERS.get(int.from_bytes(v[k:k + 2], "big"), v[k:k + 2].hex()) for k in range(1, len(v), 2))
        elif t == 0x000E:
            pl = int.from_bytes(v[0:2], "big")
            detail = ",".join(SRTP.get(int.from_bytes(v[2 + k:4 + k], "big"), v[2 + k:4 + k].hex()) for k in range(0, pl, 2))
        elif t == 0x000D:
            detail = ",".join(v[k:k + 2].hex() for k in range(2, len(v), 2))
        elif t in (0x000B, 0x002D, 0x001C):
            detail = v.hex()
        exts.append((name, ln, detail))
        i += 4 + ln
    r["extensions"] = exts
    return r


def cmd_hello(paths):
    for path in paths:
        print(f"== {path}")
        for d, (h, recs) in first_hellos(path).items():
            r = parse_hello(h)
            print(f"  {d}  len={len(h)} records={recs} legacy={r['legacy_version']} sid={r['session_id_len']} cookie={r['cookie_len']}")
            print(f"    suites: {' '.join(r['suites'])}")
            for name, ln, detail in r["extensions"]:
                print(f"    {name}({ln}) {detail}".rstrip())


def cmd_compare(specs):
    shapes = {}
    for spec in specs:
        label, path = spec.split("=", 1)
        # The probe logs carry its peer's requests too (RX): `label=file:TX` keeps one side.
        want = None
        if path.endswith((":TX", ":RX")):
            path, want = path[:-3], path[-2:]
        stun = sorted({s for d, b in datagrams(path) if (s := stun_shape(b)) and (want is None or side(d) == want)})
        hellos = first_hellos(path, want)
        h = parse_hello(next(iter(hellos.values()))[0]) if hellos else None
        shapes[label] = (stun, h)
    for label, (stun, h) in shapes.items():
        print(f"== {label}")
        for s in stun:
            print(f"  STUN {s}")
        if h:
            print(f"  DTLS suites {' '.join(h['suites'])}")
            print(f"  DTLS exts (sorted, permuted order ignored): {' '.join(sorted(n for n, _, _ in h['extensions']))}")
            for n, _, dt in h["extensions"]:
                if dt and n in ("supported_groups", "key_share", "supported_versions", "use_srtp", "signature_algorithms"):
                    print(f"    {n}: {dt}")
    labels = list(shapes)
    for a in labels:
        for b in labels:
            if a >= b or not shapes[a][1] or not shapes[b][1]:
                continue
            ea = {n for n, _, _ in shapes[a][1]["extensions"]}
            eb = {n for n, _, _ in shapes[b][1]["extensions"]}
            da = {n: dt for n, _, dt in shapes[a][1]["extensions"]}
            db = {n: dt for n, _, dt in shapes[b][1]["extensions"]}
            keys = ("supported_versions", "supported_groups", "key_share", "use_srtp", "signature_algorithms")
            differ = [k for k in keys if da.get(k) != db.get(k)]
            print(f"-- {a} vs {b}: only {a}: {sorted(ea - eb)}  only {b}: {sorted(eb - ea)}  "
                  f"suites equal: {shapes[a][1]['suites'] == shapes[b][1]['suites']}  values differ: {differ}  "
                  f"hello bytes: {shapes[a][1]['len']} vs {shapes[b][1]['len']}")


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] not in ("stun", "hello", "compare"):
        print(__doc__)
        sys.exit(2)
    {"stun": cmd_stun, "hello": cmd_hello, "compare": cmd_compare}[sys.argv[1]](sys.argv[2:])
