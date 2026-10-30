"""Raw TLS ClientHello prober for PQC / hybrid key-exchange negotiation.

Why raw? Python's stdlib `ssl` cannot offer hybrid post-quantum NamedGroups,
so it can never tell you whether a server *would* negotiate them. This module
builds a TLS 1.3 ClientHello by hand, offers hybrid ML-KEM groups first, sends
syntactically valid key shares, and reads exactly one thing: the group the
server selects in its ServerHello (or requests via HelloRetryRequest).

We never complete the handshake — after ServerHello the key shares cannot
produce a shared secret (the ML-KEM portion is a well-formed-length probe
share, not a real encapsulation keypair), and none is needed: group selection
is the entire question. The connection is closed immediately after parsing.
"""
from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519

from .classifier import HYBRID, RESISTANT, TLS_GROUPS, VULNERABLE
from .models import Finding

# group id -> (name, mlkem_pk_bytes, classical_part) ; classical_part in
# {"x25519", "p256", "p384", None}. ML-KEM share layout per
# draft-ietf-tls-ecdhe-mlkem: ML-KEM encapsulation key first, then the
# classical public key, concatenated in a single key_exchange value.
HYBRID_SHARES: dict[int, tuple[int, str]] = {
    0x11EC: (1184, "x25519"),   # X25519MLKEM768
    0x11EB: (1184, "p256"),     # SecP256r1MLKEM768
    0x11ED: (1568, "p384"),     # SecP384r1MLKEM1024
    0x6399: (1184, "x25519"),   # X25519Kyber768Draft00 (pre-standard draft)
}
PURE_MLKEM = {0x0200: ("MLKEM512", 800), 0x0201: ("MLKEM768", 1184), 0x0202: ("MLKEM1024", 1568)}
OFFERED_GROUPS: list[int] = [
    0x11EC, 0x11EB, 0x11ED, 0x6399,          # hybrid PQC, preferred
    0x0201,                                   # pure ML-KEM-768 (rare; HRR will reveal support)
    0x001D, 0x0017, 0x0018, 0x0019,           # X25519, P-256, P-384, P-521
    0x0100,                                   # ffdhe2048
]
# Groups we send an actual key_share for in the first flight. Everything else
# in OFFERED_GROUPS is discoverable via HelloRetryRequest instead.
SHARE_GROUPS: list[int] = [0x11EC, 0x001D, 0x0017]

HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
CIPHER_NAMES = {0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
                0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0x1304: "TLS_AES_128_CCM_SHA256",
                0x1305: "TLS_AES_128_CCM_8_SHA256", 0xC02F: "ECDHE-*-AES128-GCM-SHA256 (TLS1.2)",
                0xC030: "ECDHE-*-AES256-GCM-SHA384 (TLS1.2)"}

_CIPHERS = [
    0x1302, 0x1303, 0x1301,                   # TLS 1.3
    0xC02F, 0xC030, 0xC02B, 0xC02C,           # TLS 1.2 ECDHE (fallback signal)
    0x009E, 0x009C,                           # TLS 1.2 DHE/RSA
]
_SIGALGS = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0201, 0x0807]


def _classical_pub(kind: str) -> bytes:
    if kind == "x25519":
        k = x25519.X25519PrivateKey.generate()
        return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    curve = ec.SECP256R1() if kind == "p256" else ec.SECP384R1()
    k = ec.generate_private_key(curve)
    return k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def _key_share(group: int) -> bytes:
    """A syntactically valid, correct-length key share for `group`."""
    if group in HYBRID_SHARES:
        mlkem_len, classical = HYBRID_SHARES[group]
        # The ML-KEM part must be a *coefficient-valid* encapsulation key:
        # random bytes fail server-side validation (packed 12-bit coefficients
        # must be < q=3329; BoringSSL replies illegal_parameter). An all-zero
        # coefficient encoding is valid to parse and encapsulate against, and
        # we abort right after ServerHello, so no real keypair is needed.
        return bytes(mlkem_len) + _classical_pub(classical)
    if group in PURE_MLKEM:
        return bytes(PURE_MLKEM[group][1])  # coefficient-valid zero encoding, as above
    if group == 0x001D:
        return _classical_pub("x25519")
    if group == 0x0017:
        return _classical_pub("p256")
    if group == 0x0018:
        return _classical_pub("p384")
    raise ValueError(f"no key-share builder for group 0x{group:04x}")


def group_name(group: int) -> tuple[str, str]:
    if group in TLS_GROUPS:
        return TLS_GROUPS[group]
    if group in PURE_MLKEM:
        return (PURE_MLKEM[group][0], RESISTANT)
    return (f"unknown-group-0x{group:04x}", "UNKNOWN")


def build_client_hello(host: str, share_groups: list[int] | None = None) -> bytes:
    share_groups = share_groups or SHARE_GROUPS
    exts = b""

    def ext(etype: int, data: bytes) -> None:
        nonlocal exts
        exts += struct.pack(">HH", etype, len(data)) + data

    host_b = host.encode()
    ext(0, struct.pack(">H", len(host_b) + 3) + b"\x00" + struct.pack(">H", len(host_b)) + host_b)  # server_name
    ext(16, b"\x00\x0c\x02h2\x08http/1.1")  # ALPN
    groups = b"".join(struct.pack(">H", g) for g in OFFERED_GROUPS)
    ext(10, struct.pack(">H", len(groups)) + groups)  # supported_groups
    ext(11, b"\x01\x00")  # ec_point_formats: len=1, uncompressed(0)
    sigs = b"".join(struct.pack(">H", s) for s in _SIGALGS)
    ext(13, struct.pack(">H", len(sigs)) + sigs)  # signature_algorithms
    shares = b""
    for g in share_groups:
        ks = _key_share(g)
        shares += struct.pack(">HH", g, len(ks)) + ks
    ext(51, struct.pack(">H", len(shares)) + shares)  # key_share
    ext(45, b"\x01\x01")  # psk_key_exchange_modes: len=1, psk_dhe_ke(1)
    versions = bytes([4]) + struct.pack(">HH", 0x0304, 0x0303)  # byte-len + TLS1.3, TLS1.2
    ext(43, versions)  # supported_versions

    ciphers = b"".join(struct.pack(">H", c) for c in _CIPHERS)
    body = (
        b"\x03\x03" + os.urandom(32) + b"\x00"  # legacy version, random, empty session id
        + struct.pack(">H", len(ciphers)) + ciphers
        + b"\x01\x00"  # compression: null only
        + struct.pack(">H", len(exts)) + exts
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


@dataclass
class ServerHelloResult:
    kind: str                      # "server_hello" | "hello_retry_request" | "tls12" | "alert" | "error"
    tls_version: str = ""
    cipher_suite: int = 0
    selected_group: int | None = None
    detail: str = ""


def parse_first_handshake(data: bytes) -> ServerHelloResult:
    """Parse the first handshake message out of one or more TLS records."""
    pos = 0
    handshake = b""
    while pos + 5 <= len(data):
        rtype, _ver, rlen = data[pos], data[pos + 1:pos + 3], struct.unpack(">H", data[pos + 3:pos + 5])[0]
        payload = data[pos + 5:pos + 5 + rlen]
        if rtype == 21:
            return ServerHelloResult("alert", detail=f"alert level={payload[0] if payload else '?'} desc={payload[1] if len(payload) > 1 else '?'}")
        if rtype == 22:
            handshake += payload
        pos += 5 + rlen
        if len(handshake) >= 4:
            hlen = int.from_bytes(handshake[1:4], "big")
            if len(handshake) >= 4 + hlen:
                return _parse_server_hello(handshake[:4 + hlen])
    return ServerHelloResult("error", detail="no complete handshake message in first flight")


def _parse_server_hello(msg: bytes) -> ServerHelloResult:
    if msg[0] != 2:
        return ServerHelloResult("error", detail=f"unexpected handshake type {msg[0]}")
    body = msg[4:]
    try:
        _legacy_ver, random = body[:2], body[2:34]
        p = 34
        sid_len = body[p]; p += 1 + sid_len
        cipher = struct.unpack(">H", body[p:p + 2])[0]; p += 2
        p += 1  # compression
        is_hrr = random == HRR_RANDOM
        if p >= len(body):
            return ServerHelloResult("tls12", tls_version="1.2", cipher_suite=cipher, detail="no extensions")
        ext_total = struct.unpack(">H", body[p:p + 2])[0]; p += 2
        end = min(len(body), p + ext_total)
        selected_version, selected_group = None, None
        while p + 4 <= end:
            etype, elen = struct.unpack(">HH", body[p:p + 4]); p += 4
            edata = body[p:p + elen]; p += elen
            if etype == 43 and len(edata) == 2:
                selected_version = struct.unpack(">H", edata)[0]
            elif etype == 51:
                if is_hrr and len(edata) == 2:
                    selected_group = struct.unpack(">H", edata)[0]
                elif len(edata) >= 4:
                    selected_group = struct.unpack(">H", edata[:2])[0]
        if selected_version == 0x0304 or (selected_version is None and not is_hrr and 0x1301 <= cipher <= 0x1305):
            kind = "hello_retry_request" if is_hrr else "server_hello"
            return ServerHelloResult(kind, tls_version="1.3", cipher_suite=cipher, selected_group=selected_group)
        return ServerHelloResult("hello_retry_request" if is_hrr else "tls12",
                                 tls_version="1.3" if is_hrr else "1.2", cipher_suite=cipher,
                                 selected_group=selected_group)
    except (IndexError, struct.error) as exc:
        return ServerHelloResult("error", detail=f"parse failure: {exc}")


def _read_first_flight(sock: socket.socket, limit: int = 65536) -> bytes:
    data = b""
    sock.settimeout(5)
    while len(data) < limit:
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
        result = parse_first_handshake(data)
        if result.kind != "error" or "no complete" not in result.detail:
            break
        # Cheap completeness check: stop once we hold one full record set.
        if len(data) >= 5 and len(data) >= 5 + struct.unpack(">H", data[3:5])[0]:
            # Could still be a fragmented handshake; one extra read is enough in practice.
            try:
                more = sock.recv(8192)
                if more:
                    data += more
            except (socket.timeout, OSError):
                pass
            break
    return data


_SHAREABLE = set(HYBRID_SHARES) | set(PURE_MLKEM) | {0x001D, 0x0017, 0x0018}


def _probe_once(host: str, port: int, timeout: float, share_groups: list[int] | None = None) -> ServerHelloResult:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(build_client_hello(host, share_groups=share_groups))
        return parse_first_handshake(_read_first_flight(sock))


def probe_pqc(host: str, port: int = 443, timeout: float = 6.0) -> Finding | None:
    """Offer hybrid PQC groups; report what the server actually selects."""
    try:
        result = _probe_once(host, port, timeout)
        # HelloRetryRequest asking for a group we listed but sent no share for
        # already proves support; confirm it with a second ClientHello that
        # actually carries that share, and prefer the confirmed ServerHello.
        confirmed = ""
        if (result.kind == "hello_retry_request" and result.selected_group in _SHAREABLE
                and result.selected_group not in SHARE_GROUPS):
            try:
                retry = _probe_once(host, port, timeout,
                                    share_groups=[result.selected_group, 0x001D])  # type: ignore[list-item]
                if retry.kind == "server_hello" and retry.selected_group == result.selected_group:
                    result, confirmed = retry, " (confirmed on retry with requested share)"
            except OSError:
                pass  # fall back to the HRR evidence itself
        if result.kind == "error":
            return Finding(name=f"PQC probe {host}:{port}", asset_type="protocol",
                           location=f"tls://{host}:{port}", primitive="key-agree",
                           algorithm="unknown", quantum_vulnerable=None, quantum_status="UNKNOWN",
                           confidence="low", evidence=result.detail,
                           remediation="Server did not return a parseable ServerHello to a TLS 1.3 ClientHello (may be TLS<=1.2-only, require SNI/ALPN variation, or filter unusual clients). Verify with the standard TLS probe.")
    except OSError as exc:
        print(f"[!] PQC probe failed for {host}:{port} -> {exc}")
        return None

    if result.selected_group is not None:
        name, status = group_name(result.selected_group)
        vulnerable = status == VULNERABLE
        level = 3 if "768" in name else 5 if "1024" in name else 0 if vulnerable else None
        return Finding(
            name=f"PQC probe {host}:{port}", asset_type="protocol", location=f"tls://{host}:{port}",
            primitive="key-agree", algorithm=name, parameter_set=f"0x{result.selected_group:04x} {name}",
            tls_version=result.tls_version, cipher_suite=CIPHER_NAMES.get(result.cipher_suite, f"0x{result.cipher_suite:04x}"),
            quantum_vulnerable=vulnerable if status != "UNKNOWN" else None,
            quantum_status=status, nist_quantum_level=level,
            classical_security_bits=128 if vulnerable else 192 if level == 3 else 256 if level == 5 else None,
            crypto_functions=["keyderive"],
            evidence=f"{result.kind} selected group 0x{result.selected_group:04x} ({name}) after hybrid groups were offered first{confirmed}",
            remediation=("Server negotiated classical key exchange despite hybrid ML-KEM being offered. "
                         "Enable X25519MLKEM768 (or SecP384r1MLKEM1024 for CNSA 2.0) on the TLS terminator."
                         if vulnerable else
                         "Hybrid/PQC key exchange negotiated. Ensure the certificate chain roadmap (ML-DSA) is tracked separately."))
    return Finding(
        name=f"PQC probe {host}:{port}", asset_type="protocol", location=f"tls://{host}:{port}",
        primitive="key-agree", algorithm="unknown", tls_version=result.tls_version or None,
        cipher_suite=CIPHER_NAMES.get(result.cipher_suite, f"0x{result.cipher_suite:04x}") if result.cipher_suite else None,
        quantum_vulnerable=True if result.kind == "tls12" else None,
        quantum_status=VULNERABLE if result.kind == "tls12" else "UNKNOWN",
        nist_quantum_level=0 if result.kind == "tls12" else None, crypto_functions=["keyderive"],
        confidence="medium" if result.kind == "tls12" else "low",
        evidence=f"{result.kind}: no key_share group selected (offered hybrid ML-KEM groups first). {result.detail}".strip(),
        remediation="No TLS 1.3 group negotiation observed. If this endpoint is TLS 1.2-only, its ECDHE/DHE/RSA key establishment is Shor-vulnerable; upgrade the terminator to TLS 1.3 with hybrid ML-KEM groups.")
