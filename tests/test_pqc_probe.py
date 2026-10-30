import struct

from cbom_scout.pqc_probe import HRR_RANDOM, build_client_hello, group_name, parse_first_handshake


def _extensions(hello: bytes):
    assert hello[0] == 0x16
    body = hello[5 + 4:]  # record hdr + handshake hdr
    p = 34  # legacy ver(2)+random(32) -> session id len at 34 relative to body start after handshake hdr? body already past it
    # body here starts at client_version; session-id length offset:
    p = 2 + 32
    sid = body[p]; p += 1 + sid
    clen = struct.unpack(">H", body[p:p + 2])[0]; p += 2 + clen
    p += 1 + body[p]  # compression methods
    etotal = struct.unpack(">H", body[p:p + 2])[0]; p += 2
    exts = {}
    end = p + etotal
    while p < end:
        t, ln = struct.unpack(">HH", body[p:p + 4]); p += 4
        exts[t] = body[p:p + ln]; p += ln
    return exts


def test_client_hello_offers_hybrid_first_with_valid_share_lengths():
    exts = _extensions(build_client_hello("example.com"))
    groups_len = struct.unpack(">H", exts[10][:2])[0]
    groups = [struct.unpack(">H", exts[10][2 + i:4 + i])[0] for i in range(0, groups_len, 2)]
    assert groups[0] == 0x11EC and 0x001D in groups
    shares = exts[51]
    total = struct.unpack(">H", shares[:2])[0]
    p, seen = 2, {}
    while p < 2 + total:
        g, ln = struct.unpack(">HH", shares[p:p + 4]); p += 4
        seen[g] = ln; p += ln
    assert seen[0x11EC] == 1184 + 32  # ML-KEM-768 encap key + X25519 pub
    assert seen[0x001D] == 32 and seen[0x0017] == 65
    assert exts[43] == b"\x04\x03\x04\x03\x03"  # supported_versions TLS1.3, TLS1.2
    assert exts[11] == b"\x01\x00" and exts[45] == b"\x01\x01"  # length-prefixed lists must be exact (servers send decode_error otherwise)


def _record(handshake: bytes) -> bytes:
    return b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake


def _server_hello(group: int | None, hrr: bool = False, tls13: bool = True) -> bytes:
    exts = b""
    if tls13:
        exts += struct.pack(">HHH", 43, 2, 0x0304)
    if group is not None:
        data = struct.pack(">H", group) if hrr else struct.pack(">HH", group, 32) + b"\x00" * 32
        exts += struct.pack(">HH", 51, len(data)) + data
    body = (b"\x03\x03" + (HRR_RANDOM if hrr else b"\x01" * 32) + b"\x00"
            + struct.pack(">H", 0x1302 if tls13 else 0xC02F) + b"\x00"
            + struct.pack(">H", len(exts)) + exts)
    return _record(b"\x02" + len(body).to_bytes(3, "big") + body)


def test_parses_server_hello_selecting_hybrid():
    r = parse_first_handshake(_server_hello(0x11EC))
    assert r.kind == "server_hello" and r.selected_group == 0x11EC and r.tls_version == "1.3"
    assert group_name(0x11EC)[1] == "HYBRID_TRANSITIONAL"


def test_parses_hello_retry_request_group():
    r = parse_first_handshake(_server_hello(0x11EB, hrr=True))
    assert r.kind == "hello_retry_request" and r.selected_group == 0x11EB


def test_parses_classical_selection_and_tls12():
    assert parse_first_handshake(_server_hello(0x001D)).selected_group == 0x001D
    r12 = parse_first_handshake(_server_hello(None, tls13=False))
    assert r12.kind == "tls12"


def test_parses_alert():
    r = parse_first_handshake(b"\x15\x03\x03\x00\x02\x02\x28")
    assert r.kind == "alert"
