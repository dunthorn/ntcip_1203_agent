"""Decode the hex_dump_*.txt capture files into separate request/response
byte streams, then parse each stream as a sequence of BER-encoded SNMP
messages, printing a human-readable summary (OIDs + values)."""

import re
import sys


def parse_streams(path):
    """Return (request_bytes, response_bytes) extracted from a wireshark-like
    hex dump where request lines start at column 0 and response lines are
    indented."""
    req = bytearray()
    resp = bytearray()
    line_re = re.compile(
        r"^(\s*)([0-9A-Fa-f]{8})\s+((?:[0-9A-Fa-f]{2}\s+){1,16})"
    )
    with open(path, "r") as f:
        for line in f:
            m = line_re.match(line)
            if not m:
                continue
            indent, _offset, hexpart = m.groups()
            byte_strs = hexpart.split()
            data = bytes(int(b, 16) for b in byte_strs)
            if indent:
                resp.extend(data)
            else:
                req.extend(data)
    return bytes(req), bytes(resp)


def read_length(data, idx):
    """Read a BER length field starting at idx. Return (length, new_idx)."""
    first = data[idx]
    idx += 1
    if first < 0x80:
        return first, idx
    num_bytes = first & 0x7F
    length = 0
    for _ in range(num_bytes):
        length = (length << 8) | data[idx]
        idx += 1
    return length, idx


def read_tlv(data, idx):
    """Read one TLV starting at idx. Return (tag, value_bytes, next_idx)."""
    tag = data[idx]
    idx += 1
    length, idx = read_length(data, idx)
    value = data[idx : idx + length]
    idx += length
    return tag, value, idx


def decode_oid(value):
    if not value:
        return ""
    first = value[0]
    parts = [first // 40, first % 40]
    idx = 1
    while idx < len(value):
        n = 0
        while True:
            b = value[idx]
            idx += 1
            n = (n << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
        parts.append(n)
    return ".".join(str(p) for p in parts)


def decode_int(value):
    if not value:
        return 0
    n = int.from_bytes(value, "big", signed=True)
    return n


def decode_value(tag, value):
    if tag == 0x02:  # INTEGER
        return ("INTEGER", decode_int(value))
    if tag == 0x04:  # OCTET STRING
        try:
            txt = value.decode("latin-1")
        except Exception:
            txt = repr(value)
        return ("OCTET STRING", value.hex(), txt)
    if tag == 0x05:  # NULL
        return ("NULL", None)
    if tag == 0x06:  # OID
        return ("OID", decode_oid(value))
    if tag == 0x40:  # IpAddress
        return ("IpAddress", ".".join(str(b) for b in value))
    if tag == 0x41:  # Counter32
        return ("Counter32", int.from_bytes(value, "big"))
    if tag == 0x42:  # Gauge32 / Unsigned32
        return ("Gauge32", int.from_bytes(value, "big"))
    if tag == 0x43:  # TimeTicks
        return ("TimeTicks", int.from_bytes(value, "big"))
    if tag == 0x44:  # Opaque
        return ("Opaque", value.hex())
    if tag in (0x80, 0x81, 0x82):  # noSuchObject etc (context tags)
        return ("Exception", hex(tag))
    return (hex(tag), value.hex())


PDU_TAGS = {
    0xA0: "GetRequest",
    0xA1: "GetNextRequest",
    0xA2: "GetResponse",
    0xA3: "SetRequest",
    0xA4: "Trap",
}


def decode_message(data, off):
    tag, value, off = read_tlv(data, off)
    assert tag == 0x30, f"expected SEQUENCE at {off}, got {hex(tag)}"
    idx = 0
    # version
    vtag, vval, idx = read_tlv(value, idx)
    version = decode_int(vval)
    # community
    ctag, cval, idx = read_tlv(value, idx)
    community = cval.decode("latin-1")
    # pdu
    ptag, pval, idx = read_tlv(value, idx)
    pdu_type = PDU_TAGS.get(ptag, hex(ptag))

    pidx = 0
    rtag, rval, pidx = read_tlv(pval, pidx)
    request_id = decode_int(rval)
    etag, eval_, pidx = read_tlv(pval, pidx)
    error_status = decode_int(eval_)
    eitag, eival, pidx = read_tlv(pval, pidx)
    error_index = decode_int(eival)

    vbtag, vbval, pidx = read_tlv(pval, pidx)
    bindings = []
    bidx = 0
    while bidx < len(vbval):
        btag, bval, bidx = read_tlv(vbval, bidx)
        assert btag == 0x30
        binner = 0
        otag, oval, binner = read_tlv(bval, binner)
        oid = decode_oid(oval)
        vtag2, vval2, binner = read_tlv(bval, binner)
        val = decode_value(vtag2, vval2)
        bindings.append((oid, val))

    return {
        "version": version,
        "community": community,
        "pdu_type": pdu_type,
        "request_id": request_id,
        "error_status": error_status,
        "error_index": error_index,
        "bindings": bindings,
    }, off


def decode_stream(data):
    messages = []
    off = 0
    while off < len(data):
        msg, off = decode_message(data, off)
        messages.append(msg)
    return messages


def main():
    path = sys.argv[1]
    req, resp = parse_streams(path)
    print(f"=== {path} ===")
    print(f"request bytes: {len(req)}, response bytes: {len(resp)}")
    reqs = decode_stream(req)
    resps = decode_stream(resp)
    print(f"request messages: {len(reqs)}, response messages: {len(resps)}")
    for r, p in zip(reqs, resps):
        for (roid, rval), (poid, pval) in zip(r["bindings"], p["bindings"]):
            print(
                f"{r['pdu_type']:15s} reqid={r['request_id']:6d} "
                f"comm={r['community']:8s} OID={roid:35s} "
                f"req={rval} -> resp={pval}"
            )


if __name__ == "__main__":
    main()
