"""Build the seed value table for every scalar (non-table-column) object in
the dms subtree, combining:

  1. DEFVAL declarations parsed straight out of the MIB text (when present),
  2. syntax-derived generic defaults (0 / empty string / etc.) as a fallback,
  3. real values observed in hex_dump_1 / hex_dump_2 (highest precedence),
  4. a handful of values implied by artifacts/config_screenshot.jpg.

Output: ntcip_agent/data/dms_scalars.json
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
from decode_hexdump import parse_streams, decode_stream  # noqa: E402

HERE = os.path.dirname(__file__)
DMS_PREFIX = "1.3.6.1.4.1.1206.4.2.3."


def load_mib_text():
    with open(os.path.join(HERE, "1203v0305a.mib"), "r") as f:
        return f.read()


def find_object_block(text, name):
    """Return the raw text of the OBJECT-TYPE clause for `name`, from the
    'SYNTAX' keyword through to (and including) the closing '::= { ... }'."""
    m = re.search(
        rf"^{re.escape(name)}\s+OBJECT-TYPE\s*\n(.*?\n::=\s*\{{[^}}]*\}})",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if not m:
        return None
    return m.group(1)


def parse_enum_map(syntax_text):
    """Extract {name: value} from an 'INTEGER { name (n), ... }' syntax
    block. Returns {} if the syntax isn't an enumeration. Commented-out
    (retired) enumerations such as '--other (1), -retired' are ignored."""
    m = re.search(r"INTEGER\s*\{(.*?)\}", syntax_text, re.DOTALL)
    if not m:
        return {}
    body = re.sub(r"--[^\n]*", "", m.group(1))
    enum = {}
    for em in re.finditer(r"(\w+)\s*\(\s*(-?\d+)\s*\)", body):
        enum[em.group(1)] = int(em.group(2))
    return enum


def parse_defval(block, enum_map):
    """Parse an (uncommented) DEFVAL clause. Returns a python value
    (int / bytes / str) or None."""
    m = re.search(r"^\s*DEFVAL\s*\{([^}]*)\}", block, re.MULTILINE)
    if not m:
        return None
    raw = m.group(1).strip()
    # hex string e.g. '0000000000'h
    hm = re.match(r"'([0-9A-Fa-f]*)'[hH]", raw)
    if hm:
        return bytes.fromhex(hm.group(1))
    # plain integer
    if re.match(r"^-?\d+$", raw):
        return int(raw)
    # enumeration name
    if raw in enum_map:
        return enum_map[raw]
    return None


def syntax_default(syntax_text, enum_map):
    """Generic fallback default based purely on the SYNTAX text."""
    s = syntax_text.strip()
    if s.startswith("MessageActivationCode"):
        return bytes(12)
    if s.startswith("MessageIDCode"):
        # points at the blank message (memoryType=blank(7), number=1, CRC=0)
        return bytes([7, 0x00, 0x01, 0x00, 0x00])
    if (
        s.startswith("OCTET STRING")
        or s.startswith("DisplayString")
        or s.startswith("OwnerString")
    ):
        sm = re.search(r"SIZE\s*\(\s*(\d+)", s)
        if sm:
            return bytes(int(sm.group(1)))
        return b""
    if s.startswith("IpAddress"):
        return b"\x00\x00\x00\x00"
    if s.startswith("Counter"):
        return 0
    if enum_map:
        # pick the lowest-numbered (non-retired) enumeration value
        return min(enum_map.values())
    # plain INTEGER (with or without a range)
    rm = re.search(r"\(\s*(-?\d+)\s*\.\.\s*(-?\d+)\s*\)", s)
    if rm:
        lo, hi = int(rm.group(1)), int(rm.group(2))
        return 0 if lo <= 0 <= hi else lo
    return 0


def tag_for_syntax(syntax_text):
    s = syntax_text.strip()
    if s.startswith("OCTET STRING") or s in (
        "MessageActivationCode",
        "MessageIDCode",
        "OwnerString",
    ) or s.startswith("DisplayString"):
        return "OCTET STRING"
    if s.startswith("IpAddress"):
        return "IpAddress"
    if s.startswith("Counter"):
        return "Counter32"
    return "INTEGER"


# A handful of objects for which the generic syntax-derived default (often
# 0 / empty) is technically legal but operationally useless for a working
# simulator. These give the agent realistic, internally-consistent values.
REALISM_OVERRIDES = {
    "dmsSignHeight": 900,  # mm
    "dmsSignWidth": 4800,  # mm
    "dmsHorizontalBorder": 50,  # mm
    "dmsVerticalBorder": 50,  # mm
    "vmsHorizontalPitch": 28,  # mm
    "vmsVerticalPitch": 28,  # mm
    "dmsMaxMultiStringLength": 256,
    "dmsMaxNumberPages": 6,
    "dmsSupportedMultiTags": b"\xff\xff\xff\xff",
    "dmsIllumNumBrightLevels": 16,
    "dmsIllumMaxPhotocellLevel": 1023,
    "dmsIllumPhotocellLevelStatus": 512,
    "dmsIllumBrightLevelStatus": 8,
    "dmsMaxChangeableMsg": 50,
    "dmsMaxVolatileMsg": 10,
    "dmsFreeChangeableMemory": 64000,
    "dmsFreeVolatileMemory": 16000,
    "fontMaxCharacterSize": 64,
}


def load_captured_values():
    """Decode both hex dumps and return {oid_suffix: (tag, value)} using the
    *last* observed GetResponse value for each OID (later captures reflect
    later/']final' state)."""
    captured = {}
    for fname in ("hex_dump_1.txt", "hex_dump_2.txt"):
        req, resp = parse_streams(os.path.join(HERE, fname))
        reqs = decode_stream(req)
        resps = decode_stream(resp)
        for r, p in zip(reqs, resps):
            for (roid, _rval), (poid, pval) in zip(r["bindings"], p["bindings"]):
                if pval[0] in ("Exception",):
                    continue
                captured[roid] = pval
    return captured


def main():
    text = load_mib_text()
    mib = json.load(open(os.path.join(HERE, "mib_objects.json")))
    captured = load_captured_values()

    out = {}
    for m in mib:
        if m["is_table_column"]:
            continue
        if m.get("access") in (None, "not-accessible"):
            continue
        name = m["name"]
        oid = m["oid"]
        block = find_object_block(text, name)
        syntax_text = m["syntax"]
        enum_map = {}
        defval = None
        if block:
            full_syntax_m = re.search(
                r"SYNTAX\s+(.*?)\n\s*(?:MAX-ACCESS|ACCESS)", block, re.DOTALL
            )
            if full_syntax_m:
                syntax_text = full_syntax_m.group(1)
            enum_map = parse_enum_map(syntax_text)
            defval = parse_defval(block, enum_map)

        tag = tag_for_syntax(syntax_text)

        if defval is not None:
            value = defval
        else:
            value = syntax_default(syntax_text, enum_map)

        if name in REALISM_OVERRIDES:
            value = REALISM_OVERRIDES[name]

        instance_oid = oid + ".0"
        cap = captured.get(instance_oid)
        if cap:
            if cap[0] == "OCTET STRING":
                value = bytes.fromhex(cap[1])
            elif cap[0] == "Exception":
                pass
            else:
                value = cap[1]

        if isinstance(value, bytes):
            out[instance_oid] = {
                "name": name,
                "tag": "OCTET STRING",
                "hex": value.hex(),
                "access": m["access"],
            }
        else:
            out[instance_oid] = {
                "name": name,
                "tag": tag,
                "value": value,
                "access": m["access"],
            }

    # --- special: NTCIP1201 "global configuration" module-table object ---
    out["1.3.6.1.4.1.1206.4.2.6.1.3.1.5.1"] = {
        "name": "globalMaxModules",  # placeholder name, not part of this MIB
        "tag": "OCTET STRING",
        "hex": captured["1.3.6.1.4.1.1206.4.2.6.1.3.1.5.1"][1]
        if "1.3.6.1.4.1.1206.4.2.6.1.3.1.5.1" in captured
        else b"1.0 / 2015 1 September".hex(),
        "access": "read-only",
    }

    out_dir = os.path.join(HERE, "..", "ntcip_agent", "data")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "dms_scalars.json")
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2, sort_keys=False)
    print(f"wrote {len(out)} scalar objects to {out_path}")


if __name__ == "__main__":
    main()
