"""Extract the font-20 ("FDOTColorDMS") definition and its character table
from hex_dump_2.txt and write it out as ntcip_agent/data/font_220.json."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from decode_hexdump import parse_streams, decode_stream, decode_oid  # noqa: E402


DMS_PREFIX = "1.3.6.1.4.1.1206.4.2.3."


def main():
    path = os.path.join(os.path.dirname(__file__), "hex_dump_2.txt")
    req, resp = parse_streams(path)
    reqs = decode_stream(req)
    resps = decode_stream(resp)

    font = {
        "fontIndex": 20,
        "fontNumber": None,
        "fontName": None,
        "fontHeight": None,
        "fontCharSpacing": None,
        "fontLineSpacing": None,
        "fontVersionID": None,
        "fontStatus": None,
        "characters": {},
    }

    for r, p in zip(reqs, resps):
        for (roid, _rval), (poid, pval) in zip(r["bindings"], p["bindings"]):
            if not roid.startswith(DMS_PREFIX):
                continue
            suffix = roid[len(DMS_PREFIX) :]
            parts = suffix.split(".")

            if parts[:5] == ["3", "2", "1", "8", "20"]:  # fontStatus
                font["fontStatus"] = pval[1]
            elif parts[:5] == ["3", "2", "1", "2", "20"]:  # fontNumber
                font["fontNumber"] = pval[1]
            elif parts[:5] == ["3", "2", "1", "3", "20"]:  # fontName
                font["fontName"] = pval[2]
            elif parts[:5] == ["3", "2", "1", "4", "20"]:  # fontHeight
                font["fontHeight"] = pval[1]
            elif parts[:5] == ["3", "2", "1", "5", "20"]:  # fontCharSpacing
                font["fontCharSpacing"] = pval[1]
            elif parts[:5] == ["3", "2", "1", "6", "20"]:  # fontLineSpacing
                font["fontLineSpacing"] = pval[1]
            elif parts[:5] == ["3", "2", "1", "7", "20"]:  # fontVersionID
                font["fontVersionID"] = pval[1]
            elif parts[:4] == ["3", "4", "1", "2"] and parts[4] == "20":
                char_num = int(parts[5])
                font["characters"].setdefault(str(char_num), {})["width"] = pval[1]
            elif parts[:4] == ["3", "4", "1", "3"] and parts[4] == "20":
                char_num = int(parts[5])
                font["characters"].setdefault(str(char_num), {})[
                    "bitmap"
                ] = pval[1]  # hex string

    # drop characters with width == 0 and no bitmap data (undefined glyphs)
    chars = {}
    for num, data in font["characters"].items():
        width = data.get("width", 0)
        bitmap = data.get("bitmap", "")
        if width == 0 and not bitmap:
            continue
        chars[num] = {"width": width, "bitmap": bitmap}
    font["characters"] = chars

    out_dir = os.path.join(os.path.dirname(__file__), "..", "ntcip_agent", "data")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "font_220.json")
    with open(out_path, "w") as f:
        json.dump(font, f, indent=2)

    print(f"wrote {out_path}")
    print(f"font metadata: { {k: v for k, v in font.items() if k != 'characters'} }")
    print(f"character count: {len(font['characters'])}")


if __name__ == "__main__":
    main()
