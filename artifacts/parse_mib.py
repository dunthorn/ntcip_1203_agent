"""Parse the NTCIP 1203 MIB file to build a mapping of fully-qualified OIDs
(under the `dms` subtree, 1.3.6.1.4.1.1206.4.2.3) to object names, syntax
types, and access levels."""

import re
import json
import sys

DMS_ROOT = (1, 3, 6, 1, 4, 1, 1206, 4, 2, 3)

OBJTYPE_RE = re.compile(
    r"^(\w+)\s+OBJECT-TYPE\s*\n"
    r"\s*SYNTAX\s+(.+?)\n"
    r"(?:.*?\n)*?"
    r"\s*(?:MAX-ACCESS|ACCESS)\s+(\S+)\s*\n"
    r"(?:.*?\n)*?"
    r"::=\s*\{\s*(\w+)\s+(\d+)\s*\}",
    re.MULTILINE,
)

OID_RE = re.compile(
    r"^(\w+)\s+OBJECT IDENTIFIER\s*::=\s*\{\s*(\w+)\s+(\d+)\s*\}", re.MULTILINE
)


def main():
    path = sys.argv[1]
    with open(path, "r") as f:
        text = f.read()

    # parent -> name -> index
    parent_map = {}

    for m in OID_RE.finditer(text):
        name, parent, idx = m.group(1), m.group(2), int(m.group(3))
        parent_map[name] = (parent, idx)

    objects = {}
    for m in OBJTYPE_RE.finditer(text):
        name, syntax, access, parent, idx = m.groups()
        syntax = syntax.strip().rstrip("{").strip()
        parent_map[name] = (parent, int(idx))
        objects[name] = {"syntax": syntax, "access": access, "parent": parent}

    # resolve OID for "dms" itself
    parent_map["dms"] = ("__DMS_ROOT__", 0)

    def resolve(name, _seen=None):
        if _seen is None:
            _seen = set()
        if name == "dms":
            return DMS_ROOT
        if name in _seen:
            raise ValueError(f"cycle resolving {name}")
        _seen.add(name)
        if name not in parent_map:
            return None
        parent, idx = parent_map[name]
        if parent == "__DMS_ROOT__":
            return DMS_ROOT
        presolved = resolve(parent, _seen)
        if presolved is None:
            return None
        return presolved + (idx,)

    results = {}
    for name in parent_map:
        oid = resolve(name)
        if oid is None:
            continue
        if oid[: len(DMS_ROOT)] != DMS_ROOT:
            continue
        entry = {"oid": ".".join(str(x) for x in oid), "name": name}
        if name in objects:
            entry.update(objects[name])
            entry["is_table_column"] = objects[name]["parent"].lower().endswith(
                "entry"
            )
        else:
            entry["is_table_column"] = False
        results[name] = entry

    # sort by oid numerically
    def oidkey(e):
        return tuple(int(x) for x in e["oid"].split("."))

    out = sorted(results.values(), key=oidkey)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
