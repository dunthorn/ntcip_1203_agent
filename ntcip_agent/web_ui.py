"""Flask-based web UI for monitoring and controlling simulated DMS signs."""

from __future__ import annotations

import os
import struct
import zlib
from typing import List

from flask import Flask, Response, jsonify, render_template, request

from .ber import Value
from .config import AgentConfig
from .server import DmsAgent

# OIDs for UI-controllable sign state
_SHORT_ERROR_OID = "1.3.6.1.4.1.1206.4.2.3.9.7.1.0"
_CONTROLLER_ERROR_OID = "1.3.6.1.4.1.1206.4.2.3.9.7.10.0"
_CONTROL_MODE_OID = "1.3.6.1.4.1.1206.4.2.3.6.1.0"

# dmsControlMode: local(2), central(4) — other(1) and external(3) retired
_VALID_CONTROL_MODES = {2, 4}

SHORT_ERROR_BITS = {
    1: "Communications error",
    2: "Power error",
    3: "Attached device error",
    4: "Lamp error",
    5: "Pixel error",
    6: "Photocell error",
    7: "Message error",
    8: "Controller error",
    9: "Temperature warning",
    10: "Climate-control system error",
    11: "Critical temperature error",
    12: "Drum-sign rotor error",
    13: "Door open",
    14: "Humidity warning",
}

CONTROLLER_ERROR_BITS = {
    0: "Other controller error",
    1: "PROM error",
    2: "Program/processor error",
    3: "RAM error",
    4: "Controller-to-display interface error",
}

CONTROL_MODE_NAMES = {2: "local", 4: "central"}


def _sign_snapshot(idx: int, agent: DmsAgent, config: AgentConfig) -> dict:
    state = agent.state
    sign = config.signs[idx]

    current = state.messages.get((5, 1))  # MEM_CURRENT_BUFFER = 5
    multi = (
        current.multistring.decode("latin-1")
        if current and current.multistring
        else ""
    )
    owner = (
        current.owner.decode("latin-1")
        if current and current.owner
        else ""
    )

    short_errors = int(state.scalars[_SHORT_ERROR_OID].value)
    ctrl_errors = int(state.scalars[_CONTROLLER_ERROR_OID].value)
    ctrl_mode = int(state.scalars[_CONTROL_MODE_OID].value)

    return {
        "index": idx,
        "name": sign.name or f"Sign {idx + 1}",
        "port": sign.port,
        "sign_type": sign.sign_type,
        "width_pixels": sign.sign_width_pixels,
        "height_pixels": sign.sign_height_pixels,
        "color_scheme": sign.color_scheme,
        "control_mode": ctrl_mode,
        "control_mode_name": CONTROL_MODE_NAMES.get(ctrl_mode, "unknown"),
        "short_errors": short_errors,
        "controller_errors": ctrl_errors,
        "active_message": {
            "multi": multi,
            "owner": owner,
            "has_message": bool(multi),
        },
    }


def _make_png(graphic) -> bytes:
    """Render a GraphicRecord's bitmap as a minimal PNG image."""
    w, h, g_type = graphic.width, graphic.height, graphic.graphic_type

    pixels = w * h
    if g_type == 1:
        bitmap_size = (pixels + 7) // 8
    elif g_type in (2, 3):
        bitmap_size = pixels
    else:
        bitmap_size = pixels * 3

    block_size = 512
    num_blocks = max(1, (bitmap_size + block_size - 1) // block_size)
    raw_blocks = bytearray()
    for b in range(1, num_blocks + 1):
        raw_blocks.extend(graphic.bitmap_blocks.get(b, b"\x00" * block_size))
    bitmap = bytes(raw_blocks[:bitmap_size])

    def chunk(tag: bytes, data: bytes) -> bytes:
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    if g_type == 1:  # monochrome1bit → grayscale
        bpr = (w + 7) // 8
        rows = []
        for y in range(h):
            row = bytearray(w)
            for x in range(w):
                bi = y * bpr + x // 8
                bit = (bitmap[bi] >> (7 - x % 8)) & 1 if bi < len(bitmap) else 0
                row[x] = 255 if bit else 0
            rows.append(bytes(row))
        ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 0, 0, 0, 0))
    elif g_type == 2:  # monochrome8bit → grayscale
        rows = [bitmap[y * w:(y + 1) * w] for y in range(h)]
        ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 0, 0, 0, 0))
    elif g_type == 3:  # colorClassic → RGB
        _CLASSIC = [
            (0, 0, 0), (255, 0, 0), (255, 255, 0), (0, 255, 0),
            (0, 255, 255), (0, 0, 255), (255, 0, 255), (255, 255, 255),
        ]
        rows = []
        for y in range(h):
            row = bytearray()
            for x in range(w):
                ci = bitmap[y * w + x] if (y * w + x) < len(bitmap) else 0
                row.extend(_CLASSIC[ci % 8])
            rows.append(bytes(row))
        ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    else:  # color24bit → RGB
        stride = w * 3
        rows = [bitmap[y * stride:(y + 1) * stride] for y in range(h)]
        ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))

    raw = b"".join(b"\x00" + row for row in rows)
    idat = chunk(b"IDAT", zlib.compress(raw))
    iend = chunk(b"IEND", b"")
    return b"\x89PNG\r\n\x1a\n" + ihdr + idat + iend


def create_web_app(config: AgentConfig, agents: List[DmsAgent]) -> Flask:
    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    app = Flask(__name__, template_folder=template_dir)
    app.config["JSON_SORT_KEYS"] = False

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/signs")
    def list_signs():
        return jsonify([_sign_snapshot(i, a, config) for i, a in enumerate(agents)])

    @app.route("/api/signs/<int:idx>")
    def get_sign(idx: int):
        if not (0 <= idx < len(agents)):
            return jsonify({"error": "not found"}), 404
        return jsonify(_sign_snapshot(idx, agents[idx], config))

    @app.route("/api/signs/<int:idx>/control_mode", methods=["POST"])
    def set_control_mode(idx: int):
        if not (0 <= idx < len(agents)):
            return jsonify({"error": "not found"}), 404
        body = request.get_json(force=True, silent=True) or {}
        mode = body.get("mode")
        if mode not in _VALID_CONTROL_MODES:
            return jsonify({"error": f"mode must be one of {sorted(_VALID_CONTROL_MODES)}"}), 400
        agents[idx].state.scalars[_CONTROL_MODE_OID] = Value.integer(mode)
        return jsonify({"ok": True})

    @app.route("/api/signs/<int:idx>/short_errors", methods=["POST"])
    def set_short_errors(idx: int):
        if not (0 <= idx < len(agents)):
            return jsonify({"error": "not found"}), 404
        body = request.get_json(force=True, silent=True) or {}
        value = body.get("value")
        if not isinstance(value, int) or not (0 <= value <= 65535):
            return jsonify({"error": "value must be an integer 0–65535"}), 400
        agents[idx].state.scalars[_SHORT_ERROR_OID] = Value.integer(value)
        return jsonify({"ok": True})

    @app.route("/api/signs/<int:idx>/controller_errors", methods=["POST"])
    def set_controller_errors(idx: int):
        if not (0 <= idx < len(agents)):
            return jsonify({"error": "not found"}), 404
        body = request.get_json(force=True, silent=True) or {}
        value = body.get("value")
        if not isinstance(value, int) or not (0 <= value <= 255):
            return jsonify({"error": "value must be an integer 0–255"}), 400
        agents[idx].state.scalars[_CONTROLLER_ERROR_OID] = Value.integer(value)
        return jsonify({"ok": True})

    @app.route("/api/meta")
    def meta():
        return jsonify({
            "short_error_bits": SHORT_ERROR_BITS,
            "controller_error_bits": CONTROLLER_ERROR_BITS,
            "control_mode_names": CONTROL_MODE_NAMES,
        })

    @app.route("/api/signs/<int:idx>/graphics/<int:graphic_number>")
    def get_graphic(idx: int, graphic_number: int):
        if not (0 <= idx < len(agents)):
            return jsonify({"error": "not found"}), 404
        state = agents[idx].state

        # Primary lookup: find by dmsGraphicNumber field
        graphic = next(
            (g for g in state.graphics.values()
             if g.number == graphic_number and g.width > 0 and g.height > 0),
            None,
        )
        # Fallback: use graphic_number as the table index (many ATMS use index == number)
        if graphic is None:
            g = state.graphics.get(graphic_number)
            if g and g.width > 0 and g.height > 0:
                graphic = g

        if graphic is None:
            available = [
                {"table_idx": k, "number": g.number, "w": g.width, "h": g.height, "status": g.status}
                for k, g in state.graphics.items()
                if g.number != 0 or g.width > 0
            ]
            print(f"[graphic] 404: requested number={graphic_number}, available={available}")
            return jsonify({
                "error": "graphic not available",
                "requested_number": graphic_number,
                "available": available,
            }), 404

        print(f"[graphic] serving number={graphic_number}: type={graphic.graphic_type} w={graphic.width} h={graphic.height}")
        try:
            return Response(_make_png(graphic), mimetype="image/png")
        except Exception as exc:
            print(f"[graphic] PNG encode error for number={graphic_number}: {exc}")
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/signs/<int:idx>/graphics/<int:graphic_number>/info")
    def get_graphic_info(idx: int, graphic_number: int):
        """Debug endpoint: returns stored metadata and first bytes of block 1."""
        if not (0 <= idx < len(agents)):
            return jsonify({"error": "not found"}), 404
        state = agents[idx].state
        graphic = next(
            (g for g in state.graphics.values()
             if g.number == graphic_number and g.width > 0 and g.height > 0),
            None,
        )
        if graphic is None:
            g = state.graphics.get(graphic_number)
            if g and g.width > 0 and g.height > 0:
                graphic = g
        if graphic is None:
            return jsonify({"error": "not found"}), 404
        block1 = graphic.bitmap_blocks.get(1, b"")
        return jsonify({
            "table_idx": graphic.index,
            "number": graphic.number,
            "width": graphic.width,
            "height": graphic.height,
            "graphic_type": graphic.graphic_type,
            "status": graphic.status,
            "blocks_stored": sorted(graphic.bitmap_blocks.keys()),
            "block_1_first_32_hex": block1[:32].hex() if block1 else "",
        })

    return app
