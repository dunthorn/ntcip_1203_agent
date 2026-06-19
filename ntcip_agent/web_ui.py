"""Flask-based web UI for monitoring and controlling simulated DMS signs."""

from __future__ import annotations

import os
from typing import List

from flask import Flask, jsonify, render_template, request

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

    return app
