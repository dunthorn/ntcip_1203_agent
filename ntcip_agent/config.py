"""Agent configuration: network/transport settings and sign properties.

The configuration is stored as a JSON file (see ``config.example.json`` at
the repository root). It covers the items called out by the project
specification: IP address / bind address, connection type (TCP or UDP),
port, read-only and read-write SNMP community strings, and the sign
properties shown in ``artifacts/config_screenshot.jpg`` (sign type,
technology, dimensions, color scheme, max graphics, font management).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

from . import ber
from .ber import Value

# --------------------------------------------------------------------------
# Enumerations used to translate the human-readable sign profile into the
# integer codes used by the dms* MIB objects.
# --------------------------------------------------------------------------

SIGN_TYPES = {
    "other": 1,
    "bos": 2,
    "cms": 3,
    "vmsChar": 4,
    "vmsLine": 5,
    "vmsFull": 6,
    "portableOther": 129,
    "portableBOS": 130,
    "portableCMS": 131,
    "portableVMSChar": 132,
    "portableVMSLine": 133,
    "portableVMSFull": 134,
}

# dmsSignTechnology is a bitmask (bit 0 = Other, bit 1 = LED, ...)
SIGN_TECHNOLOGY_BITS = {
    "other": 0,
    "led": 1,
    "flipDisk": 2,
    "fiberOptics": 3,
    "shuttered": 4,
    "bulb": 5,
    "drum": 6,
}

COLOR_SCHEMES = {
    "monochrome1bit": 1,
    "monochrome8bit": 2,
    "colorClassic": 3,
    "color24bit": 4,
}


@dataclass
class NetworkConfig:
    host: str = "0.0.0.0"
    port: int = 161
    transport: str = "udp"  # "udp" or "tcp"
    read_community: str = "public"
    write_community: str = "public"

    def __post_init__(self) -> None:
        transport = self.transport.lower()
        if transport not in ("udp", "tcp"):
            raise ValueError(
                f"transport must be 'udp' or 'tcp', got {self.transport!r}"
            )
        self.transport = transport


@dataclass
class SignConfig:
    sign_type: str = "vmsFull"
    sign_technology: List[str] = field(default_factory=lambda: ["other", "led"])
    sign_height_pixels: int = 27
    sign_width_pixels: int = 145
    color_scheme: str = "color24bit"
    max_graphics: int = 20
    font_management_enabled: bool = True

    def dms_sign_type_value(self) -> int:
        try:
            return SIGN_TYPES[self.sign_type]
        except KeyError:
            raise ValueError(f"unknown sign_type {self.sign_type!r}")

    def dms_sign_technology_value(self) -> int:
        mask = 0
        for tech in self.sign_technology:
            try:
                mask |= 1 << SIGN_TECHNOLOGY_BITS[tech]
            except KeyError:
                raise ValueError(f"unknown sign_technology entry {tech!r}")
        return mask

    def dms_color_scheme_value(self) -> int:
        try:
            return COLOR_SCHEMES[self.color_scheme]
        except KeyError:
            raise ValueError(f"unknown color_scheme {self.color_scheme!r}")

    def scalar_overrides(self) -> Dict[str, Value]:
        """OID(.0) -> Value overrides derived from this sign profile,
        applied on top of the seed scalar values at startup."""
        return {
            "1.3.6.1.4.1.1206.4.2.3.1.2.0": Value.integer(self.dms_sign_type_value()),
            "1.3.6.1.4.1.1206.4.2.3.1.9.0": Value.integer(
                self.dms_sign_technology_value()
            ),
            "1.3.6.1.4.1.1206.4.2.3.2.3.0": Value.integer(self.sign_height_pixels),
            "1.3.6.1.4.1.1206.4.2.3.2.4.0": Value.integer(self.sign_width_pixels),
            "1.3.6.1.4.1.1206.4.2.3.4.11.0": Value.integer(
                self.dms_color_scheme_value()
            ),
            "1.3.6.1.4.1.1206.4.2.3.10.1.0": Value.integer(self.max_graphics),
        }


@dataclass
class AgentConfig:
    network: NetworkConfig = field(default_factory=NetworkConfig)
    sign: SignConfig = field(default_factory=SignConfig)

    @classmethod
    def default(cls) -> "AgentConfig":
        return cls()

    @classmethod
    def load(cls, path: str) -> "AgentConfig":
        with open(path, "r") as f:
            data: Dict[str, Any] = json.load(f)
        network = NetworkConfig(**data.get("network", {}))
        sign = SignConfig(**data.get("sign", {}))
        return cls(network=network, sign=sign)

    def save(self, path: str) -> None:
        data = {"network": asdict(self.network), "sign": asdict(self.sign)}
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
