"""The SNMP object registry for the simulated DMS agent.

This module maps :class:`ntcip_agent.sign_state.SignState` onto SNMP object
identifiers: the MIB-II ``system`` group, the NTCIP 1203 ``dms`` scalar
objects, and the dmsMessageTable / dmsFontTable / dmsFontCharacterTable /
dmsGraphicTable conceptual tables. :mod:`ntcip_agent.server` walks this
registry to answer GetRequest/GetNextRequest/SetRequest PDUs.
"""

from __future__ import annotations

import bisect
import functools
import json
import os
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from .ber import Value
from .sign_state import SignState

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

SYSTEM = (1, 3, 6, 1, 2, 1, 1)
DMS = (1, 3, 6, 1, 4, 1, 1206, 4, 2, 3)

MESSAGE_TABLE = DMS + (5, 8, 1)
FONT_TABLE = DMS + (3, 2, 1)
CHARACTER_TABLE = DMS + (3, 4, 1)
GRAPHIC_TABLE = DMS + (10, 6, 1)


def _load_json(filename: str) -> dict:
    with open(os.path.join(DATA_DIR, filename), "r") as f:
        return json.load(f)


def _oid(oid_str: str) -> Tuple[int, ...]:
    return tuple(int(part) for part in oid_str.split("."))


@dataclass
class MibObject:
    """A single instantiated SNMP object: an OID plus accessors."""

    oid: Tuple[int, ...]
    name: str
    access: str  # "read-only" or "read-write"
    getter: Callable[[], Value]
    setter: Optional[Callable[[Value], None]] = None

    @property
    def writable(self) -> bool:
        return self.access == "read-write" and self.setter is not None


class MibRegistry:
    """A flat, sorted collection of :class:`MibObject` instances supporting
    exact lookup (for Get/Set) and successor lookup (for GetNext)."""

    def __init__(self) -> None:
        self._objects: Dict[Tuple[int, ...], MibObject] = {}
        self._sorted_oids: List[Tuple[int, ...]] = []

    def register(self, obj: MibObject) -> None:
        self._objects[obj.oid] = obj

    def finalize(self) -> None:
        self._sorted_oids = sorted(self._objects.keys())

    def get(self, oid: Tuple[int, ...]) -> Optional[MibObject]:
        return self._objects.get(oid)

    def next(self, oid: Tuple[int, ...]) -> Optional[MibObject]:
        """Return the object whose OID is the lexicographically smallest
        OID strictly greater than ``oid``, or ``None`` if ``oid`` is at or
        past the end of the MIB view."""
        index = bisect.bisect_right(self._sorted_oids, oid)
        if index >= len(self._sorted_oids):
            return None
        return self._objects[self._sorted_oids[index]]


# --------------------------------------------------------------------------
# generic scalar accessors
# --------------------------------------------------------------------------


def _scalar_getter(state: SignState, oid_str: str) -> Value:
    return state.scalars[oid_str]


def _scalar_setter(state: SignState, oid_str: str, value: Value) -> None:
    state.scalars[oid_str] = value


# --------------------------------------------------------------------------
# dynamic (computed) objects
# --------------------------------------------------------------------------


def _get_sys_up_time(state: SignState) -> Value:
    return Value.time_ticks(state.uptime_centiseconds())


def _get_num_changeable_msg(state: SignState) -> Value:
    return Value.integer(state.num_changeable_msgs())


def _get_num_volatile_msg(state: SignState) -> Value:
    return Value.integer(state.num_volatile_msgs())


def _get_free_changeable_memory(state: SignState) -> Value:
    return Value.integer(state.free_changeable_memory())


def _get_free_volatile_memory(state: SignState) -> Value:
    return Value.integer(state.free_volatile_memory())


def _get_graphic_num_entries(state: SignState) -> Value:
    return Value.integer(state.num_graphics())


def _get_available_graphic_memory(state: SignState) -> Value:
    return Value.counter32(state.available_graphic_memory())


def _get_msg_requester_id(state: SignState) -> Value:
    return Value.ip_address(state.msg_requester_id)


def _get_msg_source_mode(state: SignState) -> Value:
    return Value.integer(state.msg_source_mode)


DYNAMIC_GETTERS: Dict[str, Callable[[SignState], Value]] = {
    "1.3.6.1.4.1.1206.4.2.3.5.2.0": _get_num_changeable_msg,
    "1.3.6.1.4.1.1206.4.2.3.5.4.0": _get_free_changeable_memory,
    "1.3.6.1.4.1.1206.4.2.3.5.5.0": _get_num_volatile_msg,
    "1.3.6.1.4.1.1206.4.2.3.5.7.0": _get_free_volatile_memory,
    "1.3.6.1.4.1.1206.4.2.3.6.6.0": _get_msg_requester_id,
    "1.3.6.1.4.1.1206.4.2.3.6.7.0": _get_msg_source_mode,
    "1.3.6.1.4.1.1206.4.2.3.10.2.0": _get_graphic_num_entries,
    "1.3.6.1.4.1.1206.4.2.3.10.4.0": _get_available_graphic_memory,
}


def _set_dms_activate_message(state: SignState, value: Value) -> None:
    state.activate_message(bytes(value.value))


DYNAMIC_SETTERS: Dict[str, Callable[[SignState, Value], None]] = {
    "1.3.6.1.4.1.1206.4.2.3.6.3.0": _set_dms_activate_message,
}


# --------------------------------------------------------------------------
# registration helpers
# --------------------------------------------------------------------------


def _register_system_group(reg: MibRegistry, state: SignState) -> None:
    entries = [
        ("1.3.6.1.2.1.1.1.0", "sysDescr", "read-only"),
        ("1.3.6.1.2.1.1.2.0", "sysObjectID", "read-only"),
        ("1.3.6.1.2.1.1.3.0", "sysUpTime", "read-only"),
        ("1.3.6.1.2.1.1.4.0", "sysContact", "read-write"),
        ("1.3.6.1.2.1.1.5.0", "sysName", "read-write"),
        ("1.3.6.1.2.1.1.6.0", "sysLocation", "read-write"),
        ("1.3.6.1.2.1.1.7.0", "sysServices", "read-only"),
    ]
    for oid_str, name, access in entries:
        if oid_str == "1.3.6.1.2.1.1.3.0":
            getter = functools.partial(_get_sys_up_time, state)
        else:
            getter = functools.partial(_scalar_getter, state, oid_str)
        setter = None
        if access == "read-write":
            setter = functools.partial(_scalar_setter, state, oid_str)
        reg.register(MibObject(_oid(oid_str), name, access, getter, setter))


def _register_dms_scalars(reg: MibRegistry, state: SignState) -> None:
    for oid_str, entry in _load_json("dms_scalars.json").items():
        access = entry["access"]

        if oid_str in DYNAMIC_GETTERS:
            getter = functools.partial(DYNAMIC_GETTERS[oid_str], state)
        else:
            getter = functools.partial(_scalar_getter, state, oid_str)

        setter = None
        if access == "read-write":
            if oid_str in DYNAMIC_SETTERS:
                setter = functools.partial(DYNAMIC_SETTERS[oid_str], state)
            else:
                setter = functools.partial(_scalar_setter, state, oid_str)

        reg.register(MibObject(_oid(oid_str), entry["name"], access, getter, setter))


def _register_message_table(reg: MibRegistry, state: SignState) -> None:
    def make_getter(key, attr, wrap):
        def getter():
            row = state.messages[key]
            return wrap(getattr(row, attr))

        return getter

    def make_setter(key, attr, unwrap):
        def setter(value: Value) -> None:
            state.set_message_field(key[0], key[1], attr, unwrap(value.value))

        return setter

    def status_setter(key):
        def setter(value: Value) -> None:
            state.set_message_status(key[0], key[1], int(value.value))

        return setter

    columns = [
        (1, "memory_type", Value.integer, None, "read-only"),
        (2, "number", Value.integer, None, "read-only"),
        (3, "multistring", Value.octet_string, bytes, "read-write"),
        (4, "owner", Value.octet_string, bytes, "read-write"),
        (5, "crc", Value.integer, None, "read-only"),
        (6, "beacon", Value.integer, int, "read-write"),
        (7, "pixel_service", Value.integer, int, "read-write"),
        (8, "run_time_priority", Value.integer, int, "read-write"),
        (9, "status", Value.integer, int, "read-write"),
    ]

    names = {
        1: "dmsMessageMemoryType",
        2: "dmsMessageNumber",
        3: "dmsMessageMultiString",
        4: "dmsMessageOwner",
        5: "dmsMessageCRC",
        6: "dmsMessageBeacon",
        7: "dmsMessagePixelService",
        8: "dmsMessageRunTimePriority",
        9: "dmsMessageStatus",
    }

    for key in state.messages:
        memory_type, number = key
        for col, attr, wrap, unwrap, access in columns:
            oid = MESSAGE_TABLE + (col, memory_type, number)
            getter = make_getter(key, attr, wrap)
            setter = None
            if access == "read-write":
                if col == 9:
                    setter = status_setter(key)
                else:
                    setter = make_setter(key, attr, unwrap)
            reg.register(MibObject(oid, names[col], access, getter, setter))


def _register_font_table(reg: MibRegistry, state: SignState) -> None:
    def make_getter(index, attr, wrap):
        def getter():
            return wrap(getattr(state.fonts[index], attr))

        return getter

    def make_setter(index, attr, unwrap):
        def setter(value: Value) -> None:
            setattr(state.fonts[index], attr, unwrap(value.value))

        return setter

    columns = [
        (1, "index", Value.integer, None, "read-only"),
        (2, "number", Value.integer, int, "read-write"),
        (3, "name", Value.octet_string, bytes, "read-write"),
        (4, "height", Value.integer, int, "read-write"),
        (5, "char_spacing", Value.integer, int, "read-write"),
        (6, "line_spacing", Value.integer, int, "read-write"),
        (7, "version_id", Value.integer, None, "read-only"),
        (8, "status", Value.integer, int, "read-write"),
    ]

    names = {
        1: "fontIndex",
        2: "fontNumber",
        3: "fontName",
        4: "fontHeight",
        5: "fontCharSpacing",
        6: "fontLineSpacing",
        7: "fontVersionID",
        8: "fontStatus",
    }

    for index in state.fonts:
        for col, attr, wrap, unwrap, access in columns:
            oid = FONT_TABLE + (col, index)
            getter = make_getter(index, attr, wrap)
            setter = (
                make_setter(index, attr, unwrap) if access == "read-write" else None
            )
            reg.register(MibObject(oid, names[col], access, getter, setter))


def _register_character_table(reg: MibRegistry, state: SignState) -> None:
    def make_getter(font_index, char_number, attr, wrap):
        def getter():
            char = state.fonts[font_index].characters[char_number]
            return wrap(getattr(char, attr))

        return getter

    def make_setter(font_index, char_number, attr, unwrap):
        def setter(value: Value) -> None:
            char = state.fonts[font_index].characters[char_number]
            setattr(char, attr, unwrap(value.value))

        return setter

    columns = [
        (1, "number", Value.integer, None, "read-only"),
        (2, "width", Value.integer, int, "read-write"),
        (3, "bitmap", Value.octet_string, bytes, "read-write"),
    ]

    names = {1: "characterNumber", 2: "characterWidth", 3: "characterBitmap"}

    for font_index, font in state.fonts.items():
        for char_number in font.characters:
            for col, attr, wrap, unwrap, access in columns:
                oid = CHARACTER_TABLE + (col, font_index, char_number)
                getter = make_getter(font_index, char_number, attr, wrap)
                setter = (
                    make_setter(font_index, char_number, attr, unwrap)
                    if access == "read-write"
                    else None
                )
                reg.register(MibObject(oid, names[col], access, getter, setter))


def _register_graphic_table(reg: MibRegistry, state: SignState) -> None:
    def make_getter(index, attr, wrap):
        def getter():
            return wrap(getattr(state.graphics[index], attr))

        return getter

    def make_setter(index, attr, unwrap):
        def setter(value: Value) -> None:
            setattr(state.graphics[index], attr, unwrap(value.value))

        return setter

    columns = [
        (1, "index", Value.integer, None, "read-only"),
        (2, "number", Value.integer, int, "read-write"),
        (3, "name", Value.octet_string, bytes, "read-write"),
        (4, "height", Value.integer, int, "read-write"),
        (5, "width", Value.integer, int, "read-write"),
        (6, "graphic_type", Value.integer, int, "read-write"),
        (7, "graphic_id", Value.integer, None, "read-only"),
        (8, "transparent_enabled", Value.integer, int, "read-write"),
        (9, "transparent_color", Value.octet_string, bytes, "read-write"),
        (10, "status", Value.integer, int, "read-write"),
    ]

    names = {
        1: "dmsGraphicIndex",
        2: "dmsGraphicNumber",
        3: "dmsGraphicName",
        4: "dmsGraphicHeight",
        5: "dmsGraphicWidth",
        6: "dmsGraphicType",
        7: "dmsGraphicID",
        8: "dmsGraphicTransparentEnabled",
        9: "dmsGraphicTransparentColor",
        10: "dmsGraphicStatus",
    }

    for index in state.graphics:
        for col, attr, wrap, unwrap, access in columns:
            oid = GRAPHIC_TABLE + (col, index)
            getter = make_getter(index, attr, wrap)
            setter = (
                make_setter(index, attr, unwrap) if access == "read-write" else None
            )
            reg.register(MibObject(oid, names[col], access, getter, setter))


def build_registry(state: SignState) -> MibRegistry:
    """Build the full SNMP object registry for ``state``."""
    reg = MibRegistry()
    _register_system_group(reg, state)
    _register_dms_scalars(reg, state)
    _register_message_table(reg, state)
    _register_font_table(reg, state)
    _register_character_table(reg, state)
    _register_graphic_table(reg, state)
    reg.finalize()
    return reg
