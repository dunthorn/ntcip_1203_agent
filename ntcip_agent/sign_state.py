"""Simulated state for a single Dynamic Message Sign.

This module owns all of the *mutable* data behind the NTCIP 1203 object
tree: the scalar object table, the dmsMessageTable (and its
dmsMessageStatus state machine), the dmsFontTable/dmsFontCharacterTable, and
the dmsGraphicTable. It also implements the dmsActivateMessage activation
logic (including blanking the sign).

:mod:`ntcip_agent.mib_tree` wires these data structures up to SNMP OIDs; this
module has no SNMP-specific code.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Dict, Tuple

from .ber import Value
from .config import SignConfig
from .crc import compute_message_crc
from .errors import SetError
from .snmp_message import ERR_GEN_ERR, ERR_NO_SUCH_NAME

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

# --------------------------------------------------------------------------
# dmsMessageMemoryType (NTCIP 1203, dmsMessageEntry index 1)
# --------------------------------------------------------------------------
MEM_PERMANENT = 2
MEM_CHANGEABLE = 3
MEM_VOLATILE = 4
MEM_CURRENT_BUFFER = 5
MEM_SCHEDULE = 6
MEM_BLANK = 7

# --------------------------------------------------------------------------
# dmsMessageStatus
# --------------------------------------------------------------------------
MSG_NOT_USED = 1
MSG_MODIFYING = 2
MSG_VALIDATING = 3
MSG_VALID = 4
MSG_ERROR = 5
MSG_MODIFY_REQ = 6
MSG_VALIDATE_REQ = 7
MSG_NOT_USED_REQ = 8

_VALID_MESSAGE_STATUSES = {
    MSG_NOT_USED,
    MSG_MODIFYING,
    MSG_VALIDATING,
    MSG_VALID,
    MSG_ERROR,
    MSG_MODIFY_REQ,
    MSG_VALIDATE_REQ,
    MSG_NOT_USED_REQ,
}

# --------------------------------------------------------------------------
# dmsActivateMsgError
# --------------------------------------------------------------------------
ACT_ERR_OTHER = 1
ACT_ERR_NONE = 2
ACT_ERR_PRIORITY = 3
ACT_ERR_MESSAGE_STATUS = 4
ACT_ERR_MEMORY_TYPE = 5
ACT_ERR_MESSAGE_NUMBER = 6
ACT_ERR_MESSAGE_CRC = 7

# dmsMsgSourceMode
SOURCE_MODE_OTHER = 1
SOURCE_MODE_CENTRAL = 8

# fontStatus
FONT_NOT_USED = 1

# dmsGraphicStatus (NTCIP 1203 v03.05 dmsGraphicStatus values)
GRAPHIC_NOT_USED = 1
GRAPHIC_MODIFYING = 2
GRAPHIC_CALCULATING_ID = 3
GRAPHIC_READY_FOR_USE = 4
GRAPHIC_IN_USE = 5
GRAPHIC_PERMANENT = 6
GRAPHIC_MODIFY_REQ = 7
GRAPHIC_READY_FOR_USE_REQ = 8
GRAPHIC_NOT_USED_REQ = 9


@dataclass
class MessageRecord:
    memory_type: int
    number: int
    multistring: bytes = b""
    owner: bytes = b""
    beacon: int = 0
    pixel_service: int = 0
    run_time_priority: int = 1
    status: int = MSG_NOT_USED
    crc: int = 0

    def writable(self) -> bool:
        """Only 'changeable' and 'volatile' rows may be created/modified by
        a management station; permanent/currentBuffer/schedule/blank rows
        are fixed or managed solely by the controller itself."""
        return self.memory_type in (MEM_CHANGEABLE, MEM_VOLATILE)


@dataclass
class CharacterRecord:
    number: int
    width: int = 0
    bitmap: bytes = b""


@dataclass
class FontRecord:
    index: int
    number: int
    name: bytes
    height: int
    char_spacing: int
    line_spacing: int
    version_id: int
    status: int
    characters: Dict[int, CharacterRecord] = field(default_factory=dict)


@dataclass
class GraphicRecord:
    index: int
    number: int = 0
    name: bytes = b""
    height: int = 0
    width: int = 0
    graphic_type: int = 1
    graphic_id: int = 0
    transparent_enabled: int = 0
    transparent_color: bytes = b"\x00"
    status: int = GRAPHIC_NOT_USED


def _load_json(filename: str) -> dict:
    with open(os.path.join(DATA_DIR, filename), "r") as f:
        return json.load(f)


class SignState:
    """All mutable state for the simulated DMS, plus the business logic for
    the message-table state machine and message activation."""

    # Total simulated changeable/volatile message-store sizes, in bytes of
    # dmsMessageMultiString content. Used to compute
    # dmsFreeChangeableMemory/dmsFreeVolatileMemory.
    CHANGEABLE_MEMORY_BYTES = 64000
    VOLATILE_MEMORY_BYTES = 16000
    GRAPHIC_MEMORY_BYTES = 1048576

    def __init__(self, sign_config: SignConfig):
        self.sign_config = sign_config
        self.start_time = time.monotonic()

        self.scalars: Dict[str, Value] = {}
        self.messages: Dict[Tuple[int, int], MessageRecord] = {}
        self.fonts: Dict[int, FontRecord] = {}
        self.graphics: Dict[int, GraphicRecord] = {}

        self.msg_requester_id: bytes = b"\x00\x00\x00\x00"
        self.msg_source_mode: int = SOURCE_MODE_OTHER

        self._load_scalars()
        self._apply_sign_config()
        self._init_messages()
        self._init_fonts()
        self._init_graphics()

        self.msg_table_source: bytes = bytes(
            self.scalars["1.3.6.1.4.1.1206.4.2.3.6.5.0"].value
        )

    # ------------------------------------------------------------------
    # initialization
    # ------------------------------------------------------------------

    def _load_scalars(self) -> None:
        for oid, entry in _load_json("dms_scalars.json").items():
            if entry["tag"] == "OCTET STRING":
                self.scalars[oid] = Value.octet_string(bytes.fromhex(entry["hex"]))
            elif entry["tag"] == "Counter32":
                self.scalars[oid] = Value.counter32(entry["value"])
            elif entry["tag"] == "IpAddress":
                self.scalars[oid] = Value.ip_address(bytes.fromhex(entry["value"]))
            else:
                self.scalars[oid] = Value.integer(entry["value"])

        # MIB-II system group (1.3.6.1.2.1.1)
        self.scalars["1.3.6.1.2.1.1.1.0"] = Value.octet_string(
            b"NTCIP 1203 Dynamic Message Sign Agent (simulator)"
        )
        self.scalars["1.3.6.1.2.1.1.2.0"] = Value.oid((1, 3, 6, 1, 4, 1, 1206, 4, 2, 3))
        self.scalars["1.3.6.1.2.1.1.4.0"] = Value.octet_string(b"")
        self.scalars["1.3.6.1.2.1.1.5.0"] = Value.octet_string(b"ntcip-1203-agent")
        self.scalars["1.3.6.1.2.1.1.6.0"] = Value.octet_string(b"")
        self.scalars["1.3.6.1.2.1.1.7.0"] = Value.integer(72)

    def _apply_sign_config(self) -> None:
        for oid, value in self.sign_config.scalar_overrides().items():
            self.scalars[oid] = value

    def _init_messages(self) -> None:
        max_changeable = self.scalars["1.3.6.1.4.1.1206.4.2.3.5.3.0"].value
        max_volatile = self.scalars["1.3.6.1.4.1.1206.4.2.3.5.6.0"].value

        for number in range(1, max_changeable + 1):
            self.messages[(MEM_CHANGEABLE, number)] = MessageRecord(
                MEM_CHANGEABLE, number
            )
        for number in range(1, max_volatile + 1):
            self.messages[(MEM_VOLATILE, number)] = MessageRecord(MEM_VOLATILE, number)

        # the blank message is always valid, empty, and CRC == 0
        self.messages[(MEM_BLANK, 1)] = MessageRecord(MEM_BLANK, 1, status=MSG_VALID)
        # the currently scheduled message (none, by default)
        self.messages[(MEM_SCHEDULE, 1)] = MessageRecord(
            MEM_SCHEDULE, 1, status=MSG_NOT_USED
        )
        # the currently displayed message starts out blank, owned by the
        # controller itself
        self.messages[(MEM_CURRENT_BUFFER, 1)] = MessageRecord(
            MEM_CURRENT_BUFFER, 1, status=MSG_VALID, owner=b"NT AUTHORITY\\SYSTEM"
        )

    def _init_fonts(self) -> None:
        num_fonts = self.scalars["1.3.6.1.4.1.1206.4.2.3.3.1.0"].value
        max_characters = self.scalars["1.3.6.1.4.1.1206.4.2.3.3.3.0"].value
        font20 = _load_json("font_220.json")

        for index in range(1, num_fonts + 1):
            # every font has an entry for each character 1..maxFontCharacters;
            # unused characters report width 0 and an empty bitmap
            characters = {
                number: CharacterRecord(number)
                for number in range(1, max_characters + 1)
            }
            if index == font20["fontIndex"]:
                for num, data in font20["characters"].items():
                    characters[int(num)] = CharacterRecord(
                        int(num), data["width"], bytes.fromhex(data["bitmap"])
                    )
                self.fonts[index] = FontRecord(
                    index=index,
                    number=font20["fontNumber"],
                    name=font20["fontName"].encode("latin-1"),
                    height=font20["fontHeight"],
                    char_spacing=font20["fontCharSpacing"],
                    line_spacing=font20["fontLineSpacing"],
                    version_id=font20["fontVersionID"],
                    status=font20["fontStatus"],
                    characters=characters,
                )
            else:
                # unused font slots, present so numFonts/GetNext walks are
                # consistent, but not populated
                self.fonts[index] = FontRecord(
                    index=index,
                    number=index,
                    name=b"",
                    height=0,
                    char_spacing=0,
                    line_spacing=0,
                    version_id=0,
                    status=FONT_NOT_USED,
                    characters=characters,
                )

    def _init_graphics(self) -> None:
        max_entries = self.scalars["1.3.6.1.4.1.1206.4.2.3.10.1.0"].value
        for index in range(1, max_entries + 1):
            self.graphics[index] = GraphicRecord(index=index)

    # ------------------------------------------------------------------
    # derived/dynamic scalars
    # ------------------------------------------------------------------

    def uptime_centiseconds(self) -> int:
        return int((time.monotonic() - self.start_time) * 100) & 0xFFFFFFFF

    def num_changeable_msgs(self) -> int:
        return sum(
            1
            for m in self.messages.values()
            if m.memory_type == MEM_CHANGEABLE and m.status != MSG_NOT_USED
        )

    def num_volatile_msgs(self) -> int:
        return sum(
            1
            for m in self.messages.values()
            if m.memory_type == MEM_VOLATILE and m.status != MSG_NOT_USED
        )

    def free_changeable_memory(self) -> int:
        used = sum(
            len(m.multistring)
            for m in self.messages.values()
            if m.memory_type == MEM_CHANGEABLE and m.status != MSG_NOT_USED
        )
        return max(0, self.CHANGEABLE_MEMORY_BYTES - used)

    def free_volatile_memory(self) -> int:
        used = sum(
            len(m.multistring)
            for m in self.messages.values()
            if m.memory_type == MEM_VOLATILE and m.status != MSG_NOT_USED
        )
        return max(0, self.VOLATILE_MEMORY_BYTES - used)

    def num_graphics(self) -> int:
        return sum(1 for g in self.graphics.values() if g.status != GRAPHIC_NOT_USED)

    def _graphic_size_bytes(self, g: GraphicRecord) -> int:
        pixels = g.height * g.width
        if g.graphic_type == 1:  # monochrome1bit
            return (pixels + 7) // 8
        if g.graphic_type in (2, 3):  # monochrome8bit / colorClassic
            return pixels
        return pixels * 3  # color24bit

    def available_graphic_memory(self) -> int:
        used = sum(
            self._graphic_size_bytes(g)
            for g in self.graphics.values()
            if g.status != GRAPHIC_NOT_USED
        )
        return max(0, self.GRAPHIC_MEMORY_BYTES - used)

    # ------------------------------------------------------------------
    # dmsMessageStatus state machine
    # ------------------------------------------------------------------

    def set_message_status(
        self, memory_type: int, number: int, new_status: int
    ) -> None:
        row = self.messages.get((memory_type, number))
        if row is None:
            raise SetError(ERR_NO_SUCH_NAME)
        if new_status not in _VALID_MESSAGE_STATUSES:
            raise SetError(ERR_GEN_ERR)
        if not row.writable():
            raise SetError(ERR_GEN_ERR)

        if new_status == MSG_NOT_USED_REQ:
            row.multistring = b""
            row.owner = b""
            row.beacon = 0
            row.pixel_service = 0
            row.run_time_priority = 1
            row.crc = 0
            row.status = MSG_NOT_USED
        elif new_status == MSG_MODIFY_REQ:
            row.status = MSG_MODIFYING
        elif new_status == MSG_VALIDATE_REQ:
            row.crc = compute_message_crc(
                row.multistring, row.beacon, row.pixel_service
            )
            row.status = MSG_VALID
        else:
            row.status = new_status

    def set_message_field(
        self, memory_type: int, number: int, field_name: str, value
    ) -> None:
        row = self.messages.get((memory_type, number))
        if row is None:
            raise SetError(ERR_NO_SUCH_NAME)
        if not row.writable():
            raise SetError(ERR_GEN_ERR)
        setattr(row, field_name, value)

    # ------------------------------------------------------------------
    # dmsActivateMessage
    # ------------------------------------------------------------------

    def activate_message(self, code: bytes) -> None:
        """Process a 12-byte MessageActivationCode written to
        dmsActivateMessage, updating dmsActivateMsgError, the
        currentBuffer message row, dmsMsgTableSource,
        dmsMessageTimeRemaining, dmsMsgRequesterID and dmsMsgSourceMode."""
        if len(code) != 12:
            raise SetError(ERR_GEN_ERR)

        duration = int.from_bytes(code[0:2], "big")
        priority = code[2]
        memory_type = code[3]
        number = int.from_bytes(code[4:6], "big")
        crc = int.from_bytes(code[6:8], "big")
        source_address = code[8:12]

        current = self.messages[(MEM_CURRENT_BUFFER, 1)]
        error = ACT_ERR_NONE

        if memory_type == MEM_BLANK:
            current.multistring = b""
            current.owner = b""
            current.beacon = 0
            current.pixel_service = 0
            current.run_time_priority = priority
            current.crc = 0
            current.status = MSG_VALID
            self.msg_table_source = (
                bytes([MEM_BLANK]) + (1).to_bytes(2, "big") + (0).to_bytes(2, "big")
            )
        elif memory_type in (MEM_PERMANENT, MEM_CHANGEABLE, MEM_VOLATILE, MEM_SCHEDULE):
            row = self.messages.get((memory_type, number))
            if row is None:
                error = ACT_ERR_MESSAGE_NUMBER
            elif row.status != MSG_VALID:
                error = ACT_ERR_MESSAGE_STATUS
            elif row.crc != crc:
                error = ACT_ERR_MESSAGE_CRC
            else:
                current.multistring = row.multistring
                current.owner = row.owner
                current.beacon = row.beacon
                current.pixel_service = row.pixel_service
                current.run_time_priority = priority
                current.crc = row.crc
                current.status = MSG_VALID
                self.msg_table_source = (
                    bytes([memory_type])
                    + number.to_bytes(2, "big")
                    + row.crc.to_bytes(2, "big")
                )
        else:
            error = ACT_ERR_MEMORY_TYPE

        self.scalars["1.3.6.1.4.1.1206.4.2.3.6.17.0"] = Value.integer(error)
        if error != ACT_ERR_NONE:
            self.scalars["1.3.6.1.4.1.1206.4.2.3.6.24.0"] = Value.octet_string(code)

        self.scalars["1.3.6.1.4.1.1206.4.2.3.6.3.0"] = Value.octet_string(code)
        self.scalars["1.3.6.1.4.1.1206.4.2.3.6.4.0"] = Value.integer(duration)
        self.msg_requester_id = source_address
        if error == ACT_ERR_NONE:
            self.msg_source_mode = SOURCE_MODE_CENTRAL

    # ------------------------------------------------------------------
    # dmsGraphicStatus state machine
    # ------------------------------------------------------------------

    def set_graphic_status(self, index: int, new_status: int) -> None:
        row = self.graphics.get(index)
        if row is None:
            raise SetError(ERR_NO_SUCH_NAME)

        if new_status == GRAPHIC_NOT_USED_REQ:
            row.number = 0
            row.name = b""
            row.height = 0
            row.width = 0
            row.graphic_type = 1
            row.graphic_id = 0
            row.transparent_enabled = 0
            row.transparent_color = b"\x00"
            row.status = GRAPHIC_NOT_USED
        elif new_status == GRAPHIC_MODIFY_REQ:
            row.number = 0
            row.name = b""
            row.height = 0
            row.width = 0
            row.graphic_type = 1
            row.graphic_id = 0
            row.transparent_enabled = 0
            row.transparent_color = b"\x00"
            row.status = GRAPHIC_MODIFYING
        elif new_status == GRAPHIC_READY_FOR_USE_REQ:
            row.graphic_id = self._compute_graphic_id(index)
            row.status = GRAPHIC_READY_FOR_USE
        else:
            raise SetError(ERR_GEN_ERR)

    def _compute_graphic_id(self, index: int) -> int:
        row = self.graphics[index]
        h = row.number * 31 + row.height * 97 + row.width * 7 + row.graphic_type
        return (h & 0xFFFF) or 1
