"""Tests for the dmsMessageTable state machine and message activation."""

import unittest

from ntcip_agent.config import AgentConfig
from ntcip_agent.errors import SetError
from ntcip_agent.sign_state import (
    ACT_ERR_MEMORY_TYPE,
    ACT_ERR_MESSAGE_CRC,
    ACT_ERR_MESSAGE_NUMBER,
    ACT_ERR_MESSAGE_STATUS,
    ACT_ERR_NONE,
    MEM_BLANK,
    MEM_CHANGEABLE,
    MEM_CURRENT_BUFFER,
    MEM_PERMANENT,
    MSG_MODIFY_REQ,
    MSG_MODIFYING,
    MSG_NOT_USED,
    MSG_NOT_USED_REQ,
    MSG_VALID,
    MSG_VALIDATE_REQ,
    SignState,
)


def new_state() -> SignState:
    return SignState(AgentConfig.default().signs[0])


class TestInitialState(unittest.TestCase):
    def test_table_sizes(self):
        state = new_state()
        self.assertEqual(state.num_changeable_msgs(), 0)
        self.assertEqual(state.num_volatile_msgs(), 0)
        self.assertEqual(
            state.free_changeable_memory(), SignState.CHANGEABLE_MEMORY_BYTES
        )
        self.assertEqual(state.free_volatile_memory(), SignState.VOLATILE_MEMORY_BYTES)
        self.assertEqual(state.num_graphics(), 0)
        self.assertEqual(
            state.available_graphic_memory(), SignState.GRAPHIC_MEMORY_BYTES
        )

    def test_current_buffer_starts_blank_and_valid(self):
        state = new_state()
        current = state.messages[(MEM_CURRENT_BUFFER, 1)]
        self.assertEqual(current.status, MSG_VALID)
        self.assertEqual(current.multistring, b"")
        self.assertEqual(current.owner, b"NT AUTHORITY\\SYSTEM")

    def test_font_20_loaded(self):
        state = new_state()
        font = state.fonts[20]
        self.assertEqual(font.number, 220)
        self.assertEqual(font.name, b"FDOTColorDMS")
        self.assertEqual(len(font.characters), 255)
        self.assertEqual(font.characters[33].width, 1)
        self.assertEqual(font.characters[33].bitmap, b"\xf2")
        # unused character slots default to width 0 / empty bitmap
        self.assertEqual(font.characters[1].width, 0)
        self.assertEqual(font.characters[1].bitmap, b"")


class TestMessageStatusStateMachine(unittest.TestCase):
    def test_modify_validate_cycle(self):
        state = new_state()
        state.set_message_status(MEM_CHANGEABLE, 1, MSG_MODIFY_REQ)
        self.assertEqual(state.messages[(MEM_CHANGEABLE, 1)].status, MSG_MODIFYING)

        row = state.messages[(MEM_CHANGEABLE, 1)]
        row.multistring = b"[pt30o0][pb][cf][jp3][jl3][fo220,B62F]TEST"
        row.beacon = 0
        row.pixel_service = 0

        state.set_message_status(MEM_CHANGEABLE, 1, MSG_VALIDATE_REQ)
        self.assertEqual(row.status, MSG_VALID)
        self.assertEqual(row.crc, 7439)

    def test_not_used_req_clears_row(self):
        state = new_state()
        row = state.messages[(MEM_CHANGEABLE, 1)]
        row.multistring = b"HELLO"
        row.owner = b"someone"
        row.beacon = 1
        row.crc = 1234
        row.status = MSG_VALID

        state.set_message_status(MEM_CHANGEABLE, 1, MSG_NOT_USED_REQ)
        self.assertEqual(row.status, MSG_NOT_USED)
        self.assertEqual(row.multistring, b"")
        self.assertEqual(row.owner, b"")
        self.assertEqual(row.beacon, 0)
        self.assertEqual(row.crc, 0)

    def test_writes_to_non_writable_rows_are_rejected(self):
        state = new_state()
        with self.assertRaises(SetError):
            state.set_message_status(MEM_CURRENT_BUFFER, 1, MSG_MODIFY_REQ)
        with self.assertRaises(SetError):
            state.set_message_field(MEM_BLANK, 1, "multistring", b"x")


class TestActivateMessage(unittest.TestCase):
    def _prepare_valid_message(self, state, slot=1, text=b"HELLO"):
        state.set_message_status(MEM_CHANGEABLE, slot, MSG_MODIFY_REQ)
        row = state.messages[(MEM_CHANGEABLE, slot)]
        row.multistring = text
        state.set_message_status(MEM_CHANGEABLE, slot, MSG_VALIDATE_REQ)
        return row

    def _activate_msg_error(self, state):
        return state.scalars["1.3.6.1.4.1.1206.4.2.3.6.17.0"].value

    def test_activate_valid_changeable_message(self):
        state = new_state()
        row = self._prepare_valid_message(state)
        code = (
            (65535).to_bytes(2, "big")
            + bytes([1, MEM_CHANGEABLE])
            + (1).to_bytes(2, "big")
            + row.crc.to_bytes(2, "big")
            + bytes(4)
        )
        state.activate_message(code)
        self.assertEqual(self._activate_msg_error(state), ACT_ERR_NONE)
        current = state.messages[(MEM_CURRENT_BUFFER, 1)]
        self.assertEqual(current.multistring, b"HELLO")
        self.assertEqual(current.crc, row.crc)

    def test_blank_activation(self):
        state = new_state()
        self._prepare_valid_message(state)
        code = (
            (65535).to_bytes(2, "big")
            + bytes([1, MEM_CHANGEABLE])
            + (1).to_bytes(2, "big")
            + state.messages[(MEM_CHANGEABLE, 1)].crc.to_bytes(2, "big")
            + bytes(4)
        )
        state.activate_message(code)

        blank_code = (
            (65535).to_bytes(2, "big")
            + bytes([1, MEM_BLANK])
            + (1).to_bytes(2, "big")
            + (0).to_bytes(2, "big")
            + bytes(4)
        )
        state.activate_message(blank_code)
        self.assertEqual(self._activate_msg_error(state), ACT_ERR_NONE)
        current = state.messages[(MEM_CURRENT_BUFFER, 1)]
        self.assertEqual(current.multistring, b"")

    def test_activate_unknown_message_number(self):
        state = new_state()
        code = (
            (0).to_bytes(2, "big")
            + bytes([1, MEM_CHANGEABLE])
            + (9999).to_bytes(2, "big")
            + (0).to_bytes(2, "big")
            + bytes(4)
        )
        state.activate_message(code)
        self.assertEqual(self._activate_msg_error(state), ACT_ERR_MESSAGE_NUMBER)

    def test_activate_not_yet_valid_message(self):
        state = new_state()
        state.set_message_status(MEM_CHANGEABLE, 1, MSG_MODIFY_REQ)
        code = (
            (0).to_bytes(2, "big")
            + bytes([1, MEM_CHANGEABLE])
            + (1).to_bytes(2, "big")
            + (0).to_bytes(2, "big")
            + bytes(4)
        )
        state.activate_message(code)
        self.assertEqual(self._activate_msg_error(state), ACT_ERR_MESSAGE_STATUS)

    def test_activate_crc_mismatch(self):
        state = new_state()
        row = self._prepare_valid_message(state)
        code = (
            (0).to_bytes(2, "big")
            + bytes([1, MEM_CHANGEABLE])
            + (1).to_bytes(2, "big")
            + (row.crc ^ 0xFFFF).to_bytes(2, "big")
            + bytes(4)
        )
        state.activate_message(code)
        self.assertEqual(self._activate_msg_error(state), ACT_ERR_MESSAGE_CRC)

    def test_activate_bad_memory_type(self):
        state = new_state()
        code = (
            (0).to_bytes(2, "big")
            + bytes([1, MEM_PERMANENT + 100])
            + (1).to_bytes(2, "big")
            + (0).to_bytes(2, "big")
            + bytes(4)
        )
        state.activate_message(code)
        self.assertEqual(self._activate_msg_error(state), ACT_ERR_MEMORY_TYPE)


if __name__ == "__main__":
    unittest.main()
