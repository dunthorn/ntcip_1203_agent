"""Tests for the SNMP object registry built by ntcip_agent.mib_tree."""

import unittest

from ntcip_agent.config import AgentConfig
from ntcip_agent.mib_tree import (
    CHARACTER_TABLE,
    FONT_TABLE,
    GRAPHIC_TABLE,
    MESSAGE_TABLE,
    build_registry,
)
from ntcip_agent.sign_state import MEM_CHANGEABLE, MEM_CURRENT_BUFFER, SignState


def new_registry():
    cfg = AgentConfig.default()
    state = SignState(cfg.signs[0])
    return build_registry(state), state


class TestSystemGroup(unittest.TestCase):
    def test_sys_descr(self):
        reg, _state = new_registry()
        obj = reg.get((1, 3, 6, 1, 2, 1, 1, 1, 0))
        self.assertIsNotNone(obj)
        self.assertEqual(obj.name, "sysDescr")
        self.assertFalse(obj.writable)
        value = obj.getter()
        self.assertIn(b"NTCIP 1203", value.value)

    def test_sys_up_time_is_dynamic(self):
        reg, _state = new_registry()
        obj = reg.get((1, 3, 6, 1, 2, 1, 1, 3, 0))
        first = obj.getter().value
        second = obj.getter().value
        self.assertGreaterEqual(second, first)

    def test_sys_contact_is_writable(self):
        reg, _state = new_registry()
        obj = reg.get((1, 3, 6, 1, 2, 1, 1, 4, 0))
        self.assertTrue(obj.writable)


class TestDmsScalars(unittest.TestCase):
    def test_sign_config_overrides_applied(self):
        reg, _state = new_registry()
        sign_type = reg.get((1, 3, 6, 1, 4, 1, 1206, 4, 2, 3, 1, 2, 0))
        self.assertEqual(sign_type.getter().value, 6)  # vmsFull

        sign_height = reg.get((1, 3, 6, 1, 4, 1, 1206, 4, 2, 3, 2, 3, 0))
        self.assertEqual(sign_height.getter().value, 27)

        sign_width = reg.get((1, 3, 6, 1, 4, 1, 1206, 4, 2, 3, 2, 4, 0))
        self.assertEqual(sign_width.getter().value, 145)

    def test_dynamic_getter_for_free_changeable_memory(self):
        reg, state = new_registry()
        obj = reg.get((1, 3, 6, 1, 4, 1, 1206, 4, 2, 3, 5, 4, 0))
        self.assertEqual(obj.getter().value, state.CHANGEABLE_MEMORY_BYTES)

    def test_dms_activate_message_setter_invokes_activation(self):
        reg, state = new_registry()
        obj = reg.get((1, 3, 6, 1, 4, 1, 1206, 4, 2, 3, 6, 3, 0))
        self.assertTrue(obj.writable)

        from ntcip_agent.ber import Value
        from ntcip_agent.sign_state import MEM_BLANK

        # duration=0, priority=1, memoryType=blank(7), number=1, crc=0, source=0
        code = (
            bytes(2)
            + bytes([1, MEM_BLANK])
            + (1).to_bytes(2, "big")
            + bytes(2)
            + bytes(4)
        )
        obj.setter(Value.octet_string(code))
        # blank activation succeeds; dmsActivateMsgError == none(2)
        err = reg.get((1, 3, 6, 1, 4, 1, 1206, 4, 2, 3, 6, 17, 0))
        self.assertEqual(err.getter().value, 2)


class TestMessageTable(unittest.TestCase):
    def test_current_buffer_columns(self):
        reg, _state = new_registry()
        memory_type, number = MEM_CURRENT_BUFFER, 1

        mem_type_obj = reg.get(MESSAGE_TABLE + (1, memory_type, number))
        self.assertEqual(mem_type_obj.getter().value, memory_type)
        self.assertFalse(mem_type_obj.writable)

        owner_obj = reg.get(MESSAGE_TABLE + (4, memory_type, number))
        self.assertEqual(owner_obj.getter().value, b"NT AUTHORITY\\SYSTEM")

    def test_changeable_multistring_is_writable(self):
        reg, state = new_registry()
        obj = reg.get(MESSAGE_TABLE + (3, MEM_CHANGEABLE, 1))
        self.assertTrue(obj.writable)

        from ntcip_agent.ber import Value

        obj.setter(Value.octet_string(b"HELLO"))
        self.assertEqual(state.messages[(MEM_CHANGEABLE, 1)].multistring, b"HELLO")

    def test_status_setter_drives_state_machine(self):
        reg, state = new_registry()
        from ntcip_agent.ber import Value
        from ntcip_agent.sign_state import MSG_MODIFY_REQ, MSG_MODIFYING

        status_obj = reg.get(MESSAGE_TABLE + (9, MEM_CHANGEABLE, 1))
        status_obj.setter(Value.integer(MSG_MODIFY_REQ))
        self.assertEqual(state.messages[(MEM_CHANGEABLE, 1)].status, MSG_MODIFYING)


class TestFontAndCharacterTables(unittest.TestCase):
    def test_font_20_name(self):
        reg, _state = new_registry()
        obj = reg.get(FONT_TABLE + (3, 20))
        self.assertEqual(obj.getter().value, b"FDOTColorDMS")

    def test_character_33_of_font_20(self):
        reg, _state = new_registry()
        width_obj = reg.get(CHARACTER_TABLE + (2, 20, 33))
        bitmap_obj = reg.get(CHARACTER_TABLE + (3, 20, 33))
        self.assertEqual(width_obj.getter().value, 1)
        self.assertEqual(bitmap_obj.getter().value, b"\xf2")

    def test_unused_character_present_but_empty(self):
        reg, _state = new_registry()
        width_obj = reg.get(CHARACTER_TABLE + (2, 20, 1))
        self.assertEqual(width_obj.getter().value, 0)


class TestGraphicTable(unittest.TestCase):
    def test_all_slots_registered_and_unused(self):
        reg, state = new_registry()
        for index in range(1, state.sign_config.max_graphics + 1):
            obj = reg.get(GRAPHIC_TABLE + (1, index))
            self.assertIsNotNone(obj)
            self.assertEqual(obj.getter().value, index)


class TestGetNextWalk(unittest.TestCase):
    def test_walk_from_root_reaches_sys_descr(self):
        reg, _state = new_registry()
        first = reg.next((1, 3, 6, 1, 2, 1, 1))
        self.assertEqual(first.oid, (1, 3, 6, 1, 2, 1, 1, 1, 0))

    def test_walk_past_end_returns_none(self):
        reg, _state = new_registry()
        last_oid = max(reg._sorted_oids)
        self.assertIsNone(reg.next(last_oid))

    def test_walk_is_strictly_increasing(self):
        reg, _state = new_registry()
        oid = (0,)
        seen = 0
        while True:
            obj = reg.next(oid)
            if obj is None:
                break
            self.assertGreater(obj.oid, oid)
            oid = obj.oid
            seen += 1
        self.assertEqual(seen, len(reg._sorted_oids))


if __name__ == "__main__":
    unittest.main()
