"""Tests for ntcip_agent.server.DmsAgent.handle_message."""

import unittest

from ntcip_agent import ber
from ntcip_agent.ber import Value
from ntcip_agent.config import AgentConfig
from ntcip_agent.mib_tree import DMS, MESSAGE_TABLE
from ntcip_agent.server import DmsAgent
from ntcip_agent.sign_state import (
    MEM_BLANK,
    MEM_CHANGEABLE,
    MEM_CURRENT_BUFFER,
    MSG_MODIFY_REQ,
    MSG_VALIDATE_REQ,
)
from ntcip_agent.snmp_message import (
    ERR_BAD_VALUE,
    ERR_GEN_ERR,
    ERR_NO_ERROR,
    ERR_NO_SUCH_NAME,
    ERR_READ_ONLY,
    PDU,
    SNMPMessage,
    VarBind,
)

SYS_DESCR = (1, 3, 6, 1, 2, 1, 1, 1, 0)
ACTIVATE_MESSAGE = DMS + (6, 3, 0)
ACTIVATE_MSG_ERROR = DMS + (6, 17, 0)


def new_agent() -> DmsAgent:
    cfg = AgentConfig.default()
    return DmsAgent(cfg.network, cfg.signs[0])


def request(pdu_type, request_id, bindings, community=b"public") -> bytes:
    pdu = PDU(pdu_type=pdu_type, request_id=request_id, variable_bindings=bindings)
    return SNMPMessage(0, community, pdu).encode()


def decode(reply: bytes) -> PDU:
    return SNMPMessage.decode(reply).pdu


class TestGetRequest(unittest.TestCase):
    def test_get_sys_descr(self):
        agent = new_agent()
        reply = agent.handle_message(
            request(ber.TAG_GET_REQUEST, 1, [VarBind(SYS_DESCR, Value.null())])
        )
        pdu = decode(reply)
        self.assertEqual(pdu.error_status, ERR_NO_ERROR)
        self.assertIn(b"NTCIP 1203", pdu.variable_bindings[0].value.value)

    def test_get_unknown_oid_returns_no_such_name(self):
        agent = new_agent()
        bogus = (1, 3, 6, 1, 4, 1, 1206, 99, 99, 99, 0)
        reply = agent.handle_message(
            request(ber.TAG_GET_REQUEST, 2, [VarBind(bogus, Value.null())])
        )
        pdu = decode(reply)
        self.assertEqual(pdu.error_status, ERR_NO_SUCH_NAME)
        self.assertEqual(pdu.error_index, 1)
        self.assertEqual(pdu.variable_bindings[0].value.tag, ber.TAG_NULL)

    def test_wrong_read_community_returns_gen_err(self):
        agent = new_agent()
        reply = agent.handle_message(
            request(
                ber.TAG_GET_REQUEST,
                3,
                [VarBind(SYS_DESCR, Value.null())],
                community=b"wrong",
            )
        )
        pdu = decode(reply)
        self.assertEqual(pdu.error_status, ERR_GEN_ERR)
        # community-error bindings echo the original request bindings
        self.assertEqual(pdu.variable_bindings[0].value.tag, ber.TAG_NULL)


class TestGetNextRequest(unittest.TestCase):
    def test_walk_from_root(self):
        agent = new_agent()
        reply = agent.handle_message(
            request(
                ber.TAG_GET_NEXT_REQUEST,
                4,
                [VarBind((1, 3, 6, 1, 2, 1, 1), Value.null())],
            )
        )
        pdu = decode(reply)
        self.assertEqual(pdu.error_status, ERR_NO_ERROR)
        self.assertEqual(pdu.variable_bindings[0].oid, SYS_DESCR)

    def test_walk_past_end_returns_no_such_name(self):
        agent = new_agent()
        last_oid = max(agent.registry._sorted_oids)
        reply = agent.handle_message(
            request(ber.TAG_GET_NEXT_REQUEST, 5, [VarBind(last_oid, Value.null())])
        )
        pdu = decode(reply)
        self.assertEqual(pdu.error_status, ERR_NO_SUCH_NAME)


class TestSetRequest(unittest.TestCase):
    def test_set_read_only_object_returns_read_only_error(self):
        agent = new_agent()
        reply = agent.handle_message(
            request(
                ber.TAG_SET_REQUEST, 6, [VarBind(SYS_DESCR, Value.octet_string(b"x"))]
            )
        )
        pdu = decode(reply)
        self.assertEqual(pdu.error_status, ERR_READ_ONLY)
        self.assertEqual(pdu.error_index, 1)

    def test_wrong_write_community_returns_gen_err(self):
        agent = new_agent()
        oid = MESSAGE_TABLE + (3, MEM_CHANGEABLE, 1)
        reply = agent.handle_message(
            request(
                ber.TAG_SET_REQUEST,
                7,
                [VarBind(oid, Value.octet_string(b"HI"))],
                community=b"wrong",
            )
        )
        pdu = decode(reply)
        self.assertEqual(pdu.error_status, ERR_GEN_ERR)

    def test_set_invalid_value_returns_bad_value(self):
        agent = new_agent()
        # dmsMessageBeacon expects an integer-convertible value
        oid = MESSAGE_TABLE + (6, MEM_CHANGEABLE, 1)
        reply = agent.handle_message(
            request(
                ber.TAG_SET_REQUEST,
                8,
                [VarBind(oid, Value.octet_string(b"not-a-number"))],
            )
        )
        pdu = decode(reply)
        self.assertEqual(pdu.error_status, ERR_BAD_VALUE)

    def test_set_response_echoes_requested_value(self):
        agent = new_agent()
        oid = MESSAGE_TABLE + (9, MEM_CHANGEABLE, 1)
        reply = agent.handle_message(
            request(
                ber.TAG_SET_REQUEST, 9, [VarBind(oid, Value.integer(MSG_MODIFY_REQ))]
            )
        )
        pdu = decode(reply)
        self.assertEqual(pdu.error_status, ERR_NO_ERROR)
        # echoed back verbatim, even though the stored status becomes modifying(2)
        self.assertEqual(pdu.variable_bindings[0].value.value, MSG_MODIFY_REQ)
        self.assertEqual(agent.state.messages[(MEM_CHANGEABLE, 1)].status, 2)


class TestPutMessageAndBlankLifecycle(unittest.TestCase):
    def test_full_put_message_then_blank(self):
        agent = new_agent()

        def do_set(req_id, oid, value):
            reply = agent.handle_message(
                request(ber.TAG_SET_REQUEST, req_id, [VarBind(oid, value)])
            )
            pdu = decode(reply)
            self.assertEqual(pdu.error_status, ERR_NO_ERROR)
            return pdu

        def do_get(req_id, oid):
            reply = agent.handle_message(
                request(ber.TAG_GET_REQUEST, req_id, [VarBind(oid, Value.null())])
            )
            pdu = decode(reply)
            self.assertEqual(pdu.error_status, ERR_NO_ERROR)
            return pdu.variable_bindings[0].value.value

        slot = (MEM_CHANGEABLE, 1)

        # 1. modifyReq
        do_set(10, MESSAGE_TABLE + (9,) + slot, Value.integer(MSG_MODIFY_REQ))
        # 2. write the multistring
        do_set(11, MESSAGE_TABLE + (3,) + slot, Value.octet_string(b"HELLO"))
        # 3. validateReq -> computes CRC
        do_set(12, MESSAGE_TABLE + (9,) + slot, Value.integer(MSG_VALIDATE_REQ))
        # 4. read back the computed CRC
        crc = do_get(13, MESSAGE_TABLE + (5,) + slot)
        self.assertGreater(crc, 0)

        # 5. activate the message
        activation_code = (
            (0).to_bytes(2, "big")
            + bytes([1, MEM_CHANGEABLE])
            + (1).to_bytes(2, "big")
            + crc.to_bytes(2, "big")
            + bytes(4)
        )
        do_set(14, ACTIVATE_MESSAGE, Value.octet_string(activation_code))

        # 6. dmsActivateMsgError == none(2)
        self.assertEqual(do_get(15, ACTIVATE_MSG_ERROR), 2)

        # 7. currentBuffer now shows the activated message
        self.assertEqual(
            do_get(16, MESSAGE_TABLE + (3, MEM_CURRENT_BUFFER, 1)), b"HELLO"
        )

        # 8. blank the sign
        blank_code = (
            (0).to_bytes(2, "big")
            + bytes([1, MEM_BLANK])
            + (1).to_bytes(2, "big")
            + bytes(2)
            + bytes(4)
        )
        do_set(17, ACTIVATE_MESSAGE, Value.octet_string(blank_code))
        self.assertEqual(do_get(18, ACTIVATE_MSG_ERROR), 2)
        self.assertEqual(do_get(19, MESSAGE_TABLE + (3, MEM_CURRENT_BUFFER, 1)), b"")


if __name__ == "__main__":
    unittest.main()
