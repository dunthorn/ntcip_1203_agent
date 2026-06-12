"""Round-trip tests for SNMPv1 message/PDU encoding."""

import unittest

from ntcip_agent import ber
from ntcip_agent.ber import Value
from ntcip_agent.snmp_message import PDU, SNMPMessage, VarBind


class TestSnmpMessage(unittest.TestCase):
    def test_get_request_round_trip(self):
        pdu = PDU(
            pdu_type=ber.TAG_GET_REQUEST,
            request_id=17344,
            variable_bindings=[
                VarBind((1, 3, 6, 1, 4, 1, 1206, 4, 2, 3, 9, 7, 1, 0), Value.null())
            ],
        )
        message = SNMPMessage(0, b"public", pdu)
        encoded = message.encode()
        decoded = SNMPMessage.decode(encoded)

        self.assertEqual(decoded.version, 0)
        self.assertEqual(decoded.community, b"public")
        self.assertEqual(decoded.pdu.pdu_type, ber.TAG_GET_REQUEST)
        self.assertEqual(decoded.pdu.request_id, 17344)
        self.assertEqual(decoded.pdu.error_status, 0)
        self.assertEqual(decoded.pdu.error_index, 0)
        self.assertEqual(len(decoded.pdu.variable_bindings), 1)
        vb = decoded.pdu.variable_bindings[0]
        self.assertEqual(vb.oid, (1, 3, 6, 1, 4, 1, 1206, 4, 2, 3, 9, 7, 1, 0))
        self.assertTrue(vb.value.tag == ber.TAG_NULL)

    def test_get_response_with_multiple_bindings(self):
        pdu = PDU(
            pdu_type=ber.TAG_GET_RESPONSE,
            request_id=1,
            error_status=0,
            error_index=0,
            variable_bindings=[
                VarBind((1, 3, 6, 1, 2, 1, 1, 1, 0), Value.octet_string(b"hello")),
                VarBind((1, 3, 6, 1, 2, 1, 1, 7, 0), Value.integer(72)),
            ],
        )
        message = SNMPMessage(0, b"public", pdu)
        decoded = SNMPMessage.decode(message.encode())
        self.assertEqual(len(decoded.pdu.variable_bindings), 2)
        self.assertEqual(decoded.pdu.variable_bindings[0].value.value, b"hello")
        self.assertEqual(decoded.pdu.variable_bindings[1].value.value, 72)

    def test_error_status_round_trip(self):
        pdu = PDU(
            pdu_type=ber.TAG_GET_RESPONSE,
            request_id=2,
            error_status=2,
            error_index=1,
            variable_bindings=[VarBind((1, 3, 6, 1, 2, 1, 1, 99, 0), Value.null())],
        )
        message = SNMPMessage(0, b"public", pdu)
        decoded = SNMPMessage.decode(message.encode())
        self.assertEqual(decoded.pdu.error_status, 2)
        self.assertEqual(decoded.pdu.error_index, 1)


if __name__ == "__main__":
    unittest.main()
