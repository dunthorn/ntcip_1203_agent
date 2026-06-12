"""Round-trip tests for the BER codec."""

import unittest

from ntcip_agent import ber
from ntcip_agent.ber import Value


class TestLength(unittest.TestCase):
    def test_short_form(self):
        for n in (0, 1, 0x7F):
            encoded = ber.encode_length(n)
            self.assertEqual(encoded, bytes([n]))
            decoded, idx = ber.decode_length(encoded, 0)
            self.assertEqual((decoded, idx), (n, len(encoded)))

    def test_long_form(self):
        for n in (0x80, 0xFF, 0x1234, 0x10000):
            encoded = ber.encode_length(n)
            self.assertGreaterEqual(encoded[0], 0x80)
            decoded, idx = ber.decode_length(encoded, 0)
            self.assertEqual((decoded, idx), (n, len(encoded)))


class TestInteger(unittest.TestCase):
    def test_round_trip(self):
        for n in (0, 1, -1, 127, 128, -128, -129, 255, 256, 65535, -65536, 1206):
            encoded = ber.encode_integer(n)
            tag, value, idx = ber.decode_tlv(encoded, 0)
            self.assertEqual(tag, ber.TAG_INTEGER)
            self.assertEqual(ber.decode_integer(value), n)
            self.assertEqual(idx, len(encoded))


class TestUnsigned(unittest.TestCase):
    def test_round_trip(self):
        for n in (0, 1, 127, 128, 255, 256, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF):
            encoded = ber.encode_unsigned(ber.TAG_COUNTER32, n)
            tag, value, idx = ber.decode_tlv(encoded, 0)
            self.assertEqual(tag, ber.TAG_COUNTER32)
            self.assertEqual(ber.decode_unsigned(value), n)


class TestOctetString(unittest.TestCase):
    def test_round_trip(self):
        for data in (b"", b"hello", bytes(range(256))):
            encoded = ber.encode_octet_string(data)
            tag, value, idx = ber.decode_tlv(encoded, 0)
            self.assertEqual(tag, ber.TAG_OCTET_STRING)
            self.assertEqual(ber.decode_octet_string(value), data)


class TestOid(unittest.TestCase):
    def test_round_trip(self):
        for oid in (
            (1, 3, 6, 1, 2, 1, 1, 1, 0),
            (1, 3, 6, 1, 4, 1, 1206, 4, 2, 3, 5, 8, 1, 9, 3, 1),
        ):
            encoded = ber.encode_oid(oid)
            tag, value, idx = ber.decode_tlv(encoded, 0)
            self.assertEqual(tag, ber.TAG_OID)
            self.assertEqual(ber.decode_oid(value), oid)

    def test_large_arc(self):
        # 1206 requires a multi-byte (high-bit-continued) arc encoding
        oid = (1, 3, 6, 1, 4, 1, 1206)
        encoded = ber.encode_oid(oid)
        _tag, value, _idx = ber.decode_tlv(encoded, 0)
        self.assertEqual(ber.decode_oid(value), oid)


class TestValue(unittest.TestCase):
    def test_encode_decode_round_trip(self):
        cases = [
            Value.integer(7439),
            Value.integer(-1),
            Value.octet_string(b"FDOTColorDMS"),
            Value.null(),
            Value.oid((1, 3, 6, 1, 4, 1, 1206, 4, 2, 3)),
            Value.ip_address(b"\x00\x00\x00\x00"),
            Value.counter32(1048576),
            Value.gauge32(512),
            Value.time_ticks(46),
            Value.no_such_object(),
            Value.end_of_mib_view(),
        ]
        for value in cases:
            encoded = value.encode()
            tag, raw, idx = ber.decode_tlv(encoded, 0)
            decoded = Value.decode(tag, raw)
            self.assertEqual(decoded.tag, value.tag)
            self.assertEqual(decoded.value, value.value)
            self.assertEqual(idx, len(encoded))


if __name__ == "__main__":
    unittest.main()
