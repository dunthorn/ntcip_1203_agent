"""Minimal BER (Basic Encoding Rules) codec for the ASN.1 types used by
SNMPv1/v2c.

Only the small subset of ASN.1/BER required to speak SNMP is implemented:
INTEGER, OCTET STRING, NULL, OBJECT IDENTIFIER, SEQUENCE, and the
application-wide types Counter32, Gauge32/Unsigned32, TimeTicks, IpAddress
and Opaque, plus the context-specific SNMP PDU tags and the SNMPv2
exception values (noSuchObject/noSuchInstance/endOfMibView).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple, Union

# --------------------------------------------------------------------------
# Tag constants
# --------------------------------------------------------------------------

TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30

# Application-class tags (SNMP SMI)
TAG_IP_ADDRESS = 0x40
TAG_COUNTER32 = 0x41
TAG_GAUGE32 = 0x42
TAG_TIME_TICKS = 0x43
TAG_OPAQUE = 0x44
TAG_COUNTER64 = 0x46

# SNMPv2 exception tags (context-specific, primitive)
TAG_NO_SUCH_OBJECT = 0x80
TAG_NO_SUCH_INSTANCE = 0x81
TAG_END_OF_MIB_VIEW = 0x82

# PDU tags (context-specific, constructed)
TAG_GET_REQUEST = 0xA0
TAG_GET_NEXT_REQUEST = 0xA1
TAG_GET_RESPONSE = 0xA2
TAG_SET_REQUEST = 0xA3
TAG_TRAP = 0xA4
TAG_GET_BULK_REQUEST = 0xA5
TAG_INFORM_REQUEST = 0xA6
TAG_SNMPV2_TRAP = 0xA7


class BerError(ValueError):
    """Raised when BER-encoded data cannot be decoded."""


# --------------------------------------------------------------------------
# Length encoding/decoding
# --------------------------------------------------------------------------


def encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = bytearray()
    n = length
    while n:
        encoded.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(encoded)]) + bytes(encoded)


def decode_length(data: bytes, idx: int) -> Tuple[int, int]:
    if idx >= len(data):
        raise BerError("truncated length")
    first = data[idx]
    idx += 1
    if first < 0x80:
        return first, idx
    num_bytes = first & 0x7F
    if num_bytes == 0:
        raise BerError("indefinite length not supported")
    if idx + num_bytes > len(data):
        raise BerError("truncated length")
    length = int.from_bytes(data[idx : idx + num_bytes], "big")
    return length, idx + num_bytes


# --------------------------------------------------------------------------
# TLV (tag-length-value) primitives
# --------------------------------------------------------------------------


def encode_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + encode_length(len(value)) + value


def decode_tlv(data: bytes, idx: int) -> Tuple[int, bytes, int]:
    if idx >= len(data):
        raise BerError("truncated TLV")
    tag = data[idx]
    idx += 1
    length, idx = decode_length(data, idx)
    if idx + length > len(data):
        raise BerError("truncated TLV value")
    value = data[idx : idx + length]
    return tag, value, idx + length


# --------------------------------------------------------------------------
# INTEGER (signed) and unsigned application types
# --------------------------------------------------------------------------


def encode_integer(value: int) -> bytes:
    if value == 0:
        body = b"\x00"
    else:
        n_bytes = (value.bit_length() // 8) + 1
        body = value.to_bytes(n_bytes, "big", signed=True)
        # Trim redundant leading 0x00/0xFF bytes while keeping sign correct.
        while len(body) > 1 and (
            (body[0] == 0x00 and body[1] < 0x80)
            or (body[0] == 0xFF and body[1] >= 0x80)
        ):
            body = body[1:]
    return encode_tlv(TAG_INTEGER, body)


def decode_integer(value: bytes) -> int:
    if not value:
        return 0
    return int.from_bytes(value, "big", signed=True)


def encode_unsigned(tag: int, value: int) -> bytes:
    """Encode an unsigned 32/64-bit value, prefixing a 0x00 byte when the
    high bit of the first byte would otherwise make the value look
    negative (per BER INTEGER rules, which also apply to these types)."""
    if value == 0:
        body = b"\x00"
    else:
        n_bytes = (value.bit_length() + 7) // 8
        body = value.to_bytes(n_bytes, "big")
        if body[0] & 0x80:
            body = b"\x00" + body
    return encode_tlv(tag, body)


def decode_unsigned(value: bytes) -> int:
    if not value:
        return 0
    return int.from_bytes(value, "big", signed=False)


# --------------------------------------------------------------------------
# OCTET STRING / NULL
# --------------------------------------------------------------------------


def encode_octet_string(value: bytes) -> bytes:
    return encode_tlv(TAG_OCTET_STRING, bytes(value))


def decode_octet_string(value: bytes) -> bytes:
    return bytes(value)


def encode_null() -> bytes:
    return encode_tlv(TAG_NULL, b"")


# --------------------------------------------------------------------------
# OBJECT IDENTIFIER
# --------------------------------------------------------------------------


def encode_oid(oid: Tuple[int, ...]) -> bytes:
    if len(oid) < 2:
        raise BerError("OID must have at least two arcs")
    first = oid[0] * 40 + oid[1]
    body = bytearray([first])
    for arc in oid[2:]:
        body.extend(_encode_oid_arc(arc))
    return encode_tlv(TAG_OID, bytes(body))


def _encode_oid_arc(arc: int) -> bytes:
    if arc == 0:
        return b"\x00"
    chunks = []
    n = arc
    while n:
        chunks.insert(0, n & 0x7F)
        n >>= 7
    for i in range(len(chunks) - 1):
        chunks[i] |= 0x80
    return bytes(chunks)


def decode_oid(value: bytes) -> Tuple[int, ...]:
    if not value:
        return ()
    first = value[0]
    arcs = [first // 40, first % 40]
    idx = 1
    n = 0
    while idx < len(value):
        b = value[idx]
        idx += 1
        n = (n << 7) | (b & 0x7F)
        if not (b & 0x80):
            arcs.append(n)
            n = 0
    return tuple(arcs)


# --------------------------------------------------------------------------
# SEQUENCE
# --------------------------------------------------------------------------


def encode_sequence(parts: bytes, tag: int = TAG_SEQUENCE) -> bytes:
    return encode_tlv(tag, parts)


# --------------------------------------------------------------------------
# High level "value" representation
# --------------------------------------------------------------------------


@dataclass
class Value:
    """A typed SNMP value, identified by its BER tag."""

    tag: int
    value: object

    @classmethod
    def integer(cls, value: int) -> "Value":
        return cls(TAG_INTEGER, int(value))

    @classmethod
    def octet_string(cls, value: bytes) -> "Value":
        return cls(TAG_OCTET_STRING, bytes(value))

    @classmethod
    def null(cls) -> "Value":
        return cls(TAG_NULL, None)

    @classmethod
    def oid(cls, value: Tuple[int, ...]) -> "Value":
        return cls(TAG_OID, tuple(value))

    @classmethod
    def ip_address(cls, value: bytes) -> "Value":
        return cls(TAG_IP_ADDRESS, bytes(value))

    @classmethod
    def counter32(cls, value: int) -> "Value":
        return cls(TAG_COUNTER32, int(value))

    @classmethod
    def gauge32(cls, value: int) -> "Value":
        return cls(TAG_GAUGE32, int(value))

    @classmethod
    def time_ticks(cls, value: int) -> "Value":
        return cls(TAG_TIME_TICKS, int(value))

    @classmethod
    def opaque(cls, value: bytes) -> "Value":
        return cls(TAG_OPAQUE, bytes(value))

    @classmethod
    def no_such_object(cls) -> "Value":
        return cls(TAG_NO_SUCH_OBJECT, None)

    @classmethod
    def no_such_instance(cls) -> "Value":
        return cls(TAG_NO_SUCH_INSTANCE, None)

    @classmethod
    def end_of_mib_view(cls) -> "Value":
        return cls(TAG_END_OF_MIB_VIEW, None)

    def is_exception(self) -> bool:
        return self.tag in (
            TAG_NO_SUCH_OBJECT,
            TAG_NO_SUCH_INSTANCE,
            TAG_END_OF_MIB_VIEW,
        )

    def encode(self) -> bytes:
        if self.tag == TAG_INTEGER:
            return encode_integer(self.value)
        if self.tag == TAG_OCTET_STRING:
            return encode_octet_string(self.value)
        if self.tag == TAG_NULL:
            return encode_null()
        if self.tag == TAG_OID:
            return encode_oid(self.value)
        if self.tag in (TAG_COUNTER32, TAG_GAUGE32, TAG_TIME_TICKS):
            return encode_unsigned(self.tag, self.value)
        if self.tag == TAG_IP_ADDRESS:
            return encode_tlv(TAG_IP_ADDRESS, bytes(self.value))
        if self.tag == TAG_OPAQUE:
            return encode_tlv(TAG_OPAQUE, bytes(self.value))
        if self.tag in (
            TAG_NO_SUCH_OBJECT,
            TAG_NO_SUCH_INSTANCE,
            TAG_END_OF_MIB_VIEW,
        ):
            return encode_tlv(self.tag, b"")
        raise BerError(f"unsupported value tag 0x{self.tag:02x}")

    @classmethod
    def decode(cls, tag: int, value: bytes) -> "Value":
        if tag == TAG_INTEGER:
            return cls(tag, decode_integer(value))
        if tag == TAG_OCTET_STRING:
            return cls(tag, decode_octet_string(value))
        if tag == TAG_NULL:
            return cls(tag, None)
        if tag == TAG_OID:
            return cls(tag, decode_oid(value))
        if tag in (TAG_COUNTER32, TAG_GAUGE32, TAG_TIME_TICKS, TAG_COUNTER64):
            return cls(tag, decode_unsigned(value))
        if tag == TAG_IP_ADDRESS:
            return cls(tag, bytes(value))
        if tag == TAG_OPAQUE:
            return cls(tag, bytes(value))
        if tag in (TAG_NO_SUCH_OBJECT, TAG_NO_SUCH_INSTANCE, TAG_END_OF_MIB_VIEW):
            return cls(tag, None)
        # Unknown tag: keep the raw bytes so the message can still round-trip.
        return cls(tag, value)

    def __repr__(self) -> str:
        names = {
            TAG_INTEGER: "INTEGER",
            TAG_OCTET_STRING: "OCTET STRING",
            TAG_NULL: "NULL",
            TAG_OID: "OID",
            TAG_COUNTER32: "Counter32",
            TAG_GAUGE32: "Gauge32",
            TAG_TIME_TICKS: "TimeTicks",
            TAG_IP_ADDRESS: "IpAddress",
            TAG_OPAQUE: "Opaque",
            TAG_NO_SUCH_OBJECT: "noSuchObject",
            TAG_NO_SUCH_INSTANCE: "noSuchInstance",
            TAG_END_OF_MIB_VIEW: "endOfMibView",
        }
        name = names.get(self.tag, f"0x{self.tag:02x}")
        return f"Value({name}, {self.value!r})"
