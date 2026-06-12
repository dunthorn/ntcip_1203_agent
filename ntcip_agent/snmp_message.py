"""SNMPv1/v2c message and PDU encoding/decoding built on top of :mod:`ber`."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

from . import ber
from .ber import Value

SNMP_VERSION_1 = 0
SNMP_VERSION_2C = 1

# error-status values (SNMPv1, RFC 1157)
ERR_NO_ERROR = 0
ERR_TOO_BIG = 1
ERR_NO_SUCH_NAME = 2
ERR_BAD_VALUE = 3
ERR_READ_ONLY = 4
ERR_GEN_ERR = 5

PDU_NAMES = {
    ber.TAG_GET_REQUEST: "GetRequest",
    ber.TAG_GET_NEXT_REQUEST: "GetNextRequest",
    ber.TAG_GET_RESPONSE: "GetResponse",
    ber.TAG_SET_REQUEST: "SetRequest",
    ber.TAG_TRAP: "Trap",
    ber.TAG_GET_BULK_REQUEST: "GetBulkRequest",
    ber.TAG_INFORM_REQUEST: "InformRequest",
    ber.TAG_SNMPV2_TRAP: "SNMPv2-Trap",
}


@dataclass
class VarBind:
    oid: Tuple[int, ...]
    value: Value

    def encode(self) -> bytes:
        body = ber.encode_oid(self.oid) + self.value.encode()
        return ber.encode_sequence(body)

    @classmethod
    def decode(cls, data: bytes, idx: int) -> Tuple["VarBind", int]:
        tag, value, idx = ber.decode_tlv(data, idx)
        if tag != ber.TAG_SEQUENCE:
            raise ber.BerError("expected SEQUENCE for VarBind")
        inner = 0
        oid_tag, oid_val, inner = ber.decode_tlv(value, inner)
        if oid_tag != ber.TAG_OID:
            raise ber.BerError("expected OID in VarBind")
        oid = ber.decode_oid(oid_val)
        val_tag, val_val, inner = ber.decode_tlv(value, inner)
        return cls(oid, Value.decode(val_tag, val_val)), idx


@dataclass
class PDU:
    pdu_type: int
    request_id: int
    error_status: int = ERR_NO_ERROR
    error_index: int = 0
    variable_bindings: List[VarBind] = field(default_factory=list)

    def encode(self) -> bytes:
        body = ber.encode_integer(self.request_id)
        body += ber.encode_integer(self.error_status)
        body += ber.encode_integer(self.error_index)
        vb_body = b"".join(vb.encode() for vb in self.variable_bindings)
        body += ber.encode_sequence(vb_body)
        return ber.encode_tlv(self.pdu_type, body)

    @classmethod
    def decode(cls, data: bytes, idx: int) -> Tuple["PDU", int]:
        tag, value, idx = ber.decode_tlv(data, idx)
        inner = 0
        rid_tag, rid_val, inner = ber.decode_tlv(value, inner)
        request_id = ber.decode_integer(rid_val)
        es_tag, es_val, inner = ber.decode_tlv(value, inner)
        error_status = ber.decode_integer(es_val)
        ei_tag, ei_val, inner = ber.decode_tlv(value, inner)
        error_index = ber.decode_integer(ei_val)
        vbs_tag, vbs_val, inner = ber.decode_tlv(value, inner)
        if vbs_tag != ber.TAG_SEQUENCE:
            raise ber.BerError("expected SEQUENCE for variable-bindings")
        bindings = []
        bidx = 0
        while bidx < len(vbs_val):
            vb, bidx = VarBind.decode(vbs_val, bidx)
            bindings.append(vb)
        return cls(tag, request_id, error_status, error_index, bindings), idx

    @property
    def type_name(self) -> str:
        return PDU_NAMES.get(self.pdu_type, f"0x{self.pdu_type:02x}")


@dataclass
class SNMPMessage:
    version: int
    community: bytes
    pdu: PDU

    def encode(self) -> bytes:
        body = ber.encode_integer(self.version)
        body += ber.encode_octet_string(self.community)
        body += self.pdu.encode()
        return ber.encode_sequence(body)

    @classmethod
    def decode(cls, data: bytes) -> "SNMPMessage":
        tag, value, idx = ber.decode_tlv(data, 0)
        if tag != ber.TAG_SEQUENCE:
            raise ber.BerError("expected SEQUENCE for SNMP message")
        inner = 0
        ver_tag, ver_val, inner = ber.decode_tlv(value, inner)
        version = ber.decode_integer(ver_val)
        comm_tag, comm_val, inner = ber.decode_tlv(value, inner)
        community = bytes(comm_val)
        pdu, inner = PDU.decode(value, inner)
        return cls(version, community, pdu)
