"""A small SNMPv1 client for exercising the NTCIP 1203 DMS agent.

This is a developer/test tool, not part of the ``ntcip_agent`` package. It
implements just enough of SNMPv1 (Get/GetNext/Set over UDP or TCP) to drive
the four scenarios called for by the project: polling sign status, putting a
message on the sign, blanking the sign, and walking the font table.

Examples::

    python tools/snmp_client.py poll
    python tools/snmp_client.py put-message "[fo220]HELLO WORLD"
    python tools/snmp_client.py blank
    python tools/snmp_client.py walk-font 20
    python tools/snmp_client.py get 1.3.6.1.2.1.1.1.0
    python tools/snmp_client.py set 1.3.6.1.2.1.1.6.0 octet-string "Booth 12"
"""

from __future__ import annotations

import argparse
import itertools
import os
import socket
import sys
from typing import List, Sequence, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ntcip_agent import ber
from ntcip_agent.ber import Value
from ntcip_agent.crc import compute_message_crc
from ntcip_agent.sign_state import (
    MEM_BLANK,
    MEM_CHANGEABLE,
    MSG_MODIFY_REQ,
    MSG_VALIDATE_REQ,
)
from ntcip_agent.snmp_message import PDU, SNMPMessage, VarBind

DMS = "1.3.6.1.4.1.1206.4.2.3"

# OIDs used by the scenario subcommands
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_CONTROL_MODE = f"{DMS}.6.1.0"
OID_MESSAGE_TIME_REMAINING = f"{DMS}.6.4.0"
OID_MSG_TABLE_SOURCE = f"{DMS}.6.5.0"
OID_ACTIVATE_MESSAGE = f"{DMS}.6.3.0"
OID_ACTIVATE_MSG_ERROR = f"{DMS}.6.17.0"
OID_SHORT_ERROR_STATUS = f"{DMS}.9.7.1.0"
OID_POWER_SOURCE = f"{DMS}.9.8.6.0"
OID_TEMP_MAX_CABINET = f"{DMS}.9.9.2.0"
OID_SIGN_TYPE = f"{DMS}.1.2.0"
OID_SIGN_TECHNOLOGY = f"{DMS}.1.9.0"
OID_SIGN_HEIGHT = f"{DMS}.2.3.0"
OID_SIGN_WIDTH = f"{DMS}.2.4.0"
OID_COLOR_SCHEME = f"{DMS}.4.11.0"
OID_NUM_FONTS = f"{DMS}.3.1.0"
OID_DEFAULT_FONT = f"{DMS}.4.5.0"

MESSAGE_TABLE = f"{DMS}.5.8.1"
FONT_TABLE = f"{DMS}.3.2.1"
CHARACTER_TABLE = f"{DMS}.3.4.1"

POLL_OIDS = [
    ("sysDescr", OID_SYS_DESCR),
    ("sysUpTime", OID_SYS_UPTIME),
    ("shortErrorStatus", OID_SHORT_ERROR_STATUS),
    ("powerSource", OID_POWER_SOURCE),
    ("tempMaxCtrlCabinet", OID_TEMP_MAX_CABINET),
    ("dmsControlMode", OID_CONTROL_MODE),
    ("dmsSignType", OID_SIGN_TYPE),
    ("dmsSignTechnology", OID_SIGN_TECHNOLOGY),
    ("vmsSignHeightPixels", OID_SIGN_HEIGHT),
    ("vmsSignWidthPixels", OID_SIGN_WIDTH),
    ("dmsColorScheme", OID_COLOR_SCHEME),
    ("numFonts", OID_NUM_FONTS),
    ("defaultFont", OID_DEFAULT_FONT),
    ("dmsMessageTimeRemaining", OID_MESSAGE_TIME_REMAINING),
    ("dmsMsgTableSource", OID_MSG_TABLE_SOURCE),
    ("dmsActivateMsgError", OID_ACTIVATE_MSG_ERROR),
]


def oid_tuple(text: str) -> Tuple[int, ...]:
    return tuple(int(part) for part in text.split("."))


def oid_str(oid: Tuple[int, ...]) -> str:
    return ".".join(str(part) for part in oid)


class SnmpClient:
    """A minimal SNMPv1 Get/GetNext/Set client over UDP or TCP."""

    def __init__(
        self,
        host: str,
        port: int,
        transport: str = "udp",
        community: str = "public",
        timeout: float = 2.0,
    ):
        self.host = host
        self.port = port
        self.transport = transport
        self.community = community.encode()
        self.timeout = timeout
        self._request_ids = itertools.count(1)
        self._sock: socket.socket | None = None
        if transport == "tcp":
            self._sock = socket.create_connection((host, port), timeout=timeout)

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def __enter__(self) -> "SnmpClient":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # ------------------------------------------------------------------

    def _exchange(self, pdu: PDU) -> PDU:
        message = SNMPMessage(0, self.community, pdu)
        data = message.encode()
        if self.transport == "udp":
            reply_data = self._exchange_udp(data)
        else:
            reply_data = self._exchange_tcp(data)
        reply = SNMPMessage.decode(reply_data)
        return reply.pdu

    def _exchange_udp(self, data: bytes) -> bytes:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(data, (self.host, self.port))
            reply_data, _ = sock.recvfrom(65535)
        finally:
            sock.close()
        return reply_data

    def _exchange_tcp(self, data: bytes) -> bytes:
        assert self._sock is not None
        self._sock.sendall(data)
        prefix = self._recv_exact(2)
        first_len = prefix[1]
        if first_len < 0x80:
            length, length_bytes = first_len, b""
        else:
            length_bytes = self._recv_exact(first_len & 0x7F)
            length = int.from_bytes(length_bytes, "big")
        payload = self._recv_exact(length)
        return prefix + length_bytes + payload

    def _recv_exact(self, n: int) -> bytes:
        if n == 0:
            return b""
        assert self._sock is not None
        chunks = bytearray()
        while len(chunks) < n:
            chunk = self._sock.recv(n - len(chunks))
            if not chunk:
                raise ConnectionError("connection closed by agent")
            chunks.extend(chunk)
        return bytes(chunks)

    # ------------------------------------------------------------------

    def get(self, oids: Sequence[str]) -> List[Tuple[str, Value]]:
        bindings = [VarBind(oid_tuple(oid), Value.null()) for oid in oids]
        pdu = PDU(
            pdu_type=ber.TAG_GET_REQUEST,
            request_id=next(self._request_ids),
            variable_bindings=bindings,
        )
        reply = self._exchange(pdu)
        _raise_for_error(reply)
        return [(oid_str(vb.oid), vb.value) for vb in reply.variable_bindings]

    def get_next(self, oids: Sequence[str]) -> List[Tuple[str, Value]]:
        bindings = [VarBind(oid_tuple(oid), Value.null()) for oid in oids]
        pdu = PDU(
            pdu_type=ber.TAG_GET_NEXT_REQUEST,
            request_id=next(self._request_ids),
            variable_bindings=bindings,
        )
        reply = self._exchange(pdu)
        _raise_for_error(reply)
        return [(oid_str(vb.oid), vb.value) for vb in reply.variable_bindings]

    def set(self, bindings: Sequence[Tuple[str, Value]]) -> List[Tuple[str, Value]]:
        varbinds = [VarBind(oid_tuple(oid), value) for oid, value in bindings]
        pdu = PDU(
            pdu_type=ber.TAG_SET_REQUEST,
            request_id=next(self._request_ids),
            variable_bindings=varbinds,
        )
        reply = self._exchange(pdu)
        _raise_for_error(reply)
        return [(oid_str(vb.oid), vb.value) for vb in reply.variable_bindings]

    def walk(self, base_oid: str) -> List[Tuple[str, Value]]:
        """Walk all OIDs at or below ``base_oid`` using GetNextRequest."""
        base = oid_tuple(base_oid)
        results = []
        current = base_oid
        while True:
            ((oid, value),) = self.get_next([current])
            if oid_tuple(oid)[: len(base)] != base:
                break
            results.append((oid, value))
            current = oid
        return results


class SnmpError(RuntimeError):
    def __init__(self, error_status: int, error_index: int):
        super().__init__(
            f"agent returned error-status={error_status}, error-index={error_index}"
        )
        self.error_status = error_status
        self.error_index = error_index


def _raise_for_error(pdu: PDU) -> None:
    if pdu.error_status != 0:
        raise SnmpError(pdu.error_status, pdu.error_index)


def _format_value(value: Value) -> str:
    if value.tag == ber.TAG_OCTET_STRING:
        try:
            text = value.value.decode("ascii")
        except UnicodeDecodeError:
            text = None
        if text is not None and text.isprintable():
            return f'"{text}"'
        return value.value.hex()
    return repr(value.value)


# --------------------------------------------------------------------------
# subcommands
# --------------------------------------------------------------------------


def cmd_poll(client: SnmpClient, args: argparse.Namespace) -> None:
    results = client.get([oid for _, oid in POLL_OIDS])
    for (name, _oid), (_, value) in zip(POLL_OIDS, results):
        print(f"{name:24s} = {_format_value(value)}")


def cmd_get(client: SnmpClient, args: argparse.Namespace) -> None:
    for oid, value in client.get(args.oid):
        print(f"{oid} = {_format_value(value)}")


def cmd_get_next(client: SnmpClient, args: argparse.Namespace) -> None:
    for oid, value in client.get_next(args.oid):
        print(f"{oid} = {_format_value(value)}")


VALUE_CONSTRUCTORS = {
    "integer": lambda s: Value.integer(int(s)),
    "octet-string": lambda s: Value.octet_string(s.encode("latin-1")),
    "hex-string": lambda s: Value.octet_string(bytes.fromhex(s)),
}


def cmd_set(client: SnmpClient, args: argparse.Namespace) -> None:
    value = VALUE_CONSTRUCTORS[args.type](args.value)
    for oid, value in client.set([(args.oid, value)]):
        print(f"{oid} = {_format_value(value)}")


def cmd_walk(client: SnmpClient, args: argparse.Namespace) -> None:
    for oid, value in client.walk(args.oid):
        print(f"{oid} = {_format_value(value)}")


def cmd_walk_font(client: SnmpClient, args: argparse.Namespace) -> None:
    font_index = args.font_index
    print(f"-- fontEntry.{font_index} --")
    for col in range(1, 9):
        ((oid, value),) = client.get([f"{FONT_TABLE}.{col}.{font_index}"])
        print(f"{oid} = {_format_value(value)}")

    print(f"-- characterEntry.{font_index}.* (non-empty only) --")
    for char_number in range(1, 256):
        ((woid, width),) = client.get(
            [f"{CHARACTER_TABLE}.2.{font_index}.{char_number}"]
        )
        if width.value == 0:
            continue
        ((boid, bitmap),) = client.get(
            [f"{CHARACTER_TABLE}.3.{font_index}.{char_number}"]
        )
        print(
            f"character {char_number:3d}: width={width.value:2d} bitmap={bitmap.value.hex()}"
        )


def cmd_put_message(client: SnmpClient, args: argparse.Namespace) -> None:
    slot = args.slot
    text = args.text.encode("latin-1")
    beacon = args.beacon
    pixel_service = args.pixel_service

    status_oid = f"{MESSAGE_TABLE}.9.{MEM_CHANGEABLE}.{slot}"
    multistring_oid = f"{MESSAGE_TABLE}.3.{MEM_CHANGEABLE}.{slot}"
    beacon_oid = f"{MESSAGE_TABLE}.6.{MEM_CHANGEABLE}.{slot}"
    pixel_service_oid = f"{MESSAGE_TABLE}.7.{MEM_CHANGEABLE}.{slot}"
    owner_oid = f"{MESSAGE_TABLE}.4.{MEM_CHANGEABLE}.{slot}"
    crc_oid = f"{MESSAGE_TABLE}.5.{MEM_CHANGEABLE}.{slot}"

    print(f"Putting message into changeable slot {slot}: {text!r}")
    client.set([(status_oid, Value.integer(MSG_MODIFY_REQ))])
    client.set([(multistring_oid, Value.octet_string(text))])
    client.set([(beacon_oid, Value.integer(beacon))])
    client.set([(pixel_service_oid, Value.integer(pixel_service))])
    client.set([(owner_oid, Value.octet_string(args.owner.encode("ascii")))])
    client.set([(status_oid, Value.integer(MSG_VALIDATE_REQ))])

    ((_, status),) = client.get([status_oid])
    ((_, crc),) = client.get([crc_oid])
    print(f"dmsMessageStatus = {status.value}, dmsMessageCRC = {crc.value}")

    expected_crc = compute_message_crc(text, beacon, pixel_service)
    if crc.value != expected_crc:
        print(
            f"WARNING: locally computed CRC {expected_crc} does not match agent CRC {crc.value}"
        )

    activation_code = (
        args.duration.to_bytes(2, "big")
        + bytes([args.priority, MEM_CHANGEABLE])
        + slot.to_bytes(2, "big")
        + crc.value.to_bytes(2, "big")
        + bytes(4)
    )
    client.set([(OID_ACTIVATE_MESSAGE, Value.octet_string(activation_code))])

    ((_, error),) = client.get([OID_ACTIVATE_MSG_ERROR])
    print(f"dmsActivateMsgError = {error.value} (2 == none)")


def cmd_blank(client: SnmpClient, args: argparse.Namespace) -> None:
    activation_code = (
        args.duration.to_bytes(2, "big")
        + bytes([args.priority, MEM_BLANK])
        + (1).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + bytes(4)
    )
    client.set([(OID_ACTIVATE_MESSAGE, Value.octet_string(activation_code))])

    ((_, error),) = client.get([OID_ACTIVATE_MSG_ERROR])
    print(f"dmsActivateMsgError = {error.value} (2 == none)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--host", default="127.0.0.1", help="agent host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=161, help="agent port (default: 161)"
    )
    parser.add_argument("--transport", choices=["udp", "tcp"], default="udp")
    parser.add_argument("--community", default="public")

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("poll", help="poll a set of common DMS status objects").set_defaults(
        func=cmd_poll
    )

    p = sub.add_parser("get", help="GetRequest one or more OIDs")
    p.add_argument("oid", nargs="+")
    p.set_defaults(func=cmd_get)

    p = sub.add_parser("get-next", help="GetNextRequest one or more OIDs")
    p.add_argument("oid", nargs="+")
    p.set_defaults(func=cmd_get_next)

    p = sub.add_parser("set", help="SetRequest a single OID")
    p.add_argument("oid")
    p.add_argument("type", choices=sorted(VALUE_CONSTRUCTORS))
    p.add_argument("value")
    p.set_defaults(func=cmd_set)

    p = sub.add_parser("walk", help="GetNext-walk all OIDs under a base OID")
    p.add_argument("oid")
    p.set_defaults(func=cmd_walk)

    p = sub.add_parser(
        "walk-font", help="dump a dmsFontTable/dmsFontCharacterTable entry"
    )
    p.add_argument("font_index", type=int)
    p.set_defaults(func=cmd_walk_font)

    p = sub.add_parser(
        "put-message", help="put a MULTI-syntax message on the sign and activate it"
    )
    p.add_argument("text", help="MULTI-syntax message text")
    p.add_argument(
        "--slot", type=int, default=1, help="changeable message slot (default: 1)"
    )
    p.add_argument("--owner", default="snmp_client", help="dmsMessageOwner value")
    p.add_argument("--beacon", type=int, default=0, choices=[0, 1])
    p.add_argument("--pixel-service", type=int, default=0, choices=[0, 1])
    p.add_argument(
        "--duration",
        type=int,
        default=65535,
        help="activation duration (65535 = indefinite)",
    )
    p.add_argument("--priority", type=int, default=1)
    p.set_defaults(func=cmd_put_message)

    p = sub.add_parser("blank", help="blank the sign")
    p.add_argument("--duration", type=int, default=65535)
    p.add_argument("--priority", type=int, default=1)
    p.set_defaults(func=cmd_blank)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    with SnmpClient(args.host, args.port, args.transport, args.community) as client:
        try:
            args.func(client, args)
        except SnmpError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
