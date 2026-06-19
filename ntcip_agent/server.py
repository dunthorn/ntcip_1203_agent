"""The SNMP agent server.

Implements an SNMPv1 agent over UDP or TCP that answers GetRequest,
GetNextRequest, and SetRequest PDUs against a
:class:`ntcip_agent.mib_tree.MibRegistry`.

SetRequest semantics: per the captured protocol traces this agent's
behavior is modeled on, a successful SetRequest's GetResponse echoes back
the *requested* variable-binding values verbatim -- not the (possibly
different) value that ends up stored after the set is processed. For
example, writing dmsMessageStatus = modifyReq(6) is echoed back as 6 even
though the stored status becomes modifying(2).
"""

from __future__ import annotations

import logging
import socketserver
from typing import Optional, Tuple

from . import ber
from .ber import BerError, Value
from .config import NetworkConfig, SignConfig
from .errors import SetError
from .mib_tree import MibRegistry, build_registry
from .sign_state import SignState
from .snmp_message import (
    ERR_BAD_VALUE,
    ERR_GEN_ERR,
    ERR_NO_ERROR,
    ERR_NO_SUCH_NAME,
    ERR_READ_ONLY,
    PDU,
    SNMPMessage,
    VarBind,
)

logger = logging.getLogger(__name__)


class DmsAgent:
    """Holds the simulated sign state/registry and answers SNMP PDUs."""

    def __init__(self, network: NetworkConfig, sign: SignConfig):
        self.network = network
        self.sign = sign
        self.state = SignState(sign)
        self.registry: MibRegistry = build_registry(self.state)

    def handle_message(self, data: bytes) -> Optional[bytes]:
        try:
            message = SNMPMessage.decode(data)
        except (BerError, ValueError, IndexError) as exc:
            logger.warning("failed to decode SNMP message: %s", exc)
            return None

        pdu = message.pdu

        if pdu.pdu_type == ber.TAG_GET_REQUEST:
            response = self._handle_get(pdu, next_request=False)
            community_ok = (
                message.community == self.network.read_community.encode()
            )
        elif pdu.pdu_type == ber.TAG_GET_NEXT_REQUEST:
            response = self._handle_get(pdu, next_request=True)
            community_ok = (
                message.community == self.network.read_community.encode()
            )
        elif pdu.pdu_type == ber.TAG_SET_REQUEST:
            response = self._handle_set(pdu)
            community_ok = (
                message.community == self.network.write_community.encode()
            )
        else:
            logger.debug("ignoring unsupported PDU type 0x%02x", pdu.pdu_type)
            return None

        if not community_ok:
            response = PDU(
                pdu_type=ber.TAG_GET_RESPONSE,
                request_id=pdu.request_id,
                error_status=ERR_GEN_ERR,
                error_index=0,
                variable_bindings=pdu.variable_bindings,
            )

        reply = SNMPMessage(message.version, message.community, response)
        return reply.encode()

    # ------------------------------------------------------------------
    # GetRequest / GetNextRequest
    # ------------------------------------------------------------------

    def _handle_get(self, pdu: PDU, next_request: bool) -> PDU:
        bindings = []
        error_status = ERR_NO_ERROR
        error_index = 0

        for index, vb in enumerate(pdu.variable_bindings, start=1):
            obj = (
                self.registry.next(vb.oid)
                if next_request
                else self.registry.get(vb.oid)
            )
            if obj is None:
                if error_status == ERR_NO_ERROR:
                    error_status = ERR_NO_SUCH_NAME
                    error_index = index
                bindings.append(VarBind(vb.oid, Value.null()))
                continue
            bindings.append(VarBind(obj.oid, obj.getter()))

        if error_status != ERR_NO_ERROR:
            bindings = [VarBind(vb.oid, Value.null()) for vb in pdu.variable_bindings]

        return PDU(
            pdu_type=ber.TAG_GET_RESPONSE,
            request_id=pdu.request_id,
            error_status=error_status,
            error_index=error_index,
            variable_bindings=bindings,
        )

    # ------------------------------------------------------------------
    # SetRequest
    # ------------------------------------------------------------------

    def _handle_set(self, pdu: PDU) -> PDU:
        error_status = ERR_NO_ERROR
        error_index = 0

        for index, vb in enumerate(pdu.variable_bindings, start=1):
            obj = self.registry.get(vb.oid)
            if obj is None:
                error_status = ERR_NO_SUCH_NAME
                error_index = index
                break
            if not obj.writable:
                error_status = ERR_READ_ONLY
                error_index = index
                break
            try:
                obj.setter(vb.value)
            except SetError as exc:
                error_status = exc.error_status
                error_index = index
                break
            except (ValueError, TypeError):
                error_status = ERR_BAD_VALUE
                error_index = index
                break

        # Per the captured protocol traces, a SetRequest's GetResponse
        # echoes back the requested values verbatim, regardless of whether
        # the set succeeded or what the resulting stored state is.
        bindings = [VarBind(vb.oid, vb.value) for vb in pdu.variable_bindings]

        return PDU(
            pdu_type=ber.TAG_GET_RESPONSE,
            request_id=pdu.request_id,
            error_status=error_status,
            error_index=error_index,
            variable_bindings=bindings,
        )


# --------------------------------------------------------------------------
# socketserver wiring
# --------------------------------------------------------------------------


class _UdpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        agent: DmsAgent = self.server.agent  # type: ignore[attr-defined]
        reply = agent.handle_message(data)
        if reply is not None:
            sock.sendto(reply, self.client_address)


class _TcpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        agent: DmsAgent = self.server.agent  # type: ignore[attr-defined]
        while True:
            prefix = self._recv_exact(2)  # outer SEQUENCE tag + first length byte
            if prefix is None:
                return
            first_len = prefix[1]
            if first_len < 0x80:
                length, length_bytes = first_len, b""
            else:
                length_bytes = self._recv_exact(first_len & 0x7F)
                if length_bytes is None:
                    return
                length = int.from_bytes(length_bytes, "big")
            payload = self._recv_exact(length)
            if payload is None:
                return
            data = prefix + length_bytes + payload
            reply = agent.handle_message(data)
            if reply is not None:
                self.request.sendall(reply)

    def _recv_exact(self, n: int) -> Optional[bytes]:
        if n == 0:
            return b""
        chunks = bytearray()
        while len(chunks) < n:
            chunk = self.request.recv(n - len(chunks))
            if not chunk:
                return None
            chunks.extend(chunk)
        return bytes(chunks)


class UdpServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True

    def __init__(self, address: Tuple[str, int], agent: DmsAgent):
        self.agent = agent
        super().__init__(address, _UdpHandler)


class TcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, address: Tuple[str, int], agent: DmsAgent):
        self.agent = agent
        super().__init__(address, _TcpHandler)


def create_server(network: NetworkConfig, sign: SignConfig) -> socketserver.BaseServer:
    agent = DmsAgent(network, sign)
    address = (network.host, sign.port)
    if network.transport == "tcp":
        return TcpServer(address, agent)
    return UdpServer(address, agent)
