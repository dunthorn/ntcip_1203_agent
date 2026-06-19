"""Byte-exact replay of the captured SNMP sessions in artifacts/hex_dump_*.txt
against a freshly-created DmsAgent.

This is a self-contained unittest version of artifacts/test_replay.py: it
parses the wireshark-style hex dumps directly (request bytes are at column 0,
response bytes are indented), splits each byte stream into individual
BER-encoded SNMP messages, and compares the agent's reply to each request
against the captured response.
"""

import os
import re
import unittest

from ntcip_agent import ber
from ntcip_agent.config import AgentConfig
from ntcip_agent.server import DmsAgent

ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "..", "artifacts")

_LINE_RE = re.compile(r"^(\s*)([0-9A-Fa-f]{8})\s+((?:[0-9A-Fa-f]{2}\s+){1,16})")


def _parse_streams(path):
    """Return (request_bytes, response_bytes) from a wireshark-like hex dump
    where request lines start at column 0 and response lines are indented."""
    req = bytearray()
    resp = bytearray()
    with open(path, "r") as f:
        for line in f:
            m = _LINE_RE.match(line)
            if not m:
                continue
            indent, _offset, hexpart = m.groups()
            data = bytes(int(b, 16) for b in hexpart.split())
            if indent:
                resp.extend(data)
            else:
                req.extend(data)
    return bytes(req), bytes(resp)


def _split_messages(data):
    """Split a byte stream into individual BER-encoded SNMP messages."""
    messages = []
    off = 0
    while off < len(data):
        _tag, _value, new_off = ber.decode_tlv(data, off)
        messages.append(data[off:new_off])
        off = new_off
    return messages


class TestReplayHexDumps(unittest.TestCase):
    def _replay(self, filename, known_mismatch_indices=frozenset()):
        path = os.path.join(ARTIFACTS_DIR, filename)
        req_bytes, resp_bytes = _parse_streams(path)
        requests = _split_messages(req_bytes)
        responses = _split_messages(resp_bytes)
        self.assertEqual(len(requests), len(responses))

        cfg = AgentConfig.default()
        agent = DmsAgent(cfg.network, cfg.signs[0])

        for i, (req, expected) in enumerate(zip(requests, responses)):
            actual = agent.handle_message(req)
            if i in known_mismatch_indices:
                continue
            self.assertEqual(
                actual, expected, f"mismatch at message #{i} in {filename}"
            )

    def test_hex_dump_1_poll_put_message_blank(self):
        # message #52 (GET dmsMessageStatus.3.1) returns valid(4) in the
        # capture vs notUsed(1) in a fresh simulator -- the captured device
        # had a leftover message from prior testing, which is a real-device
        # state difference, not a protocol bug.
        self._replay("hex_dump_1.txt", known_mismatch_indices={52})

    def test_hex_dump_2_font_table_download(self):
        self._replay("hex_dump_2.txt")


if __name__ == "__main__":
    unittest.main()
