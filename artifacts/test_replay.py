"""Replay hex_dump_1.txt / hex_dump_2.txt against a fresh DmsAgent and report
any mismatches between the captured GetResponse and the agent's response."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from artifacts.decode_hexdump import parse_streams
from ntcip_agent import ber
from ntcip_agent.config import AgentConfig
from ntcip_agent.server import DmsAgent


def split_messages(data: bytes):
    messages = []
    off = 0
    while off < len(data):
        tag, value, new_off = ber.decode_tlv(data, off)
        messages.append(data[off:new_off])
        off = new_off
    return messages


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "artifacts/hex_dump_1.txt"
    req_bytes, resp_bytes = parse_streams(path)
    requests = split_messages(req_bytes)
    responses = split_messages(resp_bytes)
    print(f"{path}: {len(requests)} requests, {len(responses)} responses")

    agent = DmsAgent(AgentConfig.default())

    mismatches = 0
    for i, (req, expected) in enumerate(zip(requests, responses)):
        actual = agent.handle_message(req)
        if actual != expected:
            mismatches += 1
            print(f"--- mismatch #{i} ---")
            print("expected:", expected.hex())
            print("actual:  ", actual.hex() if actual else None)
    print(f"{mismatches} mismatches out of {len(requests)}")


if __name__ == "__main__":
    main()
