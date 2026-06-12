"""Command-line entrypoint for the NTCIP 1203 DMS agent.

Usage::

    python -m ntcip_agent [--config CONFIG] [--verbose]
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

from .config import AgentConfig
from .server import create_server


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ntcip_agent",
        description="Simulate a single NTCIP 1203 Dynamic Message Sign over SNMP.",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="path to a JSON configuration file (see config.example.json). "
        "If omitted, built-in defaults are used.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable debug logging",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.config:
        if not os.path.exists(args.config):
            print(f"config file not found: {args.config}", file=sys.stderr)
            return 1
        config = AgentConfig.load(args.config)
    else:
        config = AgentConfig.default()

    server = create_server(config)
    host, port = server.server_address
    logging.getLogger(__name__).info(
        "NTCIP 1203 DMS agent listening on %s:%s/%s (read community=%r, write community=%r)",
        host,
        port,
        config.network.transport,
        config.network.read_community,
        config.network.write_community,
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
