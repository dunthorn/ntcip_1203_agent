"""Command-line entrypoint for the NTCIP 1203 DMS agent.

Usage::

    python -m ntcip_agent [--config CONFIG] [--verbose]
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import threading

from .config import AgentConfig
from .server import create_server
from .web_ui import create_web_app


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ntcip_agent",
        description="Simulate one or more NTCIP 1203 Dynamic Message Signs over SNMP.",
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
    log = logging.getLogger(__name__)

    if args.config:
        if not os.path.exists(args.config):
            print(f"config file not found: {args.config}", file=sys.stderr)
            return 1
        config = AgentConfig.load(args.config)
    else:
        config = AgentConfig.default()

    if not config.signs:
        print("config must define at least one sign", file=sys.stderr)
        return 1

    servers = []
    agents = []
    for sign in config.signs:
        server = create_server(config.network, sign)
        host, port = server.server_address
        label = sign.name or f"Sign :{port}"
        log.info(
            "NTCIP 1203 DMS agent '%s' listening on %s:%s/%s "
            "(read community=%r, write community=%r)",
            label,
            host,
            port,
            config.network.transport,
            config.network.read_community,
            config.network.write_community,
        )
        t = threading.Thread(target=server.serve_forever, daemon=True, name=f"snmp-{port}")
        t.start()
        servers.append(server)
        agents.append(server.agent)  # type: ignore[attr-defined]

    app = create_web_app(config, agents)
    log.info(
        "Web UI available at http://localhost:%d/",
        config.network.web_port,
    )

    try:
        app.run(
            host=config.network.host,
            port=config.network.web_port,
            use_reloader=False,
            threaded=True,
        )
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
