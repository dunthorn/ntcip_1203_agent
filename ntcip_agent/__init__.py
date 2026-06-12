"""A simulated NTCIP 1203 (Dynamic Message Sign) SNMP agent.

This package implements a single-sign DMS simulator: a hand-rolled
BER/SNMPv1 codec, a registry of NTCIP 1203 + MIB-II objects, the
dmsMessageTable/dmsFontTable/dmsGraphicTable state machines, and a UDP/TCP
SNMP agent server.
"""

__version__ = "1.0.0"
