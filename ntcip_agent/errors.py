"""Exceptions used to signal SNMP error-status values from MIB object
getters/setters."""

from __future__ import annotations


class SetError(Exception):
    """Raised by a MibObject setter to signal an SNMPv1 error-status that
    should be reported for the whole PDU (with the appropriate
    error-index)."""

    def __init__(self, error_status: int):
        super().__init__(error_status)
        self.error_status = error_status
