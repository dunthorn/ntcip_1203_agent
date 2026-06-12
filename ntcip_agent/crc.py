"""dmsMessageCRC computation (NTCIP 1203, section 5.6.8.5).

The CRC is "CRC-16 (polynomial defined in ISO/IEC 3309)" -- i.e. the
CRC-16/X-25 algorithm (poly 0x1021, reflected, init 0xFFFF, xorout 0xFFFF) --
computed over the dmsMessageMultiString bytes followed by the
dmsMessageBeacon and dmsMessagePixelService values (one byte each, 0 if not
supported). The 16-bit CRC-16/X-25 result is then byte-swapped to produce
the value reported by dmsMessageCRC / consumed by dmsActivateMessage.
"""

from __future__ import annotations

_POLY = 0x8408  # reflected form of 0x1021


def _crc16_x25(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ _POLY
            else:
                crc >>= 1
    return crc ^ 0xFFFF


def compute_message_crc(multistring: bytes, beacon: int, pixel_service: int) -> int:
    """Return the dmsMessageCRC value for the given message contents."""
    data = bytes(multistring) + bytes([beacon & 0xFF, pixel_service & 0xFF])
    crc = _crc16_x25(data)
    return ((crc & 0xFF) << 8) | (crc >> 8)
