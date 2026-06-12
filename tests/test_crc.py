"""dmsMessageCRC algorithm verification against a captured value."""

import unittest

from ntcip_agent.crc import compute_message_crc


class TestMessageCrc(unittest.TestCase):
    def test_captured_value(self):
        multistring = b"[pt30o0][pb][cf][jp3][jl3][fo220,B62F]TEST"
        self.assertEqual(
            compute_message_crc(multistring, beacon=0, pixel_service=0), 7439
        )

    def test_beacon_and_pixel_service_affect_crc(self):
        multistring = b"HELLO"
        base = compute_message_crc(multistring, beacon=0, pixel_service=0)
        self.assertNotEqual(
            base, compute_message_crc(multistring, beacon=1, pixel_service=0)
        )
        self.assertNotEqual(
            base, compute_message_crc(multistring, beacon=0, pixel_service=1)
        )


if __name__ == "__main__":
    unittest.main()
