import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "wallpad-fee-monitor" / "app"))

from parser import FeeParser, parse_hex_packets


class FeeParserTest(unittest.TestCase):
    def test_parse_hex_packets_accepts_commas_and_newlines(self):
        packets = parse_hex_packets("7856, 3412\n0001")

        self.assertEqual(packets, [bytes.fromhex("7856"), bytes.fromhex("3412"), bytes.fromhex("0001")])

    def test_parse_multiple_fee_records(self):
        payload = bytes.fromhex(
            "7856341238000002340000000000000021150000b00d000000000000"
            "323032362d30332d30302030303a3030"
            "0000000000000000d4780300006d01000a23000054560000d25a0000"
            "7856341238000002340000000000000021150000b00d000000000000"
            "323032362d30322d30302030303a3030"
            "0000000000000000666e0300f01301004a1a0000ec3f01008c3c0000"
        )

        parsed = FeeParser().feed(payload)

        self.assertEqual(parsed["current_month"], "2026-03")
        self.assertEqual(parsed["current_common"], 227540)
        self.assertEqual(parsed["current_water"], 8970)
        self.assertEqual(parsed["current_heating"], 22100)
        self.assertEqual(parsed["current_etc"], 23250)
        self.assertEqual(parsed["previous_month"], "2026-02")
        self.assertEqual(parsed["previous_common"], 224870)
        self.assertEqual(parsed["previous_electricity"], 70640)
        self.assertEqual(parsed["previous_total"], 399640)

    def test_parse_current_fee_record_with_zero_heating(self):
        payload = bytes.fromhex(
            "7856341238000002340000000000000021150000b00d000000000000"
            "323032362d30342d30302030303a3030"
            "00000000000000003c70030096d70000a01e000000000000785a0000"
        )

        parsed = FeeParser().feed(payload)

        self.assertEqual(parsed["current_month"], "2026-04")
        self.assertEqual(parsed["current_common"], 225340)
        self.assertEqual(parsed["current_electricity"], 55190)
        self.assertEqual(parsed["current_water"], 7840)
        self.assertEqual(parsed["current_heating"], 0)
        self.assertEqual(parsed["current_etc"], 23160)
        self.assertEqual(parsed["current_total"], 311530)


if __name__ == "__main__":
    unittest.main()
