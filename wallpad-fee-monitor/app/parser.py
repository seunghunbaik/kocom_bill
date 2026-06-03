import logging
import re
import struct
from dataclasses import dataclass


MAGIC = b"\x78\x56\x34\x12"
DATE_RE = re.compile(rb"20\d{2}-\d{2}-00 00:00")


def parse_hex_packets(raw: str) -> list[bytes]:
    packets = []
    for item in raw.replace("\n", ",").split(","):
        cleaned = "".join(item.split())
        if not cleaned:
            continue
        if len(cleaned) % 2:
            raise ValueError(f"Hex packet has odd length: {cleaned}")
        packets.append(bytes.fromhex(cleaned))
    return packets


@dataclass
class FeeRecord:
    month: str
    common: int | None = None
    electricity: int | None = None
    water: int | None = None
    heating: int | None = None
    etc: int | None = None
    total: int | None = None


class FeeParser:
    """Parser for the Kocom management-fee packets observed on TCP/15000.

    The wallpad response can contain one or more records. Each record includes an
    ASCII month marker like "2026-04-00 00:00", followed by little-endian 32-bit
    integers. Known layouts are inferred from captured wallpad traffic and kept
    deliberately conservative.
    """

    def __init__(self):
        self.latest: dict[str, FeeRecord] = {}

    def feed(self, payload: bytes) -> dict | None:
        records = self._parse_payload(payload)
        if not records:
            return None
        for record in records:
            self.latest[record.month] = record
        return self._flatten()

    def _parse_payload(self, payload: bytes) -> list[FeeRecord]:
        records: list[FeeRecord] = []
        starts = [m.start() for m in re.finditer(re.escape(MAGIC), payload)]
        if not starts and MAGIC in payload:
            starts = [payload.index(MAGIC)]
        for idx, start in enumerate(starts):
            end = starts[idx + 1] if idx + 1 < len(starts) else len(payload)
            chunk = payload[start:end]
            record = self._parse_record(chunk)
            if record:
                logging.debug("Parsed fee record %s from %s", record, chunk.hex())
                records.append(record)
        return records

    def _parse_record(self, chunk: bytes) -> FeeRecord | None:
        match = DATE_RE.search(chunk)
        if not match:
            return None
        month = match.group(0).decode("ascii")[:7]
        values_start = match.end() + 8
        raw_values = []
        for offset in range(values_start, min(len(chunk), values_start + 28), 4):
            if offset + 4 <= len(chunk):
                raw_values.append(struct.unpack_from("<I", chunk, offset)[0])

        values = [value for value in raw_values if 0 <= value <= 2_000_000]
        if not values:
            return FeeRecord(month=month)

        # Observed 5-value layout:
        # common, electricity, water, heating, etc
        if len(values) >= 5:
            common, electricity, water, heating, etc = values[:5]
            total = common + electricity + water + heating + etc
            return FeeRecord(
                month=month,
                common=common,
                electricity=electricity,
                water=water,
                heating=heating,
                etc=etc,
                total=total,
            )

        return FeeRecord(month=month)

    def _flatten(self) -> dict:
        # Sort descending by month string. Label newest as current, then previous.
        months = sorted(self.latest.keys(), reverse=True)
        labels = ["current", "previous", "before_previous"]
        result = {}
        for label, month in zip(labels, months):
            record = self.latest[month]
            result[f"{label}_month"] = record.month
            for field in ("common", "electricity", "water", "heating", "etc", "total"):
                value = getattr(record, field)
                if value is not None:
                    result[f"{label}_{field}"] = value
        return result
