import json
import logging
import signal
import struct
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import paramiko
from paho.mqtt import client as mqtt

from parser import FeeParser, parse_hex_packets


OPTIONS_PATH = Path("/data/options.json")


@dataclass
class Options:
    mango_host: str
    mango_port: int
    mango_user: str
    mango_password: str
    mango_interface: str
    wallpad_ip: str
    server_ip: str
    server_port: int
    mqtt_host: str
    mqtt_port: int
    mqtt_username: str
    mqtt_password: str
    mqtt_discovery_prefix: str
    mqtt_topic_prefix: str
    active_query_enabled: bool
    active_query_interval_hours: int
    active_query_startup_delay_seconds: int
    active_query_packets: str
    log_level: str


def load_options() -> Options:
    raw = json.loads(OPTIONS_PATH.read_text(encoding="utf-8"))
    return Options(**raw)


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )


def ip_to_bytes(ip: str) -> bytes:
    return bytes(int(part) for part in ip.split("."))


class PcapStream:
    def __init__(self, stream):
        self.stream = stream
        self.endian = "<"

    def read_exact(self, size: int) -> bytes:
        buf = bytearray()
        while len(buf) < size:
            chunk = self.stream.read(size - len(buf))
            if not chunk:
                raise EOFError
            buf.extend(chunk)
        return bytes(buf)

    def read_header(self) -> None:
        header = self.read_exact(24)
        magic = header[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            self.endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            self.endian = ">"
        else:
            raise ValueError(f"Unsupported pcap magic: {magic.hex()}")

    def packets(self):
        self.read_header()
        while True:
            try:
                rec = self.read_exact(16)
            except EOFError:
                return
            _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack(
                f"{self.endian}IIII", rec
            )
            yield self.read_exact(incl_len)


def tcp_payload_from_ethernet(packet: bytes, src_ip: bytes, dst_ip: bytes, port: int):
    if len(packet) < 14 or packet[12:14] != b"\x08\x00":
        return None
    ip_offset = 14
    if len(packet) < ip_offset + 20:
        return None
    ihl = (packet[ip_offset] & 0x0F) * 4
    proto = packet[ip_offset + 9]
    if proto != 6:
        return None
    if packet[ip_offset + 12 : ip_offset + 16] != src_ip:
        return None
    if packet[ip_offset + 16 : ip_offset + 20] != dst_ip:
        return None
    total_len = struct.unpack("!H", packet[ip_offset + 2 : ip_offset + 4])[0]
    tcp_offset = ip_offset + ihl
    if len(packet) < tcp_offset + 20:
        return None
    src_port, dst_port = struct.unpack("!HH", packet[tcp_offset : tcp_offset + 4])
    if src_port != port and dst_port != port:
        return None
    data_offset = ((packet[tcp_offset + 12] >> 4) & 0x0F) * 4
    payload_offset = tcp_offset + data_offset
    payload_end = ip_offset + total_len
    payload = packet[payload_offset:payload_end]
    return payload or None


class Publisher:
    def __init__(self, opts: Options):
        self.opts = opts
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        if opts.mqtt_username:
            self.client.username_pw_set(opts.mqtt_username, opts.mqtt_password)

    def connect(self):
        logging.info("Connecting to MQTT %s:%s", self.opts.mqtt_host, self.opts.mqtt_port)
        self.client.connect(self.opts.mqtt_host, self.opts.mqtt_port, 60)
        self.client.loop_start()

    def stop(self):
        self.client.loop_stop()
        self.client.disconnect()

    def publish_discovery(self, values: dict):
        for key in values:
            config_topic = (
                f"{self.opts.mqtt_discovery_prefix}/sensor/wallpad_fee_{key}/config"
            )
            state_topic = f"{self.opts.mqtt_topic_prefix}/state"
            payload = {
                "name": f"Wallpad Fee {key.replace('_', ' ').title()}",
                "unique_id": f"wallpad_fee_{key}",
                "state_topic": state_topic,
                "value_template": f"{{{{ value_json.{key} }}}}",
                "device": {
                    "identifiers": ["wallpad_fee_monitor"],
                    "name": "Wallpad Fee Monitor",
                    "manufacturer": "Kocom packet monitor",
                },
            }
            if key.endswith(("total", "common", "electricity", "water", "heating", "etc")):
                payload["unit_of_measurement"] = "KRW"
                payload["state_class"] = "measurement"
            self.client.publish(config_topic, json.dumps(payload), retain=True)

    def publish_state(self, values: dict):
        self.publish_discovery(values)
        topic = f"{self.opts.mqtt_topic_prefix}/state"
        self.client.publish(topic, json.dumps(values, ensure_ascii=False), retain=True)


def ssh_tcpdump(opts: Options):
    ssh = ssh_connect(opts)
    command = (
        f"tcpdump -i {opts.mango_interface} -nn -s0 -U -w - "
        f"'src host {opts.server_ip} and dst host {opts.wallpad_ip} and port {opts.server_port}'"
    )
    logging.info("Starting remote capture: %s", command)
    _stdin, stdout, _stderr = ssh.exec_command(command, get_pty=False)
    return ssh, stdout


def ssh_connect(opts: Options):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        opts.mango_host,
        port=opts.mango_port,
        username=opts.mango_user,
        password=opts.mango_password or None,
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
    )
    return ssh


def run_active_query_once(opts: Options, parser: FeeParser, publisher: Publisher):
    packets = parse_hex_packets(opts.active_query_packets)
    if not packets:
        logging.warning("Active query is enabled, but active_query_packets is empty")
        return

    ssh = None
    channel = None
    try:
        ssh = ssh_connect(opts)
        transport = ssh.get_transport()
        if not transport:
            raise RuntimeError("SSH transport is not available")
        channel = transport.open_channel(
            "direct-tcpip",
            (opts.server_ip, opts.server_port),
            ("127.0.0.1", 0),
        )
        channel.settimeout(3)
        logging.info("Sending %s active fee query packet(s)", len(packets))
        for packet in packets:
            channel.sendall(packet)
            time.sleep(0.2)

        received = bytearray()
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            try:
                chunk = channel.recv(4096)
            except TimeoutError:
                continue
            except Exception:
                break
            if not chunk:
                break
            received.extend(chunk)
            parsed = parser.feed(bytes(received))
            if parsed:
                logging.info("Publishing active fee data: %s", parsed)
                publisher.publish_state(parsed)
                return
        logging.warning("Active query completed without parsable fee data")
    finally:
        if channel:
            channel.close()
        if ssh:
            ssh.close()


def active_query_loop(opts: Options, parser: FeeParser, publisher: Publisher, stop_event):
    delay = max(0, opts.active_query_startup_delay_seconds)
    interval = max(1, opts.active_query_interval_hours) * 3600
    if stop_event.wait(delay):
        return
    while not stop_event.is_set():
        try:
            run_active_query_once(opts, parser, publisher)
        except Exception as exc:
            logging.exception("Active query failed: %s", exc)
        if stop_event.wait(interval):
            return


def main() -> int:
    opts = load_options()
    setup_logging(opts.log_level)
    stop_event = threading.Event()

    def handle_stop(_signum, _frame):
        stop_event.set()

    signal.signal(signal.SIGTERM, handle_stop)
    signal.signal(signal.SIGINT, handle_stop)

    publisher = Publisher(opts)
    publisher.connect()
    parser = FeeParser()
    src_ip = ip_to_bytes(opts.server_ip)
    dst_ip = ip_to_bytes(opts.wallpad_ip)
    active_thread = None
    if opts.active_query_enabled:
        active_thread = threading.Thread(
            target=active_query_loop,
            args=(opts, parser, publisher, stop_event),
            daemon=True,
        )
        active_thread.start()

    while not stop_event.is_set():
        ssh = None
        try:
            ssh, stdout = ssh_tcpdump(opts)
            stream = PcapStream(stdout)
            for packet in stream.packets():
                if stop_event.is_set():
                    break
                payload = tcp_payload_from_ethernet(packet, src_ip, dst_ip, opts.server_port)
                if not payload:
                    continue
                parsed = parser.feed(payload)
                if parsed:
                    logging.info("Publishing fee data: %s", parsed)
                    publisher.publish_state(parsed)
        except Exception as exc:
            logging.exception("Capture loop failed: %s", exc)
            time.sleep(10)
        finally:
            if ssh:
                ssh.close()

    if active_thread:
        active_thread.join(timeout=5)
    publisher.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
