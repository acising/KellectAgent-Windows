#!/usr/bin/env python3
r"""
Demo business-ACK responder for a real broker (EMQX etc.).

The agent only deletes a spooled batch after the backend acknowledges it
(`persisted`/`duplicate`). Without a SecArgus backend you can run this to make
an EMQX demo work end to end:

    python tools\mqtt_ack_responder.py --host 192.168.1.93 --port 1883

It subscribes to `secargus/v1/endpoints/+/events`, prints each batch and
publishes `{"status":"persisted", ...}` to `.../<endpoint_id>/acks`.

Plain MQTT 3.1.1 over TCP, pure stdlib.
"""

import argparse
import datetime
import json
import select
import socket
import struct
import sys
import time

PREFIX = "secargus/v1/endpoints"


def enc_str(text):
    raw = text.encode("utf-8")
    return struct.pack(">H", len(raw)) + raw


def enc_varint(value):
    out = bytearray()
    while True:
        byte = value % 128
        value //= 128
        if value:
            byte |= 0x80
        out.append(byte)
        if not value:
            return bytes(out)


def send_packet(sock, header, body):
    sock.sendall(bytes([header]) + enc_varint(len(body)) + body)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("broker closed the connection")
        buf += chunk
    return buf


def read_packet(sock, timeout):
    """Returns (header, body) or None on timeout."""
    readable, _, _ = select.select([sock], [], [], timeout)
    if not readable:
        return None

    first = recv_exact(sock, 1)[0]
    remaining = 0
    multiplier = 1
    while True:
        byte = recv_exact(sock, 1)[0]
        remaining += (byte & 0x7F) * multiplier
        if not (byte & 0x80):
            break
        multiplier *= 128
    body = recv_exact(sock, remaining) if remaining else b""
    return first, body


class Client:
    def __init__(self, host, port, username, password, client_id):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client_id = client_id
        self.sock = None
        self.packet_id = 0
        self.last_send = 0.0

    def next_packet_id(self):
        self.packet_id = (self.packet_id % 65535) + 1
        return self.packet_id

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=10)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        flags = 0x02  # clean session
        if self.username:
            flags |= 0x80
        if self.password:
            flags |= 0x40

        body = enc_str("MQTT") + bytes([4, flags]) + struct.pack(">H", 30)
        body += enc_str(self.client_id)
        if self.username:
            body += enc_str(self.username)
        if self.password:
            body += enc_str(self.password)
        send_packet(self.sock, 0x10, body)

        header, ack = read_packet(self.sock, 10)
        if header is None or (header >> 4) != 2 or len(ack) < 2:
            raise ConnectionError("no CONNACK")
        code = ack[1]
        if code != 0:
            raise ConnectionError("CONNACK refused, code %d" % code)
        self.last_send = time.time()

    def subscribe(self, topic_filter):
        body = struct.pack(">H", self.next_packet_id()) + enc_str(topic_filter) + b"\x01"
        send_packet(self.sock, 0x82, body)
        self.last_send = time.time()

    def publish(self, topic, payload, qos=1):
        pid = self.next_packet_id()
        body = enc_str(topic)
        if qos:
            body += struct.pack(">H", pid)
        body += payload.encode("utf-8")
        send_packet(self.sock, 0x30 | (qos << 1), body)
        self.last_send = time.time()

    def keepalive(self):
        if time.time() - self.last_send >= 15:
            send_packet(self.sock, 0xC0, b"")
            self.last_send = time.time()

    def close(self):
        if self.sock:
            try:
                send_packet(self.sock, 0xE0, b"")
            except OSError:
                pass
            self.sock.close()
            self.sock = None


def ack_payload(batch, status):
    endpoint = batch.get("endpoint_id", "")
    now = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00"
    return json.dumps({
        "protocol_version": "1.0",
        "message_type": "batch_ack",
        "endpoint_id": endpoint,
        "batch_id": batch.get("batch_id", ""),
        "status": status,
        "stored_count": batch.get("event_count", 0),
        "stored_at": now,
        "reason": None,
    })


def run(args):
    client = Client(args.host, args.port, args.username, args.password,
                    args.client_id)
    client.connect()
    client.subscribe(args.prefix + "/+/events")
    print("connected to %s:%d, waiting for event batches on %s/+/events" %
          (args.host, args.port, args.prefix))

    while True:
        client.keepalive()
        packet = read_packet(client.sock, 1.0)
        if packet is None:
            continue

        header, body = packet
        kind = header >> 4
        flags = header & 0x0F

        if kind == 3:  # PUBLISH
            topic_len = struct.unpack(">H", body[0:2])[0]
            topic = body[2:2 + topic_len].decode("utf-8", "replace")
            offset = 2 + topic_len
            qos = (flags >> 1) & 0x03
            pid = 0
            if qos:
                pid = struct.unpack(">H", body[offset:offset + 2])[0]
                offset += 2
            payload = body[offset:].decode("utf-8", "replace")

            if qos == 1:
                send_packet(client.sock, 0x40, struct.pack(">H", pid))

            try:
                batch = json.loads(payload)
            except json.JSONDecodeError:
                print("[-] non-JSON publish on %s" % topic)
                continue

            if batch.get("message_type") != "event_batch":
                continue

            endpoint = batch.get("endpoint_id", "")
            print("[batch] %s batch=%s events=%s" % (
                endpoint, batch.get("batch_id"), batch.get("event_count")))
            client.publish(
                "%s/%s/acks" % (args.prefix, endpoint),
                ack_payload(batch, args.status))
            print("[ack]   %s -> %s" % (batch.get("batch_id"), args.status))

        elif kind == 12:  # PINGREQ from broker (unlikely) -> PINGRESP
            send_packet(client.sock, 0xD0, b"")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=1883)
    parser.add_argument("--username", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--prefix", default=PREFIX)
    parser.add_argument("--client-id", default="kellect-demo-ack")
    parser.add_argument("--status", default="persisted",
                        choices=["persisted", "duplicate", "rejected"])
    args = parser.parse_args()

    while True:
        try:
            run(args)
        except (ConnectionError, OSError, KeyboardInterrupt) as exc:
            if isinstance(exc, KeyboardInterrupt):
                return 0
            print("[-] connection lost (%s), retrying in 2s" % exc)
            time.sleep(2)


if __name__ == "__main__":
    sys.exit(main())
