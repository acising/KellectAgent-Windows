#!/usr/bin/env python3
r"""
Minimal MQTT 3.1.1 command sender for the Kellect SecArgus channel.

Pure stdlib (no paho dependency). Sends one command to
`<prefix>/<endpoint_id>/commands`, optionally waits for the reply on
`<prefix>/<endpoint_id>/replies` and prints it.

Examples:
    python tools\mqtt_command.py --name get_status
    python tools\mqtt_command.py --name stop_collection
    python tools\mqtt_command.py --name restart_collection
    python tools\mqtt_command.py --name update_collection_config ^
        --args "{\"event_mask\":175,\"restart\":true}"

The endpoint id is read from dist\config\endpoint.json by default.
"""

import argparse
import datetime
import json
import os
import socket
import struct
import sys
import time
import uuid


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return buf


def read_packet(conn):
    first = recv_exact(conn, 1)[0]
    remaining = 0
    multiplier = 1
    while True:
        byte = recv_exact(conn, 1)[0]
        remaining += (byte & 0x7F) * multiplier
        if not (byte & 0x80):
            break
        multiplier *= 128
    body = recv_exact(conn, remaining) if remaining else b""
    return first, body


def encode_remaining(length):
    out = bytearray()
    while True:
        byte = length % 128
        length //= 128
        if length:
            byte |= 0x80
        out.append(byte)
        if not length:
            break
    return bytes(out)


def send_packet(conn, header, body):
    conn.sendall(bytes([header]) + encode_remaining(len(body)) + body)


def mqtt_string(text):
    raw = text.encode("utf-8")
    return struct.pack(">H", len(raw)) + raw


def read_string(body, offset):
    length = struct.unpack_from(">H", body, offset)[0]
    offset += 2
    return body[offset:offset + length].decode("utf-8", "replace"), offset + length


def default_endpoint(config):
    candidates = [config, os.path.join("dist", "config", "endpoint.json"),
                  os.path.join("config", "endpoint.json")]
    for path in candidates:
        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle).get("endpoint_id", "")
    return ""


def main():
    parser = argparse.ArgumentParser(description="Send a Kellect MQTT command")
    parser.add_argument("--host", default="192.168.1.93")
    parser.add_argument("--port", type=int, default=1883)
    parser.add_argument("--prefix", default="secargus/v1/endpoints")
    parser.add_argument("--endpoint", default="",
                        help="endpoint id; default read from dist/config/endpoint.json")
    parser.add_argument("--config", default="dist/config/endpoint.json")
    parser.add_argument("--name", required=True,
                        help="get_status|get_metrics|get_capabilities|"
                             "get_collection_config|update_collection_config|"
                             "stop_collection|restart_collection|start_collection")
    parser.add_argument("--args", default="{}", help="JSON object for command args")
    parser.add_argument("--command-id", default="")
    parser.add_argument("--expires-in", type=int, default=60)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--no-wait", action="store_true")
    args = parser.parse_args()

    endpoint = args.endpoint or default_endpoint(args.config)
    if not endpoint:
        print("ERROR: endpoint id not found; pass --endpoint", file=sys.stderr)
        return 2

    try:
        command_args = json.loads(args.args)
    except json.JSONDecodeError as exc:
        print("ERROR: --args is not JSON: %s" % exc, file=sys.stderr)
        return 2

    command_id = args.command_id or "cmd-" + uuid.uuid4().hex[:12]
    now = datetime.datetime.now(datetime.timezone.utc)
    expires = now + datetime.timedelta(seconds=args.expires_in)
    payload = json.dumps({
        "protocol_version": "1.0",
        "message_type": "command",
        "endpoint_id": endpoint,
        "command_id": command_id,
        "name": args.name,
        "args": command_args,
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": expires.isoformat().replace("+00:00", "Z"),
    }).encode("utf-8")

    client_id = "kellect-cmd-" + uuid.uuid4().hex[:8]
    conn = socket.create_connection((args.host, args.port), timeout=args.timeout)

    connect = (mqtt_string("MQTT") + bytes([4, 0x02]) + struct.pack(">H", 30) +
               mqtt_string(client_id))
    send_packet(conn, 0x10, connect)
    header, _ = read_packet(conn)
    if header != 0x20:
        print("ERROR: CONNACK missing", file=sys.stderr)
        return 3

    commands_topic = "%s/%s/commands" % (args.prefix, endpoint)
    replies_topic = "%s/%s/replies" % (args.prefix, endpoint)
    if not args.no_wait:
        subscribe = struct.pack(">H", 1) + mqtt_string(replies_topic) + b"\x01"
        send_packet(conn, 0x82, subscribe)
        read_packet(conn)

    send_packet(conn, 0x32, mqtt_string(commands_topic) + struct.pack(">H", 2) + payload)
    read_packet(conn)   # PUBACK

    print("sent %s id=%s to %s" % (args.name, command_id, commands_topic))
    if args.no_wait:
        return 0

    deadline = time.time() + args.timeout
    while time.time() < deadline:
        header, body = read_packet(conn)
        packet_type = header >> 4
        if packet_type == 3:      # PUBLISH
            qos = (header >> 1) & 0x03
            topic, offset = read_string(body, 0)
            packet_id = 0
            if qos > 0:
                packet_id = struct.unpack_from(">H", body, offset)[0]
                offset += 2
            text = body[offset:].decode("utf-8", "replace")
            if qos == 1 and packet_id:
                send_packet(conn, 0x40, struct.pack(">H", packet_id))
            if topic == replies_topic:
                print(text)
                return 0
        elif packet_type == 13:   # PINGREQ
            send_packet(conn, 0xD0, b"")
    print("ERROR: no reply within %.1fs" % args.timeout, file=sys.stderr)
    return 4


if __name__ == "__main__":
    sys.exit(main())
