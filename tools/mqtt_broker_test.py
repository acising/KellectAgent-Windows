#!/usr/bin/env python3
r"""
Minimal MQTT 3.1.1 broker for testing the SecArgus output sink.

Pure stdlib (socket/json/hashlib), no dependencies. Implements just enough of
the protocol for the agent: CONNECT/CONNACK, SUBSCRIBE/SUBACK, PUBLISH (QoS 0/1)
and PING. For every `event_batch` it validates the envelope (including
`payload_sha256` over the raw events array) and answers with a business ACK on
`<prefix>/<endpoint_id>/acks`. `<prefix>/<id>/status` and `/metrics` messages are
printed with their key fields.

    python tools/mqtt_broker_test.py --port 1883
    # another terminal:
    kellect.exe -e all -f events.jsonl --mqtt --mqtt-config config\secargus.ini

TLS is not supported: the demo agent speaks MQTT 3.1.1 over plain TCP.

Options for negative tests:
    --no-ack            never send the business ACK (agent retries, spool grows)
    --ack-status retry  send status=retry instead of persisted
    --drop-after N      close the connection after N batches (reconnect test)
"""

import argparse
import datetime
import hashlib
import json
import socket
import struct
import sys


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


def publish(conn, topic, payload, qos=0, packet_id=0):
    body = mqtt_string(topic)
    if qos:
        body += struct.pack(">H", packet_id)
    body += payload.encode("utf-8")
    send_packet(conn, 0x30 | (qos << 1), body)


def validate_envelope(text):
    """Returns (ok, summary). Checks fields + sha256 over the raw events array."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        return False, "invalid JSON: %s" % exc

    problems = []
    if doc.get("protocol_version") != "1.0":
        problems.append("protocol_version")
    if doc.get("message_type") != "event_batch":
        problems.append("message_type")
    for key in ("endpoint_id", "batch_id"):
        if not doc.get(key):
            problems.append(key)
    events = doc.get("events")
    if not isinstance(events, list):
        return False, "events missing"

    if doc.get("event_count") != len(events):
        problems.append("event_count!=len(events)")

    # The agent appends the events array last, so the raw bytes are the suffix.
    marker = '"events":'
    index = text.find(marker)
    if index < 0:
        problems.append("events marker")
    else:
        raw = text[index + len(marker):]
        if raw.endswith("}"):
            raw = raw[:-1]
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        if doc.get("payload_sha256") != digest:
            problems.append("payload_sha256 mismatch")

    summary = "endpoint=%s seq=%s events=%d bytes=%d batch=%s" % (
        doc.get("endpoint_id"), doc.get("sequence_number"), len(events),
        len(text), doc.get("batch_id"))
    return not problems, summary + ("" if not problems else " PROBLEMS=" + ",".join(problems))


def serve(args):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(1)

    print("mock MQTT broker on %s:%d (acks=%s)" %
          (args.host, args.port, not args.no_ack))

    try:
        while True:
            conn, addr = server.accept()
            print("[+] connection from %s" % (addr,))
            try:
                handle_connection(conn, args)
            except (ConnectionError, OSError) as exc:
                print("[-] connection ended: %s" % exc)
            finally:
                conn.close()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.close()
    return 0


def handle_connection(conn, args):
    client_id = ""
    packet_id = 1
    batches = 0
    sent_command = False
    conn.settimeout(0.5)

    while True:
        try:
            first, body = read_packet(conn)
        except socket.timeout:
            continue

        packet_type = first >> 4
        if packet_type == 1:      # CONNECT
            name_len = struct.unpack(">H", body[0:2])[0]
            offset = 2 + name_len + 4     # protocol name, level, flags, keepalive
            if len(body) >= offset + 2:
                cid_len = struct.unpack(">H", body[offset:offset + 2])[0]
                client_id = body[offset + 2:offset + 2 + cid_len].decode("utf-8", "replace")
            print("[connect] client_id=%s" % client_id)
            send_packet(conn, 0x20, b"\x00\x00")     # CONNACK accepted

        elif packet_type == 8:    # SUBSCRIBE
            sub_id = struct.unpack(">H", body[0:2])[0]
            offset = 2
            granted = b""
            topics = []
            while offset + 2 <= len(body):
                topic_len = struct.unpack(">H", body[offset:offset + 2])[0]
                topic = body[offset + 2:offset + 2 + topic_len].decode("utf-8", "replace")
                offset += 2 + topic_len + 1      # + requested QoS
                granted += b"\x01"
                topics.append(topic)
                print("[subscribe] %s" % topic)
            send_packet(conn, 0x90, struct.pack(">H", sub_id) + granted)

            if args.send_command and not sent_command:
                for topic in topics:
                    if not topic.endswith("/commands"):
                        continue
                    endpoint = topic.split("/")[-2]
                    now = datetime.datetime.now(datetime.timezone.utc)
                    command = {
                        "protocol_version": "1.0",
                        "message_type": "command",
                        "command_id": "cmd-%d" % int(now.timestamp()),
                        "endpoint_id": endpoint,
                        "name": args.send_command,
                        "args": json.loads(args.command_args),
                        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00",
                        "expires_at": (now + datetime.timedelta(seconds=60)).strftime(
                            "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00",
                    }
                    print("[command] %s %s" % (args.send_command, command["command_id"]))
                    publish(conn, topic, json.dumps(command))
                    sent_command = True
                    break

        elif packet_type == 3:    # PUBLISH
            qos = (first >> 1) & 0x03
            topic_len = struct.unpack(">H", body[0:2])[0]
            topic = body[2:2 + topic_len].decode("utf-8", "replace")
            offset = 2 + topic_len
            msg_id = 0
            if qos:
                msg_id = struct.unpack(">H", body[offset:offset + 2])[0]
                offset += 2
            payload = body[offset:].decode("utf-8", "replace")

            if qos == 1:
                send_packet(conn, 0x40, struct.pack(">H", msg_id))

            if topic.endswith("/events"):
                batches += 1
                ok, summary = validate_envelope(payload)
                print("[batch %d] %s %s" % (batches, "OK " if ok else "BAD", summary))
                if not args.no_ack and ok:
                    doc = json.loads(payload)
                    endpoint = doc.get("endpoint_id", "")
                    ack = json.dumps({
                        "protocol_version": "1.0",
                        "message_type": "batch_ack",
                        "endpoint_id": endpoint,
                        "batch_id": doc["batch_id"],
                        "status": args.ack_status,
                        "stored_count": doc["event_count"],
                    })
                    ack_topic = "%s/%s/acks" % (args.prefix, endpoint)
                    publish(conn, ack_topic, ack)
                    print("[ack] %s %s" % (ack_topic, args.ack_status))
                if args.drop_after and batches >= args.drop_after:
                    raise ConnectionError("dropping after %d batches" % batches)
            else:
                kind = topic.rsplit("/", 1)[-1]
                if kind == "replies":
                    try:
                        doc = json.loads(payload)
                        result = doc.get("result") or {}
                        print("[reply] status=%s error=%s result=%s" % (
                            doc.get("status"), doc.get("error"),
                            json.dumps(result)[:300]))
                    except json.JSONDecodeError:
                        print("[reply] INVALID JSON (%d bytes)" % len(payload))
                elif kind in ("status", "metrics"):
                    try:
                        doc = json.loads(payload)
                        print("[%s] endpoint=%s state=%s degraded=%s bytes=%d" % (
                            kind, doc.get("endpoint_id"),
                            doc.get("collection", {}).get("state"),
                            doc.get("degraded"), len(payload)))
                        if kind == "metrics":
                            print("        events_per_s=%.1f spool_batches=%s" % (
                                doc.get("events_per_s", 0.0),
                                doc.get("spool", {}).get("batches")))
                    except json.JSONDecodeError:
                        print("[%s] INVALID JSON (%d bytes)" % (kind, len(payload)))
                else:
                    print("[publish] %s (%d bytes)" % (topic, len(payload)))

        elif packet_type == 12:   # PINGREQ
            send_packet(conn, 0xD0, b"")

        elif packet_type == 14:   # DISCONNECT
            print("[disconnect]")
            return

        else:
            print("[packet] type=%d len=%d" % (packet_type, len(body)))


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1883)
    parser.add_argument("--prefix", default="secargus/v1/endpoints")
    parser.add_argument("--no-ack", action="store_true")
    parser.add_argument("--ack-status", default="persisted",
                        choices=["persisted", "duplicate", "rejected", "retry"])
    parser.add_argument("--drop-after", type=int, default=0)
    parser.add_argument("--cert", help=argparse.SUPPRESS)
    parser.add_argument("--key", help=argparse.SUPPRESS)
    parser.add_argument("--ca", help=argparse.SUPPRESS)
    parser.add_argument("--send-command", default="",
                        help="send this command after the client subscribes (e.g. get_status)")
    parser.add_argument("--command-args", default="{}",
                        help="JSON object passed as the command args")
    args = parser.parse_args()

    try:
        return serve(args)
    except OSError as exc:
        print("cannot bind %s:%d: %s" % (args.host, args.port, exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
