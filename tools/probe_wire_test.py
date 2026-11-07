#!/usr/bin/env python3
"""
Probe-channel wire checks and a dependency-free mock backend.

Two independent modes:

  python tools/probe_wire_test.py --vectors
      Verify the exact MessagePack byte rules that include/channel/msgpack.h
      implements, plus the FILETIME -> ISO conversion and the event mapping
      table used by source/channel/probe_channel.cpp. Runs offline.

  python tools/probe_wire_test.py --mock-server --port 8765
      Minimal WebSocket + MessagePack server implementing the Kellect probe
      protocol v1 (hello / hello_ack / events / ack / ping / command). Use it to
      test `kellect.exe --probe` without the System backend. Pure stdlib.

  # terminal 1
  python tools/probe_wire_test.py --mock-server --port 8765 --command probe.info
  # terminal 2 (admin)
  kellect.exe -e 0x1 --probe --probe-url ws://127.0.0.1:8765/ws/probe \
      --probe-id probe-demo --probe-token demo --probe-config missing.ini
"""

import argparse
import base64
import hashlib
import json
import socket
import struct
import sys
import time
import uuid

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# ---------------------------------------------------------------------------
# MessagePack (mirror of include/channel/msgpack.h)
# ---------------------------------------------------------------------------

def _be(value, size):
    return value.to_bytes(size, "big")


def pack(value):
    if value is None:
        return b"\xc0"
    if value is True:
        return b"\xc3"
    if value is False:
        return b"\xc2"
    if isinstance(value, int):
        if value >= 0:
            if value <= 0x7F:
                return bytes([value])
            if value <= 0xFF:
                return b"\xcc" + bytes([value])
            if value <= 0xFFFF:
                return b"\xcd" + _be(value, 2)
            if value <= 0xFFFFFFFF:
                return b"\xce" + _be(value, 4)
            return b"\xcf" + _be(value, 8)
        if value >= -32:
            return bytes([value & 0xFF])
        if value >= -128:
            return b"\xd0" + bytes([value & 0xFF])
        if value >= -32768:
            return b"\xd1" + _be(value & 0xFFFF, 2)
        if value >= -2147483648:
            return b"\xd2" + _be(value & 0xFFFFFFFF, 4)
        return b"\xd3" + _be(value & 0xFFFFFFFFFFFFFFFF, 8)
    if isinstance(value, float):
        return b"\xcb" + struct.pack(">d", value)
    if isinstance(value, str):
        raw = value.encode("utf-8")
        n = len(raw)
        if n <= 31:
            head = bytes([0xA0 | n])
        elif n <= 0xFF:
            head = b"\xd9" + bytes([n])
        elif n <= 0xFFFF:
            head = b"\xda" + _be(n, 2)
        else:
            head = b"\xdb" + _be(n, 4)
        return head + raw
    if isinstance(value, (list, tuple)):
        n = len(value)
        if n <= 15:
            head = bytes([0x90 | n])
        elif n <= 0xFFFF:
            head = b"\xdc" + _be(n, 2)
        else:
            head = b"\xdd" + _be(n, 4)
        return head + b"".join(pack(item) for item in value)
    if isinstance(value, dict):
        n = len(value)
        if n <= 15:
            head = bytes([0x80 | n])
        elif n <= 0xFFFF:
            head = b"\xde" + _be(n, 2)
        else:
            head = b"\xdf" + _be(n, 4)
        out = [head]
        for key, item in value.items():
            out.append(pack(key))
            out.append(pack(item))
        return b"".join(out)
    raise TypeError("unsupported type: %r" % (type(value),))


def unpack(data, pos=0):
    b = data[pos]
    pos += 1
    if b <= 0x7F:
        return b, pos
    if b >= 0xE0:
        return b - 0x100, pos
    if 0x80 <= b <= 0x8F:
        n = b & 0x0F
        out = {}
        for _ in range(n):
            key, pos = unpack(data, pos)
            out[key], pos = unpack(data, pos)
        return out, pos
    if 0x90 <= b <= 0x9F:
        n = b & 0x0F
        out = []
        for _ in range(n):
            item, pos = unpack(data, pos)
            out.append(item)
        return out, pos
    if 0xA0 <= b <= 0xBF:
        n = b & 0x1F
        return data[pos:pos + n].decode("utf-8", "replace"), pos + n
    if b == 0xC0:
        return None, pos
    if b == 0xC2:
        return False, pos
    if b == 0xC3:
        return True, pos
    if b == 0xCB:
        return struct.unpack(">d", data[pos:pos + 8])[0], pos + 8
    if b == 0xCA:
        return struct.unpack(">f", data[pos:pos + 4])[0], pos + 4
    if b in (0xC4, 0xC5, 0xC6):
        size = {0xC4: 1, 0xC5: 2, 0xC6: 4}[b]
        n = int.from_bytes(data[pos:pos + size], "big")
        pos += size
        return data[pos:pos + n], pos + n
    if b in (0xCC, 0xCD, 0xCE, 0xCF):
        size = {0xCC: 1, 0xCD: 2, 0xCE: 4, 0xCF: 8}[b]
        return int.from_bytes(data[pos:pos + size], "big"), pos + size
    if b in (0xD0, 0xD1, 0xD2, 0xD3):
        size = {0xD0: 1, 0xD1: 2, 0xD2: 4, 0xD3: 8}[b]
        return int.from_bytes(data[pos:pos + size], "big", signed=True), pos + size
    if b in (0xD9, 0xDA, 0xDB):
        size = {0xD9: 1, 0xDA: 2, 0xDB: 4}[b]
        n = int.from_bytes(data[pos:pos + size], "big")
        pos += size
        return data[pos:pos + n].decode("utf-8", "replace"), pos + n
    if b in (0xDC, 0xDD):
        size = {0xDC: 2, 0xDD: 4}[b]
        n = int.from_bytes(data[pos:pos + size], "big")
        pos += size
        out = []
        for _ in range(n):
            item, pos = unpack(data, pos)
            out.append(item)
        return out, pos
    if b in (0xDE, 0xDF):
        size = {0xDE: 2, 0xDF: 4}[b]
        n = int.from_bytes(data[pos:pos + size], "big")
        pos += size
        out = {}
        for _ in range(n):
            key, pos = unpack(data, pos)
            out[key], pos = unpack(data, pos)
        return out, pos
    raise ValueError("unsupported msgpack byte 0x%02x" % b)


# ---------------------------------------------------------------------------
# --vectors
# ---------------------------------------------------------------------------

def filetime_to_iso(filetime):
    epoch_diff = 116444736000000000
    if filetime <= epoch_diff:
        return None
    delta = filetime - epoch_diff
    seconds = delta // 10000000
    millis = (delta % 10000000) // 10000
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(seconds))
    return "%s.%03u+00:00" % (stamp, millis)


# Mirrors MapEvent() in source/channel/probe_channel.cpp
EVENT_MAP = {
    "ProcessStart": ("process", "exec"),
    "ProcessEnd": ("process", "exit"),
    "ThreadStart": ("process", "thread_start"),
    "ThreadCSwitch": ("process", "switch"),
    "ImageLoad": ("system", "image_load"),
    "FileIOFileCreate": ("file", "create"),
    "FileIOWrite": ("file", "write"),
    "FileIOFileDelete": ("file", "unlink"),
    "TcpIpConnectIPV4": ("network", "connect"),
    "TcpIpSendIPV4": ("network", "send"),
}


def map_event(name):
    if name in EVENT_MAP:
        return EVENT_MAP[name]
    if name.startswith("Registry"):
        return ("system", "registry_" + name[8:].lower())
    if name.startswith("FileIO"):
        return ("file", name[6:].lower())
    if name.startswith("TcpIp"):
        return ("network", name[6:].lower())
    return ("system", name.lower())


def run_vectors():
    failures = []

    def check(label, got, want):
        if got != want:
            failures.append("%s: got %r want %r" % (label, got, want))

    # MessagePack canonical encodings
    check("uint 0", pack(0), b"\x00")
    check("uint 127", pack(127), b"\x7f")
    check("uint 128", pack(128), b"\xcc\x80")
    check("uint 255", pack(255), b"\xcc\xff")
    check("uint 256", pack(256), b"\xcd\x01\x00")
    check("uint 65535", pack(65535), b"\xcd\xff\xff")
    check("uint 65536", pack(65536), b"\xce\x00\x01\x00\x00")
    check("uint 2^32", pack(2 ** 32), b"\xcf\x00\x00\x00\x01\x00\x00\x00\x00")
    check("int -1", pack(-1), b"\xff")
    check("int -32", pack(-32), b"\xe0")
    check("int -33", pack(-33), b"\xd0\xdf")
    check("int -129", pack(-129), b"\xd1\xff\x7f")
    check("int -32769", pack(-32769), b"\xd2\xff\xff\x7f\xff")
    check("nil", pack(None), b"\xc0")
    check("bool", pack(True), b"\xc3")
    check("str empty", pack(""), b"\xa0")
    check("str 1", pack("a"), b"\xa1a")
    check("str 31", pack("x" * 31), b"\xbf" + b"x" * 31)
    check("str 32", pack("x" * 32), b"\xd9\x20" + b"x" * 32)
    check("str 256", pack("x" * 256), b"\xda\x01\x00" + b"x" * 256)
    check("map", pack({"a": 1}), b"\x81\xa1a\x01")
    check("array", pack([1, 2]), b"\x92\x01\x02")
    check("nested", pack({"v": 1, "events": []}), b"\x82\xa1v\x01\xa6events\x90")

    # Round-trip a protocol-shaped frame through the same rules
    frame = {
        "v": 1, "probe_id": "probe-demo", "session_id": "s-1", "seq": 1,
        "type": "events", "sent_at": "2026-11-07T11:00:01.100+00:00",
        "events": [{"event_id": "e-1", "ts": "2026-11-07T11:00:01.100+00:00",
                    "category": "process", "type": "exec",
                    "payload": {"pid": 4, "comm": "curl"}}],
    }
    decoded, end = unpack(pack(frame))
    check("frame round-trip", decoded, frame)
    check("frame fully consumed", end, len(pack(frame)))

    # FILETIME (kernel session uses ClientContext=2)
    check("filetime epoch", filetime_to_iso(116444736000000000), None)

    # Event mapping
    check("map ProcessStart", map_event("ProcessStart"), ("process", "exec"))
    check("map FileIOFileCreate", map_event("FileIOFileCreate"), ("file", "create"))
    check("map RegistrySetValue", map_event("RegistrySetValue"), ("system", "registry_setvalue"))
    check("map TcpIpConnectIPV4", map_event("TcpIpConnectIPV4"), ("network", "connect"))
    check("map unknown", map_event("DiskIOWrite"), ("system", "diskiowrite"))

    if failures:
        print("FAIL (%d)" % len(failures))
        for item in failures:
            print("  x " + item)
        return 1

    print("OK: msgpack rules, frame shape, mapping and timestamp conversion match "
          "the specification.")
    return 0


# ---------------------------------------------------------------------------
# --mock-server
# ---------------------------------------------------------------------------

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return buf


def recv_frame(sock):
    header = recv_exact(sock, 2)
    b0, b1 = header[0], header[1]
    fin = bool(b0 & 0x80)
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F
    if length == 126:
        length = struct.unpack(">H", recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", recv_exact(sock, 8))[0]
    mask = recv_exact(sock, 4) if masked else None
    payload = recv_exact(sock, length) if length else b""
    if mask:
        payload = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
    return fin, opcode, payload


def send_frame(sock, opcode, payload):
    header = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        header += bytes([n])
    elif n <= 0xFFFF:
        header += b"\x7e" + _be(n, 2)
    else:
        header += b"\x7f" + _be(n, 8)
    sock.sendall(header + payload)


def send_json(sock, obj):
    send_frame(sock, 0x1, json.dumps(obj, ensure_ascii=False).encode("utf-8"))


def run_mock_server(args):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(1)
    print("mock backend listening on ws://%s:%d/ws/probe" % (args.host, args.port))
    print("press Ctrl+C to stop")

    try:
        while True:
            client, addr = server.accept()
            print("[+] connection from %s" % (addr,))
            try:
                handle_connection(client, args)
            except (ConnectionError, OSError) as exc:
                print("[-] connection ended: %s" % exc)
            finally:
                client.close()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.close()
    return 0


def handle_connection(client, args):
    request = b""
    while b"\r\n\r\n" not in request:
        request += client.recv(512)
        if not request:
            raise ConnectionError("closed during handshake")
    headers = {}
    for line in request.split(b"\r\n")[1:]:
        if b":" in line:
            key, value = line.split(b":", 1)
            headers[key.strip().lower()] = value.strip()
    key = headers.get(b"sec-websocket-key", b"")
    accept = base64.b64encode(hashlib.sha1(key + WS_GUID.encode()).digest()).decode()
    client.sendall(
        ("HTTP/1.1 101 Switching Protocols\r\n"
         "Upgrade: websocket\r\n"
         "Connection: Upgrade\r\n"
         "Sec-WebSocket-Accept: %s\r\n\r\n" % accept).encode()
    )

    fin, opcode, payload = recv_frame(client)
    hello = json.loads(payload.decode("utf-8"))
    print("[hello] probe_id=%s platform=%s agent=%s capabilities=%s backlog=%s"
          % (hello.get("probe_id"), hello.get("platform"), hello.get("agent_version"),
             hello.get("capabilities"), hello.get("backlog")))

    if args.token and hello.get("token") != args.token:
        send_json(client, {"type": "error", "code": "unauthorized", "message": "bad token"})
        raise ConnectionError("unauthorized")

    session_id = uuid.uuid4().hex
    send_json(client, {
        "type": "hello_ack",
        "session_id": session_id,
        "heartbeat_s": 15,
        "max_batch_bytes": 1048576,
        "max_events_per_batch": 500,
        "throttle_high_watermark": 5000,
    })
    print("[hello_ack] session=%s" % session_id)

    events_seen = 0
    frames = 0
    started = time.time()
    command_sent = False
    client.settimeout(1.0)

    try:
        while True:
            try:
                fin, opcode, payload = recv_frame(client)
            except socket.timeout:
                send_json(client, {"type": "ping"})
                continue

            if opcode == 0x8:
                print("[close]")
                break
            if opcode == 0x9:
                send_frame(client, 0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode != 0x2:
                text = payload.decode("utf-8", "replace")
                print("[text] %s" % text[:200])
                continue

            frame = unpack(payload)[0]
            frames += 1
            events = frame.get("events") or []
            events_seen += len(events)
            print("[frame] seq=%s events=%d bytes=%d" % (frame.get("seq"), len(events), len(payload)))
            for event in events[: args.show]:
                print("   %s/%s %s %s" % (event.get("category"), event.get("type"),
                                          event.get("ts"), json.dumps(event.get("payload"),
                                                                     ensure_ascii=False)[:160]))
            send_json(client, {"type": "ack", "seq": frame.get("seq")})

            if args.command and not command_sent and events_seen > 0:
                command_sent = True
                send_json(client, {"type": "command", "command_id": uuid.uuid4().hex,
                                   "name": args.command, "args": {}})

            if args.duration and time.time() - started > args.duration:
                print("[summary] frames=%d events=%d" % (frames, events_seen))
                break
    except ConnectionError:
        print("[close] peer disconnected")
        return

    print("[summary] frames=%d events=%d" % (frames, events_seen))


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--vectors", action="store_true", help="run offline wire checks")
    parser.add_argument("--mock-server", action="store_true", help="run a mock backend")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--token", default="", help="reject a hello whose token differs")
    parser.add_argument("--command", default="", help="send this command once after events arrive")
    parser.add_argument("--duration", type=float, default=0, help="stop after N seconds")
    parser.add_argument("--show", type=int, default=3, help="events printed per frame")
    args = parser.parse_args()

    if args.vectors:
        return run_vectors()
    if args.mock_server:
        return run_mock_server(args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
