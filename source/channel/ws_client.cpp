#include "channel/ws_client.h"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <random>
#include <sstream>

namespace kellect {
namespace ws {

namespace {

const char* kWebSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

inline uint32_t Rol(uint32_t v, int n) {
    return (v << n) | (v >> (32 - n));
}

std::string Sha1(const std::string& data) {
    uint32_t h[5] = { 0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u };

    std::string msg = data;
    const uint64_t bitLen = static_cast<uint64_t>(msg.size()) * 8;
    msg.push_back(static_cast<char>(0x80));
    while (msg.size() % 64 != 56)
        msg.push_back(static_cast<char>(0x00));
    for (int i = 7; i >= 0; --i)
        msg.push_back(static_cast<char>((bitLen >> (8 * i)) & 0xff));

    for (size_t chunk = 0; chunk < msg.size(); chunk += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(static_cast<unsigned char>(msg[chunk + 4 * i])) << 24) |
                   (static_cast<uint32_t>(static_cast<unsigned char>(msg[chunk + 4 * i + 1])) << 16) |
                   (static_cast<uint32_t>(static_cast<unsigned char>(msg[chunk + 4 * i + 2])) << 8) |
                   (static_cast<uint32_t>(static_cast<unsigned char>(msg[chunk + 4 * i + 3])));
        }
        for (int i = 16; i < 80; ++i)
            w[i] = Rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999u; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1u; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCu; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6u; }
            const uint32_t tmp = Rol(a, 5) + f + e + k + w[i];
            e = d; d = c; c = Rol(b, 30); b = a; a = tmp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }

    std::string out(20, '\0');
    for (int i = 0; i < 5; ++i) {
        out[4 * i + 0] = static_cast<char>((h[i] >> 24) & 0xff);
        out[4 * i + 1] = static_cast<char>((h[i] >> 16) & 0xff);
        out[4 * i + 2] = static_cast<char>((h[i] >> 8) & 0xff);
        out[4 * i + 3] = static_cast<char>(h[i] & 0xff);
    }
    return out;
}

std::string Base64(const std::string& in) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int value = 0;
    int bits = -6;
    for (unsigned char c : in) {
        value = (value << 8) + c;
        bits += 8;
        while (bits >= 0) {
            out.push_back(table[(value >> bits) & 0x3f]);
            bits -= 6;
        }
    }
    if (bits > -6)
        out.push_back(table[((value << 8) >> (bits + 8)) & 0x3f]);
    while (out.size() % 4)
        out.push_back('=');
    return out;
}

std::string RandomBytes(size_t n) {
    static std::atomic<uint64_t> counter{ 0 };
    std::random_device rd;
    const uint64_t seed = (static_cast<uint64_t>(rd()) << 32) ^ rd() ^
                          GetTickCount64() ^ (counter.fetch_add(1) * 0x9E3779B97F4A7C15ull);
    std::mt19937_64 gen(seed);
    std::string out(n, '\0');
    for (size_t i = 0; i < n; ++i)
        out[i] = static_cast<char>(gen() & 0xff);
    return out;
}

std::string ToLower(const std::string& s) {
    std::string out = s;
    for (char& c : out)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return out;
}

} // namespace

bool ParseUrl(const std::string& url, std::string& host, std::string& port,
              std::string& path, std::string& error) {
    std::string rest;
    if (url.compare(0, 5, "ws://") == 0) {
        rest = url.substr(5);
    } else if (url.compare(0, 6, "wss://") == 0) {
        error = "wss:// is not supported: probe protocol v1 is plaintext (put a TLS proxy in front)";
        return false;
    } else if (url.compare(0, 7, "http://") == 0) {
        rest = url.substr(7);   // tolerated for convenience
    } else {
        error = "url must start with ws:// (got '" + url + "')";
        return false;
    }

    const size_t slash = rest.find('/');
    const std::string hostPort = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    path = (slash == std::string::npos) ? "/" : rest.substr(slash);

    std::string p;
    if (!hostPort.empty() && hostPort[0] == '[') {          // [::1]:8000
        const size_t close = hostPort.find(']');
        if (close == std::string::npos) {
            error = "malformed IPv6 host in url";
            return false;
        }
        host = hostPort.substr(1, close - 1);
        if (close + 1 < hostPort.size() && hostPort[close + 1] == ':')
            p = hostPort.substr(close + 2);
    } else {
        const size_t colon = hostPort.rfind(':');
        if (colon == std::string::npos) {
            host = hostPort;
        } else {
            host = hostPort.substr(0, colon);
            p = hostPort.substr(colon + 1);
        }
    }

    if (host.empty()) {
        error = "url has no host";
        return false;
    }
    port = p.empty() ? "80" : p;
    return true;
}

Client::Client() = default;

Client::~Client() {
    Close();
    if (wsaStarted_) {
        WSACleanup();
        wsaStarted_ = false;
    }
}

bool Client::Connect(const std::string& url, std::string& error) {
    Close();

    std::string host, port, path;
    if (!ParseUrl(url, host, port, path, error))
        return false;

    if (!wsaStarted_) {
        WSADATA wsa;
        const int rc = WSAStartup(MAKEWORD(2, 2), &wsa);
        if (rc != 0) {
            error = "WSAStartup failed: " + std::to_string(rc);
            return false;
        }
        wsaStarted_ = true;
    }

    addrinfo hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = nullptr;
    const int gai = getaddrinfo(host.c_str(), port.c_str(), &hints, &result);
    if (gai != 0) {
        error = "cannot resolve " + host + ":" + port + " (getaddrinfo " +
                std::to_string(gai) + ")";
        return false;
    }

    SOCKET sock = INVALID_SOCKET;
    std::string lastError = "connect failed";

    for (addrinfo* ai = result; ai != nullptr; ai = ai->ai_next) {
        SOCKET s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET)
            continue;

        u_long nonBlocking = 1;
        ioctlsocket(s, FIONBIO, &nonBlocking);

        bool connected = false;
        if (connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen)) == 0) {
            connected = true;
        } else if (WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set writable;
            FD_ZERO(&writable);
            FD_SET(s, &writable);
            timeval tv;
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            if (select(0, nullptr, &writable, nullptr, &tv) > 0) {
                int soError = 0;
                int len = sizeof(soError);
                if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soError), &len) == 0)
                    connected = (soError == 0);
                if (!connected)
                    lastError = "connect: " + std::to_string(soError);
            } else {
                lastError = "connect timed out";
            }
        } else {
            lastError = "connect failed: " + std::to_string(WSAGetLastError());
        }

        nonBlocking = 0;
        ioctlsocket(s, FIONBIO, &nonBlocking);

        if (!connected) {
            closesocket(s);
            continue;
        }

        int one = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));

        // Bound blocking sends: a stalled peer must not wedge the sender thread.
        DWORD sendTimeout = 10000;
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
                   reinterpret_cast<const char*>(&sendTimeout), sizeof(sendTimeout));

        sock = s;
        break;
    }

    freeaddrinfo(result);

    if (sock == INVALID_SOCKET) {
        error = lastError;
        return false;
    }

    sock_ = sock;
    rxLeftover_.clear();
    const std::string hostHeader = (port == "80") ? host : (host + ":" + port);

    if (!Handshake(hostHeader, path, error)) {
        Close();
        return false;
    }

    open_ = true;
    return true;
}

void Client::Close() {
    open_ = false;
    const SOCKET sock = sock_.exchange(INVALID_SOCKET);
    if (sock != INVALID_SOCKET) {
        shutdown(sock, SD_BOTH);
        closesocket(sock);
    }
    rxLeftover_.clear();
}

bool Client::SendAll(const char* data, size_t n, std::string& error) {
    size_t sent = 0;
    while (sent < n) {
        const int chunk = static_cast<int>(n - sent);
        const int rc = send(sock_, data + sent, chunk, 0);
        if (rc == SOCKET_ERROR) {
            error = "send failed: " + std::to_string(WSAGetLastError());
            open_ = false;
            return false;
        }
        if (rc == 0) {
            error = "send returned 0";
            open_ = false;
            return false;
        }
        sent += static_cast<size_t>(rc);
    }
    return true;
}

bool Client::Handshake(const std::string& hostHeader, const std::string& path,
                       std::string& error) {
    const std::string key = Base64(RandomBytes(16));

    std::ostringstream request;
    request << "GET " << path << " HTTP/1.1\r\n"
            << "Host: " << hostHeader << "\r\n"
            << "Upgrade: websocket\r\n"
            << "Connection: Upgrade\r\n"
            << "Sec-WebSocket-Key: " << key << "\r\n"
            << "Sec-WebSocket-Version: 13\r\n"
            << "User-Agent: kellect-probe/1.0\r\n"
            << "\r\n";

    const std::string head = request.str();
    if (!SendAll(head.data(), head.size(), error))
        return false;

    // Read until the end of the HTTP response head (bounded).
    std::string response;
    while (response.find("\r\n\r\n") == std::string::npos) {
        if (response.size() > 16 * 1024) {
            error = "handshake response too large";
            return false;
        }
        char buffer[512];
        size_t got = 0;
        const RxStatus st = RecvChunk(buffer, sizeof(buffer), 10000, got, error);
        if (st == RxStatus::Timeout) {
            error = "handshake timed out";
            return false;
        }
        if (st == RxStatus::Closed) {
            error = "connection closed during handshake";
            return false;
        }
        if (st == RxStatus::Error) {
            if (error.empty()) error = "handshake read failed";
            return false;
        }
        response.append(buffer, got);
    }

    const size_t headEnd = response.find("\r\n\r\n") + 4;
    const std::string headPart = response.substr(0, headEnd);
    rxLeftover_ = response.substr(headEnd);   // frames the server already sent

    const size_t lineEnd = headPart.find("\r\n");
    const std::string statusLine = headPart.substr(0, lineEnd);
    if (statusLine.find(" 101 ") == std::string::npos &&
        statusLine.find(" 101") == std::string::npos) {
        error = "handshake rejected: " + statusLine;
        return false;
    }

    const std::string expected = Base64(Sha1(key + kWebSocketGuid));
    std::string accept;
    size_t pos = 0;
    while (pos < headPart.size()) {
        size_t eol = headPart.find("\r\n", pos);
        if (eol == std::string::npos) eol = headPart.size();
        const std::string line = headPart.substr(pos, eol - pos);
        pos = eol + 2;
        const size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        if (ToLower(line.substr(0, colon)) == "sec-websocket-accept") {
            accept = line.substr(colon + 1);
            while (!accept.empty() && (accept[0] == ' ' || accept[0] == '\t')) accept.erase(0, 1);
            while (!accept.empty() && (accept.back() == ' ' || accept.back() == '\r')) accept.pop_back();
        }
    }

    if (accept != expected) {
        error = "handshake accepts key mismatch";
        return false;
    }
    return true;
}

bool Client::WriteFrame(int opcode, const std::string& payload, std::string& error) {
    if (sock_ == INVALID_SOCKET) {
        error = "socket closed";
        return false;
    }
    if (payload.size() > static_cast<size_t>(kMaxMessageBytes)) {
        error = "frame too large";
        return false;
    }

    const size_t n = payload.size();
    std::string frame;
    frame.reserve(n + 14);
    frame.push_back(static_cast<char>(0x80 | (opcode & 0x0f)));

    if (n < 126) {
        frame.push_back(static_cast<char>(0x80 | static_cast<unsigned char>(n)));
    } else if (n <= 0xffff) {
        frame.push_back(static_cast<char>(0x80 | 126));
        frame.push_back(static_cast<char>((n >> 8) & 0xff));
        frame.push_back(static_cast<char>(n & 0xff));
    } else {
        frame.push_back(static_cast<char>(0x80 | 127));
        for (int i = 7; i >= 0; --i)
            frame.push_back(static_cast<char>((static_cast<uint64_t>(n) >> (8 * i)) & 0xff));
    }

    const std::string mask = RandomBytes(4);
    frame.append(mask);
    const size_t payloadOffset = frame.size();
    frame.append(payload);
    for (size_t i = 0; i < n; ++i)
        frame[payloadOffset + i] = static_cast<char>(frame[payloadOffset + i] ^ mask[i & 3]);

    std::lock_guard<std::mutex> lock(sendMutex_);
    return SendAll(frame.data(), frame.size(), error);
}

bool Client::SendText(const std::string& payload, std::string& error) {
    return WriteFrame(0x1, payload, error);
}

bool Client::SendBinary(const std::string& payload, std::string& error) {
    return WriteFrame(0x2, payload, error);
}

RxStatus Client::RecvChunk(char* dst, size_t maxBytes, int timeoutMs, size_t& got,
                           std::string& error) {
    got = 0;
    if (sock_ == INVALID_SOCKET) {
        error = "socket closed";
        return RxStatus::Error;
    }
    if (!rxLeftover_.empty()) {
        const size_t take = (std::min)(maxBytes, rxLeftover_.size());
        std::memcpy(dst, rxLeftover_.data(), take);
        rxLeftover_.erase(0, take);
        got = take;
        return RxStatus::Message;
    }

    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(sock_, &readable);
    timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    const int selected = select(0, &readable, nullptr, nullptr, &tv);
    if (selected == 0)
        return RxStatus::Timeout;
    if (selected == SOCKET_ERROR) {
        error = "select failed: " + std::to_string(WSAGetLastError());
        return RxStatus::Error;
    }

    const int rc = recv(sock_, dst, static_cast<int>(maxBytes), 0);
    if (rc == 0) {
        error = "connection closed by peer";
        open_ = false;
        return RxStatus::Closed;
    }
    if (rc == SOCKET_ERROR) {
        error = "recv failed: " + std::to_string(WSAGetLastError());
        open_ = false;
        return RxStatus::Error;
    }
    got = static_cast<size_t>(rc);
    return RxStatus::Message;
}

RxStatus Client::RecvExact(char* dst, size_t n, int timeoutMs, bool& gotAny,
                           std::string& error) {
    if (sock_ == INVALID_SOCKET) {
        error = "socket closed";
        return RxStatus::Error;
    }
    size_t off = 0;
    while (off < n) {
        if (!rxLeftover_.empty()) {
            const size_t take = (std::min)(n - off, rxLeftover_.size());
            std::memcpy(dst + off, rxLeftover_.data(), take);
            rxLeftover_.erase(0, take);
            off += take;
            gotAny = true;
            continue;
        }

        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(sock_, &readable);
        timeval tv;
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        const int selected = select(0, &readable, nullptr, nullptr, &tv);
        if (selected == 0)
            return gotAny ? RxStatus::Error : RxStatus::Timeout;
        if (selected == SOCKET_ERROR) {
            error = "select failed: " + std::to_string(WSAGetLastError());
            return RxStatus::Error;
        }

        const int got = recv(sock_, dst + off, static_cast<int>(n - off), 0);
        if (got == 0) {
            error = "connection closed by peer";
            open_ = false;
            return RxStatus::Closed;
        }
        if (got == SOCKET_ERROR) {
            const int rc = WSAGetLastError();
            if (rc == WSAEWOULDBLOCK) continue;
            error = "recv failed: " + std::to_string(rc);
            open_ = false;
            return RxStatus::Error;
        }
        off += static_cast<size_t>(got);
        gotAny = true;
    }
    return RxStatus::Message;
}

RxStatus Client::ReadFrame(int& opcode, bool& fin, std::string& payload,
                           std::string& error) {
    unsigned char header[2];
    bool gotAny = false;
    RxStatus st = RecvExact(reinterpret_cast<char*>(header), 2, kReadTimeoutMs, gotAny, error);
    if (st != RxStatus::Message)
        return st;
    if (header[0] & 0x70) {
        error = "server set RSV bits without an extension";
        return RxStatus::Error;
    }

    fin = (header[0] & 0x80) != 0;
    opcode = header[0] & 0x0f;
    const bool masked = (header[1] & 0x80) != 0;
    uint64_t length = header[1] & 0x7f;

    gotAny = true;
    if (length == 126) {
        unsigned char ext[2];
        st = RecvExact(reinterpret_cast<char*>(ext), 2, 10000, gotAny, error);
        if (st != RxStatus::Message) return st;
        length = (static_cast<uint64_t>(ext[0]) << 8) | ext[1];
    } else if (length == 127) {
        unsigned char ext[8];
        st = RecvExact(reinterpret_cast<char*>(ext), 8, 10000, gotAny, error);
        if (st != RxStatus::Message) return st;
        length = 0;
        for (int i = 0; i < 8; ++i)
            length = (length << 8) | ext[i];
    }

    if (length > static_cast<uint64_t>(kMaxMessageBytes)) {
        error = "incoming frame exceeds limit";
        return RxStatus::Error;
    }
    if (opcode >= 0x8 && (length > 125 || !fin)) {
        error = "invalid control frame";
        return RxStatus::Error;
    }

    unsigned char mask[4] = { 0, 0, 0, 0 };
    if (masked) {
        st = RecvExact(reinterpret_cast<char*>(mask), 4, 10000, gotAny, error);
        if (st != RxStatus::Message) return st;
    }

    payload.assign(static_cast<size_t>(length), '\0');
    if (length > 0) {
        st = RecvExact(&payload[0], static_cast<size_t>(length), 10000, gotAny, error);
        if (st != RxStatus::Message) return st;
        if (masked) {
            for (size_t i = 0; i < payload.size(); ++i)
                payload[i] = static_cast<char>(payload[i] ^ mask[i & 3]);
        }
    }
    return RxStatus::Message;
}

RxStatus Client::Receive(std::string& payload, std::string& error) {
    std::string assembled;
    int messageOpcode = 0;

    for (;;) {
        int opcode = 0;
        bool fin = false;
        std::string chunk;
        const RxStatus st = ReadFrame(opcode, fin, chunk, error);
        if (st != RxStatus::Message)
            return st;

        switch (opcode) {
            case 0x1:   // text
            case 0x2: { // binary
                if (!fin) {
                    messageOpcode = opcode;
                    assembled = chunk;
                    continue;
                }
                payload = chunk;
                return RxStatus::Message;
            }
            case 0x0: { // continuation
                if (messageOpcode == 0) {
                    error = "continuation frame without a start frame";
                    return RxStatus::Error;
                }
                assembled += chunk;
                if (assembled.size() > static_cast<size_t>(kMaxMessageBytes)) {
                    error = "assembled message exceeds limit";
                    return RxStatus::Error;
                }
                if (fin) {
                    payload = assembled;
                    return RxStatus::Message;
                }
                continue;
            }
            case 0x8: { // close
                std::string ignored;
                WriteFrame(0x8, chunk, ignored);   // best-effort close echo
                open_ = false;
                return RxStatus::Closed;
            }
            case 0x9: { // ping -> pong
                std::string ignored;
                WriteFrame(0xA, chunk, ignored);
                continue;
            }
            case 0xA:   // pong
                continue;
            default:
                error = "unsupported opcode " + std::to_string(opcode);
                return RxStatus::Error;
        }
    }
}

} // namespace ws
} // namespace kellect
