#include "secargus/mqtt_client.h"

#include <windows.h>

#include <cstring>

namespace kellect {
namespace secargus {

namespace {

void AppendU16(std::string& out, uint16_t v) {
    out.push_back(static_cast<char>((v >> 8) & 0xff));
    out.push_back(static_cast<char>(v & 0xff));
}

void AppendString(std::string& out, const std::string& s) {
    AppendU16(out, static_cast<uint16_t>(s.size()));
    out.append(s);
}

void AppendVarint(std::string& out, uint32_t value) {
    do {
        uint8_t byte = static_cast<uint8_t>(value % 128);
        value /= 128;
        if (value > 0) byte |= 0x80;
        out.push_back(static_cast<char>(byte));
    } while (value > 0);
}

uint16_t ReadU16(const std::string& body, size_t offset) {
    return static_cast<uint16_t>((static_cast<uint8_t>(body[offset]) << 8) |
                                 static_cast<uint8_t>(body[offset + 1]));
}

} // namespace

MqttClient::~MqttClient() {
    Close();
    if (wsaStarted_) {
        WSACleanup();
        wsaStarted_ = false;
    }
}

void MqttClient::Close() {
    if (sock_ != INVALID_SOCKET) {
        shutdown(sock_, SD_BOTH);
        closesocket(sock_);
        sock_ = INVALID_SOCKET;
    }
}

bool MqttClient::SendAll(const char* data, size_t n, std::string& error) {
    size_t sent = 0;
    while (sent < n) {
        const int rc = send(sock_, data + sent, static_cast<int>(n - sent), 0);
        if (rc == SOCKET_ERROR) {
            error = "send failed: " + std::to_string(WSAGetLastError());
            Close();
            return false;
        }
        if (rc == 0) {
            error = "send returned 0";
            Close();
            return false;
        }
        sent += static_cast<size_t>(rc);
    }
    return true;
}

bool MqttClient::RecvExact(char* dst, size_t n, int timeoutMs, std::string& error) {
    size_t off = 0;
    while (off < n) {
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(sock_, &readable);
        timeval tv;
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;

        const int selected = select(0, &readable, nullptr, nullptr, &tv);
        if (selected == 0) {
            error = "timeout";
            return false;
        }
        if (selected == SOCKET_ERROR) {
            error = "select failed: " + std::to_string(WSAGetLastError());
            Close();
            return false;
        }

        const int rc = recv(sock_, dst + off, static_cast<int>(n - off), 0);
        if (rc == 0) {
            error = "connection closed by broker";
            Close();
            return false;
        }
        if (rc == SOCKET_ERROR) {
            error = "recv failed: " + std::to_string(WSAGetLastError());
            Close();
            return false;
        }
        off += static_cast<size_t>(rc);
    }
    return true;
}

bool MqttClient::SendPacket(uint8_t header, const std::string& body,
                            std::string& error) {
    std::string packet;
    packet.push_back(static_cast<char>(header));
    AppendVarint(packet, static_cast<uint32_t>(body.size()));
    packet += body;

    if (!SendAll(packet.data(), packet.size(), error))
        return false;
    lastSend_ = std::chrono::steady_clock::now();
    return true;
}

bool MqttClient::ReadPacket(uint8_t& header, std::string& body, int timeoutMs,
                            std::string& error) {
    char first = 0;
    if (!RecvExact(&first, 1, timeoutMs, error))
        return false;
    header = static_cast<uint8_t>(first);

    uint32_t remaining = 0;
    uint32_t multiplier = 1;
    for (int i = 0; i < 4; ++i) {
        char byte = 0;
        if (!RecvExact(&byte, 1, timeoutMs, error))
            return false;
        const uint8_t value = static_cast<uint8_t>(byte);
        remaining += (value & 0x7f) * multiplier;
        if ((value & 0x80) == 0)
            break;
        multiplier *= 128;
    }

    body.assign(remaining, '\0');
    if (remaining > 0 && !RecvExact(&body[0], remaining, timeoutMs, error))
        return false;
    return true;
}

bool MqttClient::ConnectSocket(std::string& error) {
    addrinfo hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = nullptr;
    const std::string portText = std::to_string(port_);
    if (getaddrinfo(host_.c_str(), portText.c_str(), &hints, &result) != 0) {
        error = "cannot resolve " + host_;
        return false;
    }

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
                if (getsockopt(s, SOL_SOCKET, SO_ERROR,
                               reinterpret_cast<char*>(&soError), &len) == 0)
                    connected = (soError == 0);
            } else {
                lastError = "connect timed out";
            }
        }

        nonBlocking = 0;
        ioctlsocket(s, FIONBIO, &nonBlocking);

        if (!connected) {
            closesocket(s);
            continue;
        }

        int one = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
                   reinterpret_cast<const char*>(&one), sizeof(one));
        DWORD sendTimeout = 10000;
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
                   reinterpret_cast<const char*>(&sendTimeout), sizeof(sendTimeout));

        sock_ = s;
        freeaddrinfo(result);
        return true;
    }

    freeaddrinfo(result);
    error = lastError;
    return false;
}

bool MqttClient::Connect(const MqttSettings& settings, const std::string& clientId,
                         const Will& will, std::string& error) {
    Close();

    if (!wsaStarted_) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            error = "WSAStartup failed";
            return false;
        }
        wsaStarted_ = true;
    }

    host_ = settings.host;
    port_ = settings.port;
    keepaliveS_ = settings.keepaliveS > 0 ? settings.keepaliveS : 30;

    if (!ConnectSocket(error))
        return false;

    // CONNECT
    std::string body;
    AppendString(body, "MQTT");
    body.push_back(4);   // protocol level 3.1.1
    uint8_t flags = settings.cleanSession ? 0x02 : 0x00;
    if (will.enabled) {
        flags |= 0x04;                                  // will flag
        flags |= static_cast<uint8_t>((will.qos & 0x03) << 3);
        if (will.retain) flags |= 0x20;
    }
    if (!settings.username.empty()) flags |= 0x80;
    if (!settings.password.empty()) flags |= 0x40;
    body.push_back(static_cast<char>(flags));
    AppendU16(body, static_cast<uint16_t>(keepaliveS_));   // keepalive seconds
    AppendString(body, clientId);
    if (will.enabled) {
        AppendString(body, will.topic);
        AppendString(body, will.payload);
    }
    if (!settings.username.empty()) AppendString(body, settings.username);
    if (!settings.password.empty()) AppendString(body, settings.password);

    if (!SendPacket(0x10, body, error)) {
        Close();
        return false;
    }

    uint8_t header = 0;
    std::string ack;
    if (!ReadPacket(header, ack, 10000, error)) {
        Close();
        return false;
    }
    if ((header >> 4) != 2 || ack.size() < 2) {
        error = "unexpected CONNACK";
        Close();
        return false;
    }
    const uint8_t rc = static_cast<uint8_t>(ack[1]);
    if (rc != 0) {
        error = "CONNACK refused, code " + std::to_string(rc);
        Close();
        return false;
    }

    return true;
}

bool MqttClient::Publish(const std::string& topic, const std::string& payload,
                         int qos, bool retain, std::vector<Incoming>& inbox,
                         std::string& error) {
    const uint16_t packetId = nextPacketId_++;
    if (nextPacketId_ == 0)
        nextPacketId_ = 1;

    std::string body;
    AppendString(body, topic);
    if (qos > 0)
        AppendU16(body, packetId);
    body += payload;

    uint8_t header = static_cast<uint8_t>(0x30 | ((qos & 0x03) << 1));
    if (retain)
        header |= 0x01;
    if (!SendPacket(header, body, error))
        return false;

    if (qos > 0) {
        // Collect inbound PUBLISH (business ACKs / commands) while waiting.
        return WaitForPubAck(packetId, 10000, inbox, error);
    }
    return true;
}

bool MqttClient::WaitForPubAck(uint16_t packetId, int timeoutMs,
                               std::vector<Incoming>& messages, std::string& error) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeoutMs);

    for (;;) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            error = "PUBACK timeout";
            return false;
        }
        const int remaining = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
        if (remaining <= 0) {
            error = "PUBACK timeout";
            return false;
        }

        uint8_t header = 0;
        std::string body;
        if (!ReadPacket(header, body, remaining, error))
            return false;

        if ((header >> 4) == 4 && body.size() >= 2 && ReadU16(body, 0) == packetId)
            return true;

        if (!HandleInbound(header, body, messages, error))
            return false;
    }
}

bool MqttClient::Subscribe(const std::string& topicFilter, int qos,
                           std::string& error) {
    const uint16_t packetId = nextPacketId_++;
    if (nextPacketId_ == 0)
        nextPacketId_ = 1;

    std::string body;
    AppendU16(body, packetId);
    AppendString(body, topicFilter);
    body.push_back(static_cast<char>(qos & 0x03));

    if (!SendPacket(0x82, body, error))
        return false;

    // SUBACK is consumed by Pump(); do not block here.
    return true;
}

bool MqttClient::HandleInbound(uint8_t header, const std::string& body,
                               std::vector<Incoming>& messages, std::string& error) {
    const uint8_t type = header >> 4;
    const uint8_t flags = header & 0x0f;

    if (type == 3) {   // PUBLISH
        if (body.size() < 2) {
            error = "malformed PUBLISH";
            return false;
        }
        const uint16_t topicLen = ReadU16(body, 0);
        if (body.size() < static_cast<size_t>(2 + topicLen)) {
            error = "malformed PUBLISH topic";
            return false;
        }
        Incoming message;
        message.topic = body.substr(2, topicLen);
        message.retained = (flags & 0x01) != 0;
        size_t offset = 2 + topicLen;

        const int qos = (flags >> 1) & 0x03;
        uint16_t packetId = 0;
        if (qos > 0) {
            if (body.size() < offset + 2) {
                error = "malformed PUBLISH packet id";
                return false;
            }
            packetId = ReadU16(body, offset);
            offset += 2;
        }
        message.payload = body.substr(offset);

        if (qos == 1) {
            std::string ack;
            AppendU16(ack, packetId);
            std::string ignored;
            if (!SendPacket(0x40, ack, ignored))
                return false;
        } else if (qos == 2) {
            error = "QoS 2 is not supported";
            return false;
        }

        messages.push_back(std::move(message));
        return true;
    }

    if (type == 4 || type == 9 || type == 13)
        return true;   // PUBACK / SUBACK / PINGRESP

    if (type == 14) {
        error = "broker disconnected";
        Close();
        return false;
    }

    error = "unexpected MQTT packet type " + std::to_string(type);
    return false;
}

bool MqttClient::Pump(std::vector<Incoming>& messages, int timeoutMs,
                      std::string& error) {
    uint8_t header = 0;
    std::string body;
    if (!ReadPacket(header, body, timeoutMs, error))
        return false;
    return HandleInbound(header, body, messages, error);
}

void MqttClient::KeepAlive() {
    if (sock_ == INVALID_SOCKET)
        return;
    const auto now = std::chrono::steady_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - lastSend_).count();
    if (elapsed < (keepaliveS_ / 2 > 0 ? keepaliveS_ / 2 : 1))
        return;
    std::string error;
    SendPacket(0xC0, std::string(), error);   // PINGREQ
}

} // namespace secargus
} // namespace kellect
