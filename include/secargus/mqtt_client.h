#pragma once
//
// Minimal MQTT 3.1.1 client (publish/subscribe, QoS 0/1, keepalive).
//
// Plain TCP over Winsock: this build targets a lab/demo deployment where the
// broker is reachable on a trusted network and TLS overhead is not wanted.
//
#include <winsock2.h>
#include <ws2tcpip.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "secargus/config.h"

namespace kellect {
namespace secargus {

class MqttClient {
public:
    struct Incoming {
        std::string topic;
        std::string payload;
        bool retained = false;
    };

    // MQTT will (LWT): the broker publishes it when the connection drops, so a
    // crashed agent shows up as "offline" instead of looking healthy forever.
    struct Will {
        bool enabled = false;
        std::string topic;
        std::string payload;
        int qos = 1;
        bool retain = true;
    };

    MqttClient() = default;
    ~MqttClient();

    MqttClient(const MqttClient&) = delete;
    MqttClient& operator=(const MqttClient&) = delete;

    bool Connect(const MqttSettings& settings, const std::string& clientId,
                 const Will& will, std::string& error);
    void Close();
    bool IsConnected() const { return sock_ != INVALID_SOCKET; }

    bool Publish(const std::string& topic, const std::string& payload, int qos,
                 bool retain, std::vector<Incoming>& inbox, std::string& error);
    bool Subscribe(const std::string& topicFilter, int qos, std::string& error);

    // Reads at most one packet. Returns false with error=="timeout" when nothing
    // arrived within `timeoutMs`; other errors are fatal for the connection.
    bool Pump(std::vector<Incoming>& messages, int timeoutMs, std::string& error);

    // Sends PINGREQ when half the keepalive elapsed.
    void KeepAlive();

    // Waits for the PUBACK of `packetId`, processing inbound PUBLISH packets
    // into `messages` meanwhile. Returns false on timeout/error.
    bool WaitForPubAck(uint16_t packetId, int timeoutMs,
                       std::vector<Incoming>& messages, std::string& error);

private:
    bool ConnectSocket(std::string& error);
    bool SendPacket(uint8_t header, const std::string& body, std::string& error);
    bool ReadPacket(uint8_t& header, std::string& body, int timeoutMs,
                    std::string& error);
    bool RecvExact(char* dst, size_t n, int timeoutMs, std::string& error);
    bool SendAll(const char* data, size_t n, std::string& error);
    bool HandleInbound(uint8_t header, const std::string& body,
                       std::vector<Incoming>& messages, std::string& error);

    SOCKET sock_ = INVALID_SOCKET;
    bool wsaStarted_ = false;
    std::string host_;
    int port_ = 1883;
    int keepaliveS_ = 30;
    uint16_t nextPacketId_ = 1;
    std::chrono::steady_clock::time_point lastSend_{};
};

} // namespace secargus
} // namespace kellect
