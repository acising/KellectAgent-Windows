#pragma once
//
// Minimal RFC 6455 WebSocket client (ws:// only).
//
// Why hand-rolled: the probe protocol (System/docs/probe-integration.md v1) is
// plaintext WebSocket on Windows 7+, and the collector already links only
// Winsock + the vendored libs. WinHTTP's WebSocket API needs Windows 8 and the
// WinHTTP session model, which is more than this channel needs.
//
// Scope: client role, masked frames, text/binary messages, fragmentation,
// ping/pong/close control frames, single message <= kMaxMessageBytes.
// Not implemented (not needed by protocol v1): TLS (wss), extensions,
// compression, server role.
//
#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
#include <mutex>
#include <string>

namespace kellect {
namespace ws {

enum class RxStatus {
    Message,   // a complete text/binary message was returned
    Timeout,   // nothing arrived within the read timeout (connection still sane)
    Closed,    // peer sent a close frame, or the socket was closed
    Error,     // protocol/socket error; the connection must be re-established
};

class Client {
public:
    Client();
    ~Client();

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    // `url` = ws://host[:port][/path]. Returns false and fills `error` on
    // failure (including wss://, which protocol v1 does not use).
    bool Connect(const std::string& url, std::string& error);
    void Close();
    bool IsOpen() const { return open_.load(); }

    bool SendText(const std::string& payload, std::string& error);
    bool SendBinary(const std::string& payload, std::string& error);

    // Reads one complete data message. Control frames are handled internally
    // (ping gets a pong) except close, which is reported as RxStatus::Closed.
    RxStatus Receive(std::string& payload, std::string& error);

private:
    enum { kMaxMessageBytes = 4 * 1024 * 1024, kReadTimeoutMs = 1000 };

    bool Handshake(const std::string& hostHeader, const std::string& path, std::string& error);
    bool WriteFrame(int opcode, const std::string& payload, std::string& error);

    // Reads one raw frame. `opcode` is the wire opcode, `fin` the FIN bit.
    // A timeout before the first byte is RxStatus::Timeout; once a frame has
    // started, a timeout is an Error (we cannot resynchronise a half-read frame).
    RxStatus ReadFrame(int& opcode, bool& fin, std::string& payload, std::string& error);

    // timeoutMs < 0 blocks until `n` bytes arrive.
    RxStatus RecvExact(char* dst, size_t n, int timeoutMs, bool& gotAny, std::string& error);
    // Reads whatever is available after waiting up to timeoutMs (at least one
    // byte). Used for the HTTP handshake, which has no known length.
    RxStatus RecvChunk(char* dst, size_t maxBytes, int timeoutMs, size_t& got,
                       std::string& error);
    bool SendAll(const char* data, size_t n, std::string& error);

    // Atomic: Close() can run on the sender thread while the reader is blocked
    // inside select()/recv() on the same handle.
    std::atomic<SOCKET> sock_{ INVALID_SOCKET };
    std::atomic<bool> open_{ false };
    std::mutex sendMutex_;
    std::string rxLeftover_;   // bytes read past the HTTP response
    bool wsaStarted_ = false;
    unsigned char maskKeyCounter_ = 0;
};

// Exposed for the self-test tooling: ws://host[:port][/path].
bool ParseUrl(const std::string& url, std::string& host, std::string& port,
              std::string& path, std::string& error);

} // namespace ws
} // namespace kellect
