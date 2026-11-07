#pragma once
//
// Probe channel: streams Kellect kernel events to the Kellect backend over
// WebSocket + MessagePack (protocol v1, System/docs/probe-integration.md).
//
// Shape:
//   ETW pipeline -> Output queue -> output()  (base output thread)
//                    -> bounded buffer -> sender thread
//                       -> MessagePack batches -> ws://host:8000/ws/probe
//   reader thread  <- ack / throttle / ping / command
//
// Select the probe output with --probe.
//
#include "channel/ws_client.h"
#include "nlohmann/json.hpp"
#include "output/output.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace kellect {
namespace channel {

// Matches the agent_version field the backend records; bump on protocol changes.
extern const char* const kAgentVersion;

struct ProbeConfig {
    std::string url;                 // ws://127.0.0.1:8000/ws/probe
    std::string probeId;             // registered probe id (stable identity)
    std::string token;               // one-time token from the admin API
    std::string hostname;            // empty = auto-detect
    std::string platform = "windows";
    std::string configPath;          // filled by LoadProbeConfig
    size_t queueCapacity = 20000;    // local backlog before dropping oldest
    size_t batchEvents = 200;        // <= server max_events_per_batch (500)
    size_t batchBytes = 512 * 1024;  // <= server max_batch_bytes (1 MiB)
    int ratePerSecond = 0;           // 0 = unlimited
    bool verbose = false;
};

// Reads config/probe.ini. Missing file is not an error (CLI flags may supply
// everything); malformed lines are reported through `error` and false.
bool LoadProbeConfig(const std::string& path, ProbeConfig& cfg, std::string& error);

class ProbeChannel : public Output {
public:
    explicit ProbeChannel(const ProbeConfig& cfg);
    ~ProbeChannel() override;

    STATUS init() override;
    void output(std::string outputString) override;
    // Waits (bounded) until the local queue has been drained by the worker.
    void waitFlushed(int timeoutMs) override;

private:
    void Worker();
    bool Hello(std::string& error);
    void ReaderLoop();
    void HandleControl(const std::string& text);
    void HandleCommand(const nlohmann::json& frame);

    std::vector<std::string> TakeBatch();
    // Encodes up to the configured batch limits. `consumed` = how many entries
    // of `raw` were handled (encoded or skipped); the caller requeues the rest.
    bool EncodeBatch(const std::vector<std::string>& raw, std::string& frame,
                     size_t& usedEvents, size_t& consumed);
    void RequeueFront(std::deque<std::string>& leftovers);

    void Enqueue(std::string line);
    bool TakeRateTokenLocked();
    bool ShouldStop() const;
    void SleepBackoff(int ms);
    void FinalDrain();
    void RecordError(const std::string& text);

    size_t QueueDepth();
    unsigned long long DroppedTotal();

    ProbeConfig cfg_;
    ws::Client client_;

    std::mutex queueMutex_;
    std::condition_variable queueCv_;
    std::deque<std::string> queue_;

    std::atomic<bool> paused_{ false };
    std::atomic<int> rate_{ 0 };
    // Adjustable at runtime by config.update (reader thread) while the sender
    // reads it; a plain size_t would be a data race.
    std::atomic<size_t> batchEvents_{ 200 };
    std::atomic<bool> connectionLost_{ false };
    std::atomic<bool> readerStop_{ false };

    // metrics
    std::atomic<unsigned long long> sentEvents_{ 0 };
    std::atomic<unsigned long long> droppedQueue_{ 0 };
    std::atomic<unsigned long long> droppedRate_{ 0 };
    std::atomic<unsigned long long> droppedPaused_{ 0 };
    std::atomic<unsigned long long> parseErrors_{ 0 };
    std::atomic<unsigned long long> reconnects_{ 0 };
    std::atomic<unsigned long long> seq_{ 0 };
    std::atomic<unsigned long long> eventCounter_{ 0 };

    // session state, written by the worker before the reader starts
    std::string sessionId_;
    size_t serverMaxEvents_ = 500;
    size_t serverMaxBytes_ = 1024 * 1024;
    std::string bootId_;
    std::string hostname_;
    std::string osVersion_;
    std::chrono::steady_clock::time_point startedAt_;

    // rate limiter state (guarded by queueMutex_)
    double rateTokens_ = 0.0;
    std::chrono::steady_clock::time_point rateWindowStart_;

    std::thread worker_;
    std::mutex lastErrorMutex_;
    std::string lastError_;
};

} // namespace channel
} // namespace kellect
