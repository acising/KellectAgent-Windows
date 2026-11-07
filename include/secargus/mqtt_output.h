#pragma once
//
// SecArgus MQTT output sink.
//
// Runs entirely off the ETW callback: the tee hands it JSON batch blobs; it
// splits lines, builds protocol envelopes, spools them to disk, publishes over
// MQTT QoS1 and waits for the backend's business ACK before deleting the spool
// file (design doc §9.3 / §11).
//
// Failure isolation: if the broker is unreachable, only this sink degrades; the
// file/console sinks keep working and the ETW pipeline is unaffected.
//
#include <chrono>
#include <condition_variable>
#include <deque>
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "secargus/mqtt_client.h"
#include "secargus/batch.h"
#include "secargus/commands.h"
#include "secargus/config.h"
#include "output/output.h"

namespace kellect {
namespace secargus {

class MqttOutput : public Output {
public:
    MqttOutput(MqttSettings settings, EndpointIdentity identity,
               CollectionInfo collection);
    ~MqttOutput() override;

    STATUS init() override;
    void output(std::string outputString) override;
    void waitFlushed(int timeoutMs) override;

private:
    struct Inflight {
        uint64_t sequence = 0;
        std::string batchId;
        std::string payload;
        std::chrono::steady_clock::time_point sentAt{};
        int retries = 0;
        size_t events = 0;
        bool published = false;
    };

    void worker();
    bool connectAndSubscribe(std::string& error);
    void flushLocked();                       // builds+spools the current batch
    bool takeNextUnpublished(Inflight& out);  // copy of the next batch to send
    void markPublished(const std::string& batchId);
    void markSendFailed(const std::string& batchId);
    void handleInbox(const std::vector<MqttClient::Incoming>& inbox);
    void handleAck(const std::string& payload);
    void retryDueBatches();
    void publishReply(const std::string& payload);

    // status/metrics (design doc §9.4/§9.5)
    std::string buildStatusJson(const char* state) const;
    bool publishStatus();
    bool publishMetrics();
    void noteError(const std::string& error);
    std::string lastError() const;

    MqttSettings settings_;
    EndpointIdentity identity_;
    CollectionInfo collection_;
    MqttClient client_;
    SpoolStore spool_;
    BatchBuilder builder_;
    std::unique_ptr<CommandProcessor> commands_;

    std::string eventsTopic_;
    std::string acksTopic_;
    std::string statusTopic_;
    std::string metricsTopic_;
    std::string commandsTopic_;
    std::string repliesTopic_;
    std::string willPayload_;

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<Inflight> inflight_;
    std::thread worker_;
    std::atomic<bool> stop_{ false };

    uint64_t nextSequence_ = 1;
    std::chrono::steady_clock::time_point lastFlush_{};
    std::chrono::steady_clock::time_point lastConnectAttempt_{};
    std::chrono::steady_clock::time_point lastStatus_{};
    std::chrono::steady_clock::time_point lastMetrics_{};

    mutable std::mutex errorMutex_;
    std::string lastError_;
    unsigned long long sampleEvents_ = 0;
    std::chrono::steady_clock::time_point sampleAt_{};

    std::atomic<unsigned long long> eventsEnqueued_{ 0 };
    std::atomic<unsigned long long> eventsDropped_{ 0 };
    std::atomic<unsigned long long> batchesCreated_{ 0 };
    std::atomic<unsigned long long> batchesAcked_{ 0 };
    std::atomic<unsigned long long> batchesRejected_{ 0 };
    std::atomic<unsigned long long> batchesRetried_{ 0 };
    std::atomic<unsigned long long> batchesDropped_{ 0 };
    std::atomic<unsigned long long> publishErrors_{ 0 };
    std::atomic<unsigned long long> reconnects_{ 0 };
};

} // namespace secargus
} // namespace kellect
