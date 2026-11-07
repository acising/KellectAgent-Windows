#include "secargus/mqtt_output.h"
#include "secargus/mqtt_stats.h"

#include <windows.h>

#include <algorithm>

#include "nlohmann/json.hpp"
#include "secargus/util.h"
#include "tools/logger.h"
#include "tools/stats.h"

namespace kellect {
namespace secargus {

namespace {
const char* const kAgentVersion = "vnext-0.1.0";

size_t CountBatchEvents(const std::string& payload) {
    try {
        const auto doc = nlohmann::json::parse(payload);
        const auto it = doc.find("events");
        return it != doc.end() && it->is_array() ? it->size() : 0;
    } catch (...) {
        return 0;
    }
}
}

MqttOutput::MqttOutput(MqttSettings settings, EndpointIdentity identity,
                       CollectionInfo collection)
    : settings_(std::move(settings)), identity_(std::move(identity)),
      collection_(std::move(collection)),
      builder_(settings_, identity_.endpointId, identity_.hostUuid) {}

MqttOutput::~MqttOutput() {
    stop_.store(true);
    cv_.notify_all();
    // Close before joining: a worker blocked in PUBACK wait must be unblocked,
    // otherwise shutdown stalls for the full publish timeout.
    client_.Close();
    if (worker_.joinable())
        worker_.join();
}

STATUS MqttOutput::init() {
    std::string error;

    if (!spool_.Open(settings_.spoolDirectory, error)) {
        MyLogger::writeLog("secargus: " + error);
        return STATUS_FILE_OPEN_FAILED;
    }

    eventsTopic_ = BuildTopic(settings_, identity_.endpointId, "events");
    acksTopic_ = BuildTopic(settings_, identity_.endpointId, "acks");
    statusTopic_ = BuildTopic(settings_, identity_.endpointId, "status");
    metricsTopic_ = BuildTopic(settings_, identity_.endpointId, "metrics");
    commandsTopic_ = BuildTopic(settings_, identity_.endpointId, "commands");
    repliesTopic_ = BuildTopic(settings_, identity_.endpointId, "replies");

    // Command channel (design doc §9.6): whitelist + validation + idempotency.
    CommandProcessor::Context commandContext;
    commandContext.settings = settings_;
    commandContext.identity = identity_;
    commandContext.collection = collection_;
    commandContext.statusJson = [this] { return buildStatusJson("collecting"); };
    commandContext.metricsJson = [this] {
        nlohmann::json doc = nlohmann::json::parse(buildStatusJson("collecting"));
        doc["message_type"] = "metrics";
        return doc.dump();
    };
    commands_.reset(new CommandProcessor(std::move(commandContext)));

    // Last Will: the broker publishes this (retained) if we disconnect without
    // a clean shutdown, so a crashed agent does not look "online" forever.
    nlohmann::json will = {
        { "protocol_version", "1.0" },
        { "message_type", "status" },
        { "endpoint_id", identity_.endpointId },
        { "host_uuid", identity_.hostUuid },
        { "collection", { { "state", "unknown" } } },
        { "mqtt", { { "state", "offline" } } },
        { "sent_at", IsoNowUtc() },
    };
    willPayload_ = will.dump();

    // Resume anything left from a previous run before accepting new events.
    // Payloads stay on disk and are read back when sent, so a large spool does
    // not turn into a large resident set.
    std::vector<SpoolEntry> pending = spool_.LoadPending();
    for (const SpoolEntry& entry : pending) {
        Inflight item;
        item.sequence = entry.sequence;
        inflight_.push_back(std::move(item));
    }
    nextSequence_ = spool_.LoadNextSequence();
    for (const SpoolEntry& entry : pending) {
        if (entry.sequence >= nextSequence_)
            nextSequence_ = entry.sequence + 1;
    }

    lastFlush_ = std::chrono::steady_clock::now();
    lastConnectAttempt_ = lastFlush_ - std::chrono::seconds(60);

    worker_ = std::thread(&MqttOutput::worker, this);
    setInit(true);

    MyLogger::writeLog("secargus: mqtt sink ready, " + std::to_string(pending.size()) +
                       " spooled batch(es), topic " + eventsTopic_);
    return STATUS_SUCCESS;
}


std::atomic<uint64_t> g_mqttSent{ 0 };
std::atomic<uint64_t> g_mqttEventsSent{ 0 };
std::atomic<uint64_t> g_mqttEventsAcked{ 0 };
std::atomic<uint64_t> g_mqttAcked{ 0 };
std::atomic<uint64_t> g_mqttSpool{ 0 };
std::atomic<uint64_t> g_mqttDropped{ 0 };
std::atomic<bool> g_mqttConnected{ false };

void MqttOutput::output(std::string outputString) {
    std::lock_guard<std::mutex> lock(mutex_);

    size_t start = 0;
    while (start < outputString.size()) {
        const size_t end = outputString.find('\n', start);
        std::string line = outputString.substr(
            start, (end == std::string::npos ? outputString.size() : end) - start);
        start = (end == std::string::npos) ? outputString.size() : end + 1;

        if (line.empty())
            continue;
        if (!builder_.AddLine(line)) {
            eventsDropped_.fetch_add(1);
            continue;
        }
        eventsEnqueued_.fetch_add(1);

        if (builder_.ShouldFlushBySize())
            flushLocked();
    }

    cv_.notify_one();
}

void MqttOutput::flushLocked() {
    if (builder_.Empty())
        return;

    const uint64_t sequence = nextSequence_++;
    const size_t eventCount = builder_.EventCount();
    std::string batchId;
    std::string payload = builder_.Build(sequence, batchId);

    Inflight item;
    item.sequence = sequence;
    item.batchId = batchId;
    item.payload = payload;
    item.events = eventCount;

    SpoolEntry spoolEntry;
    spoolEntry.sequence = sequence;
    spoolEntry.batchId = batchId;
    spoolEntry.path = spool_.directory();
    spoolEntry.payload = payload;

    std::string error;
    // Capacity guard: never grow the spool without bound. Dropping here is
    // explicit and counted (status/metrics report it); silently claiming
    // lossless delivery would be worse.
    if (settings_.maxSpoolBytes > 0 &&
        spool_.Bytes() + static_cast<long long>(payload.size()) > settings_.maxSpoolBytes) {
        eventsDropped_.fetch_add(eventCount);
        batchesDropped_.fetch_add(1);
        MyLogger::writeLog("secargus: spool full, batch dropped (max_spool_bytes=" +
                           std::to_string(settings_.maxSpoolBytes) + ")");
        return;
    }

    if (!spool_.Put(spoolEntry, error)) {
        // Cannot spool => do not pretend it will be delivered.
        eventsDropped_.fetch_add(eventCount);
        publishErrors_.fetch_add(1);
        MyLogger::writeLog("secargus: spool write failed: " + error);
        return;
    }
    spool_.SaveNextSequence(nextSequence_);

    inflight_.push_back(std::move(item));
    batchesCreated_.fetch_add(1);
    lastFlush_ = std::chrono::steady_clock::now();
}

bool MqttOutput::connectAndSubscribe(std::string& error) {
    MqttClient::Will will;
    will.enabled = settings_.statusIntervalS > 0;
    will.topic = statusTopic_;
    will.payload = willPayload_;
    will.qos = 1;
    will.retain = true;

    if (!client_.Connect(settings_, identity_.clientId, will, error))
        return false;
    if (!client_.Subscribe(acksTopic_, 1, error)) {
        client_.Close();
        return false;
    }
    if (!client_.Subscribe(commandsTopic_, 1, error)) {
        client_.Close();
        return false;
    }

    reconnects_.fetch_add(1);
    noteError("");
    g_mqttConnected.store(true);
    // Publish status/metrics immediately after (re)connecting.
    const auto longAgo = std::chrono::steady_clock::now() - std::chrono::hours(1);
    lastStatus_ = longAgo;
    lastMetrics_ = longAgo;
    sampleEvents_ = kellect::stats::eventsReceived.load();
    sampleAt_ = std::chrono::steady_clock::now();
    return true;
}

std::string MqttOutput::lastError() const {
    std::lock_guard<std::mutex> lock(errorMutex_);
    return lastError_;
}

void MqttOutput::noteError(const std::string& error) {
    std::lock_guard<std::mutex> lock(errorMutex_);
    lastError_ = error;
}

std::string MqttOutput::buildStatusJson(const char* state) const {
    nlohmann::json lastErr = nullptr;
    const std::string last = lastError();
    if (!last.empty())
        lastErr = last;

    nlohmann::json doc;
    doc["protocol_version"] = "1.0";
    doc["message_type"] = "status";
    doc["endpoint_id"] = identity_.endpointId;
    doc["host_uuid"] = identity_.hostUuid;
    doc["agent_version"] = kAgentVersion;
    doc["kellect_version"] = identity_.kellectVersion;
    doc["communication_version"] = identity_.communicationVersion;
    doc["collection"] = {
        { "state", state },
        { "events_received", kellect::stats::eventsReceived.load() },
        { "events_filtered", kellect::stats::eventsFiltered.load() },
        { "events_parsed", kellect::stats::eventsParsed.load() },
        { "events_lost", kellect::stats::etwEventsLost.load() },
    };
    doc["mqtt"] = {
        { "state", client_.IsConnected() ? "connected" : "disconnected" },
        { "broker", settings_.host + ":" + std::to_string(settings_.port) },
        { "last_error", lastErr },
    };
    doc["spool"] = {
        { "batches", spool_.Count() },
        { "bytes", spool_.Bytes() },
        { "max_bytes", settings_.maxSpoolBytes },
    };
    doc["transport"] = {
        { "batches_created", batchesCreated_.load() },
        { "batches_acked", batchesAcked_.load() },
        { "batches_rejected", batchesRejected_.load() },
        { "batches_retried", batchesRetried_.load() },
        { "batches_dropped", batchesDropped_.load() },
        { "publish_errors", publishErrors_.load() },
        { "reconnects", reconnects_.load() },
        { "events_dropped", eventsDropped_.load() },
    };
    doc["degraded"] = batchesDropped_.load() > 0 || eventsDropped_.load() > 0;
    doc["sent_at"] = IsoNowUtc();
    return doc.dump();
}

bool MqttOutput::publishStatus() {
    if (!client_.IsConnected())
        return false;

    std::vector<MqttClient::Incoming> inbox;
    std::string error;
    if (!client_.Publish(statusTopic_, buildStatusJson("collecting"), 1, true,
                         inbox, error)) {
        noteError("status publish: " + error);
        publishErrors_.fetch_add(1);
        client_.Close();
        return false;
    }
    handleInbox(inbox);
    return true;
}

bool MqttOutput::publishMetrics() {
    if (!client_.IsConnected())
        return false;

    const auto now = std::chrono::steady_clock::now();
    const double windowSeconds = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - sampleAt_).count() / 1000.0;
    const unsigned long long received = kellect::stats::eventsReceived.load();
    const double rate = windowSeconds > 0.5
                            ? (received - sampleEvents_) / windowSeconds
                            : 0.0;
    sampleEvents_ = received;
    sampleAt_ = now;

    nlohmann::json doc = nlohmann::json::parse(buildStatusJson("collecting"));
    doc["message_type"] = "metrics";
    doc["window_s"] = windowSeconds;
    doc["events_per_s"] = rate;

    std::vector<MqttClient::Incoming> inbox;
    std::string error;
    // QoS0: metrics are advisory; never let them block event delivery.
    if (!client_.Publish(metricsTopic_, doc.dump(), 0, false, inbox, error)) {
        noteError("metrics publish: " + error);
        publishErrors_.fetch_add(1);
        return false;
    }
    handleInbox(inbox);
    return true;
}

bool MqttOutput::takeNextUnpublished(Inflight& out) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = inflight_.begin(); it != inflight_.end(); ++it) {
        if (it->published)
            continue;

        out = *it;
        if (out.payload.empty() && !spool_.Read(out.sequence, out.payload)) {
            // Spool file vanished: nothing to send, drop the bookkeeping.
            inflight_.erase(it);
            publishErrors_.fetch_add(1);
            return false;
        }
        return true;
    }
    return false;
}

void MqttOutput::markPublished(const std::string& batchId) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (Inflight& item : inflight_) {
        if (item.batchId == batchId) {
            item.published = true;
            g_mqttSent.fetch_add(1);
            g_mqttEventsSent.fetch_add(item.events);
            item.sentAt = std::chrono::steady_clock::now();
            item.payload.clear();   // free memory; the spool holds the bytes
            return;
        }
    }
}

void MqttOutput::markSendFailed(const std::string& batchId) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (Inflight& item : inflight_) {
        if (item.batchId == batchId) {
            item.published = false;
            return;
        }
    }
}

void MqttOutput::handleAck(const std::string& payload) {
    nlohmann::json ack = nlohmann::json::parse(payload, nullptr, false);
    if (ack.is_discarded() || !ack.is_object())
        return;

    const std::string batchId = ack.value("batch_id", std::string());
    const std::string status = ack.value("status", std::string());
    if (batchId.empty())
        return;

    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = inflight_.begin(); it != inflight_.end(); ++it) {
        if (it->batchId != batchId)
            continue;

        if (status == "persisted" || status == "duplicate") {
            spool_.Remove(it->sequence);
            inflight_.erase(it);
            batchesAcked_.fetch_add(1);
            g_mqttAcked.fetch_add(1);
            g_mqttEventsAcked.fetch_add(it->events);
        } else if (status == "rejected") {
            spool_.Remove(it->sequence);
            inflight_.erase(it);
            batchesRejected_.fetch_add(1);
        }
        // "retry" / unknown: keep it; the timeout path republishes.
        return;
    }
}

void MqttOutput::handleInbox(const std::vector<MqttClient::Incoming>& inbox) {
    for (const MqttClient::Incoming& message : inbox) {
        if (message.topic == acksTopic_) {
            handleAck(message.payload);
        } else if (message.topic == commandsTopic_ && commands_) {
            const std::string reply =
                commands_->Handle(message.payload, message.retained);
            if (!reply.empty())
                publishReply(reply);
        }
    }
}

void MqttOutput::publishReply(const std::string& payload) {
    if (!client_.IsConnected())
        return;

    std::vector<MqttClient::Incoming> inbox;
    std::string error;
    if (!client_.Publish(repliesTopic_, payload, 1, false, inbox, error)) {
        noteError("reply publish: " + error);
        publishErrors_.fetch_add(1);
        return;
    }
    // Only ACKs are handled here; commands are not re-entered from a reply.
    for (const MqttClient::Incoming& message : inbox) {
        if (message.topic == acksTopic_)
            handleAck(message.payload);
    }
}

void MqttOutput::retryDueBatches() {
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mutex_);
    for (Inflight& item : inflight_) {
        if (!item.published)
            continue;
        const auto age = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - item.sentAt).count();
        if (age < settings_.ackTimeoutMs)
            continue;

        if (item.retries >= settings_.maxRetries) {
            // Give up publishing but keep the spool file: it is still the only
            // copy of the data, and the status/metrics surface the backlog.
            continue;
        }
        item.published = false;   // picked up again by the sender loop
        ++item.retries;
        batchesRetried_.fetch_add(1);
    }
}

void MqttOutput::worker() {
    int backoffMs = 1000;

    while (!stop_.load()) {
        // Time-based flush first: it only writes the spool, so it must also run
        // while the broker is unreachable (a partial batch must not sit in RAM).
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!builder_.Empty()) {
                const auto age = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - lastFlush_).count();
                if (age >= settings_.flushIntervalMs)
                    flushLocked();
            }
        }

        if (!client_.IsConnected()) {
            const auto now = std::chrono::steady_clock::now();
            const auto since = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - lastConnectAttempt_).count();
            if (since >= backoffMs) {
                lastConnectAttempt_ = now;
                std::string error;
                if (connectAndSubscribe(error)) {
                    backoffMs = 1000;
                } else {
                    noteError("mqtt connect: " + error);
                    MyLogger::writeLog("secargus: mqtt connect failed: " + error);
                    backoffMs = (std::min)(backoffMs * 2, 30000);
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        client_.KeepAlive();

        // Age out batches whose business ACK never arrived. Runs even when new
        // batches are flowing, not only when the send queue is empty.
        retryDueBatches();

        // Periodic status/metrics (design doc §9.4/§9.5).
        const auto now = std::chrono::steady_clock::now();
        if (settings_.statusIntervalS > 0 &&
            now - lastStatus_ >= std::chrono::seconds(settings_.statusIntervalS)) {
            if (publishStatus())
                lastStatus_ = now;
            else
                continue;
        }
        if (settings_.metricsIntervalS > 0 &&
            now - lastMetrics_ >= std::chrono::seconds(settings_.metricsIntervalS)) {
            if (publishMetrics())
                lastMetrics_ = now;
        }

        // Publish the next unsent batch. Publishing happens outside the mutex.
        Inflight toSend;
        if (takeNextUnpublished(toSend)) {
            std::vector<MqttClient::Incoming> inbox;
            std::string error;
            if (client_.Publish(eventsTopic_, toSend.payload, settings_.qos, false,
                                inbox, error)) {
                markPublished(toSend.batchId);
            } else {
                publishErrors_.fetch_add(1);
                markSendFailed(toSend.batchId);
                if (error != "timeout" && error != "PUBACK timeout") {
                    client_.Close();
                }
                // Do not spin: a broker that accepted TCP but stopped answering
                // must not burn a core.
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
            handleInbox(inbox);
            continue;
        }

        // Nothing to send: pump inbound (business ACKs) for a short while.
        std::vector<MqttClient::Incoming> inbox;
        std::string error;
        if (client_.Pump(inbox, 50, error)) {
            handleInbox(inbox);
        } else if (error != "timeout") {
            client_.Close();
        }

        g_mqttConnected.store(client_.IsConnected());
        g_mqttSpool.store(spool_.Count());
        {
            std::unique_lock<std::mutex> lock(mutex_);
            if (inflight_.empty() && builder_.Empty())
                cv_.wait_for(lock, std::chrono::milliseconds(50));
        }
    }
}

void MqttOutput::waitFlushed(int timeoutMs) {
    // Flush whatever is buffered, then wait for the in-flight batches to be
    // ACKed (bounded).
    {
        std::lock_guard<std::mutex> lock(mutex_);
        flushLocked();
    }

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (inflight_.empty())
                break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

} // namespace secargus
} // namespace kellect
