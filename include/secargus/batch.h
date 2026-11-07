#pragma once
//
// Event batching and the durable spool for the SecArgus MQTT output.
//
// A batch is the protocol envelope (design doc §9.2). The events array contains
// the raw Kellect JSON lines byte-for-byte, so the original fields
// (Event/PID/TID/TimeStamp/Host-UUID/args) are never rewritten.
//
// Spool: one file per batch (`<sequence>.batch`), written atomically before the
// publish attempt. A batch file is deleted only after the backend ACK
// (persisted/duplicate) - MQTT QoS1 PUBACK alone is not enough.
//
#include <cstdint>
#include <string>
#include <vector>

#include "secargus/config.h"

namespace kellect {
namespace secargus {

class BatchBuilder {
public:
    BatchBuilder(const MqttSettings& settings, std::string endpointId, std::string hostUuid);

    // false => line is not a JSON object (never expected from the pipeline, but
    // a malformed event must not corrupt the batch).
    bool AddLine(const std::string& line);

    size_t EventCount() const { return lines_.size(); }
    size_t Bytes() const { return bytes_; }
    bool Empty() const { return lines_.empty(); }

    bool ShouldFlushBySize() const;

    // Builds the envelope, clears the batch. `batchId` is echoed back for spool
    // bookkeeping. `sequence` must be allocated by the caller (SpoolStore keeps
    // it persistent across restarts).
    std::string Build(uint64_t sequence, std::string& batchId);

    void Clear();

private:
    MqttSettings settings_;
    std::string endpointId_;
    std::string hostUuid_;
    std::vector<std::string> lines_;
    size_t bytes_ = 0;
};

struct SpoolEntry {
    uint64_t sequence = 0;
    std::string batchId;
    std::string path;
    std::string payload;
};

class SpoolStore {
public:
    bool Open(const std::string& directory, std::string& error);

    bool Put(const SpoolEntry& entry, std::string& error);
    void Remove(uint64_t sequence);

    // Sorted by sequence; used on startup to resume sending.
    std::vector<SpoolEntry> LoadPending() const;

    // Reads one batch payload back (used instead of keeping every payload in
    // memory: the spool is the source of truth).
    bool Read(uint64_t sequence, std::string& payload) const;

    size_t Count() const;
    long long Bytes() const;

    // Monotonic sequence across restarts (state.txt in the spool directory).
    uint64_t LoadNextSequence() const;
    void SaveNextSequence(uint64_t sequence) const;

    const std::string& directory() const { return directory_; }

private:
    std::string PathFor(uint64_t sequence) const;

    std::string directory_;
};

} // namespace secargus
} // namespace kellect
