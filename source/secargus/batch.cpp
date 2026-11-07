#include "secargus/batch.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>

#include "secargus/util.h"

namespace kellect {
namespace secargus {

BatchBuilder::BatchBuilder(const MqttSettings& settings, std::string endpointId,
                           std::string hostUuid)
    : settings_(settings), endpointId_(std::move(endpointId)),
      hostUuid_(std::move(hostUuid)) {}

bool BatchBuilder::AddLine(const std::string& line) {
    if (line.size() < 2 || line.front() != '{' || line.back() != '}')
        return false;
    // A single event must never blow the batch budget on its own: the backend
    // would reject the whole frame. Skip it and let the caller count the drop.
    if (static_cast<int>(line.size()) + 2 > settings_.maxBatchBytes)
        return false;

    lines_.push_back(line);
    bytes_ += line.size() + 1;   // + comma
    return true;
}

bool BatchBuilder::ShouldFlushBySize() const {
    return static_cast<int>(lines_.size()) >= settings_.maxBatchEvents ||
           static_cast<long long>(bytes_) >= settings_.maxBatchBytes;
}

void BatchBuilder::Clear() {
    lines_.clear();
    bytes_ = 0;
}

std::string BatchBuilder::Build(uint64_t sequence, std::string& batchId) {
    std::string array;
    for (size_t i = 0; i < lines_.size(); ++i) {
        if (i != 0) array.push_back(',');
        array += lines_[i];
    }
    array = "[" + array + "]";

    char seqText[32];
    snprintf(seqText, sizeof(seqText), "%010llu",
             static_cast<unsigned long long>(sequence));
    batchId = endpointId_ + "-" + seqText;

    std::string out;
    out.reserve(array.size() + 512);
    out += "{\"protocol_version\":\"1.0\",\"message_type\":\"event_batch\"";
    out += ",\"endpoint_id\":\"" + JsonEscape(endpointId_) + "\"";
    out += ",\"host_uuid\":\"" + JsonEscape(hostUuid_) + "\"";
    out += ",\"batch_id\":\"" + JsonEscape(batchId) + "\"";
    out += ",\"sequence_number\":" + std::to_string(sequence);
    out += ",\"sent_at\":\"" + IsoNowUtc() + "\"";
    out += ",\"payload_format\":\"kellect-json\"";
    out += ",\"compression_codec\":\"none\"";
    out += ",\"time_base\":\"filetime-100ns-since-1601\"";
    out += ",\"event_count\":" + std::to_string(lines_.size());
    out += ",\"payload_sha256\":\"" + Sha256Hex(array) + "\"";
    out += ",\"events\":" + array;
    out += "}";

    Clear();
    return out;
}

bool SpoolStore::Open(const std::string& directory, std::string& error) {
    directory_ = directory;
    if (!EnsureDirectory(directory_)) {
        error = "cannot create spool directory " + directory_;
        return false;
    }
    return true;
}

std::string SpoolStore::PathFor(uint64_t sequence) const {
    char name[64];
    snprintf(name, sizeof(name), "\\%020llu.batch",
             static_cast<unsigned long long>(sequence));
    return directory_ + name;
}

bool SpoolStore::Put(const SpoolEntry& entry, std::string& error) {
    if (!EnsureDirectory(directory_)) {
        error = "spool directory unavailable";
        return false;
    }
    return WriteFileAtomic(PathFor(entry.sequence), entry.payload, error);
}

void SpoolStore::Remove(uint64_t sequence) {
    DeleteFileA(PathFor(sequence).c_str());
}

std::vector<SpoolEntry> SpoolStore::LoadPending() const {
    std::vector<SpoolEntry> entries;

    WIN32_FIND_DATAA data;
    const std::string pattern = directory_ + "\\*.batch";
    HANDLE handle = FindFirstFileA(pattern.c_str(), &data);
    if (handle == INVALID_HANDLE_VALUE)
        return entries;

    do {
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        const std::string name = data.cFileName;
        const size_t dot = name.find('.');
        if (dot == std::string::npos)
            continue;

        SpoolEntry entry;
        entry.sequence = strtoull(name.substr(0, dot).c_str(), nullptr, 10);
        entry.path = directory_ + "\\" + name;

        std::ifstream in(entry.path, std::ios::binary);
        if (!in.is_open())
            continue;
        std::ostringstream buffer;
        buffer << in.rdbuf();
        entry.payload = buffer.str();
        if (entry.payload.empty())
            continue;

        entries.push_back(std::move(entry));
    } while (FindNextFileA(handle, &data));

    FindClose(handle);

    std::sort(entries.begin(), entries.end(),
              [](const SpoolEntry& a, const SpoolEntry& b) {
                  return a.sequence < b.sequence;
              });
    return entries;
}

bool SpoolStore::Read(uint64_t sequence, std::string& payload) const {
    std::ifstream in(PathFor(sequence), std::ios::binary);
    if (!in.is_open())
        return false;
    std::ostringstream buffer;
    buffer << in.rdbuf();
    payload = buffer.str();
    return !payload.empty();
}

size_t SpoolStore::Count() const {    size_t count = 0;
    WIN32_FIND_DATAA data;
    HANDLE handle = FindFirstFileA((directory_ + "\\*.batch").c_str(), &data);
    if (handle == INVALID_HANDLE_VALUE)
        return 0;
    do {
        if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            ++count;
    } while (FindNextFileA(handle, &data));
    FindClose(handle);
    return count;
}

long long SpoolStore::Bytes() const {
    long long total = 0;
    WIN32_FIND_DATAA data;
    HANDLE handle = FindFirstFileA((directory_ + "\\*.batch").c_str(), &data);
    if (handle == INVALID_HANDLE_VALUE)
        return 0;
    do {
        if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            total += (static_cast<long long>(data.nFileSizeHigh) << 32) +
                     data.nFileSizeLow;
    } while (FindNextFileA(handle, &data));
    FindClose(handle);
    return total;
}

uint64_t SpoolStore::LoadNextSequence() const {
    std::ifstream in(directory_ + "\\state.txt");
    if (!in.is_open())
        return 1;
    unsigned long long seq = 0;
    in >> seq;
    return seq == 0 ? 1 : seq;
}

void SpoolStore::SaveNextSequence(uint64_t sequence) const {
    std::string error;
    WriteFileAtomic(directory_ + "\\state.txt", std::to_string(sequence), error);
}

} // namespace secargus
} // namespace kellect
