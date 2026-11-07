#include "runtime/evidence.h"

#include <tdh.h>
#include <objbase.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include "nlohmann/json.hpp"
#include "process/module_history.h"
#include "process/stack_capture.h"
#include "schema/schema.h"
#include "tools/ConcurrentQueue.h"
#include "tools/stats.h"
#include "tools/tools.h"

namespace kellect {
namespace evidence {
namespace {

using nlohmann::json;
using Bytes = std::vector<unsigned char>;
constexpr size_t kQueueBytes = 32 * 1024 * 1024;
constexpr size_t kQueueRecords = 16384;
constexpr uint64_t kAssociationWindow = 4096;
constexpr size_t kCatalogLimit = 4096;
constexpr size_t kPendingFrameLimit = 65536;
constexpr size_t kPendingStackLimit = 8192;
constexpr size_t kHotImageLimit = 4096;
constexpr size_t kRecommendedImages = 32;

size_t Index(Source source) { return static_cast<size_t>(source); }
const char* Name(Source source) { return source == Source::Kernel ? "kernel_etw" : "user_etw"; }

std::string GuidString(const GUID& guid) {
    char str[37];
    std::snprintf(str, sizeof(str), "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                  guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1],
                  guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5],
                  guid.Data4[6], guid.Data4[7]);
    return str;
}

std::string Hex(const void* data, size_t size) {
    const auto* bytes = static_cast<const unsigned char*>(data);
    const char digits[] = "0123456789abcdef";
    std::string result(2 * size, '0');
    for (size_t i = 0; i < size; ++i) {
        result[2 * i] = digits[bytes[i] >> 4];
        result[2 * i + 1] = digits[bytes[i] & 15];
    }
    return result;
}

std::string Address(uint64_t ip) {
    char str[19];
    std::snprintf(str, sizeof(str), "0x%016llx", static_cast<unsigned long long>(ip));
    return str;
}

std::string Utf8(const wchar_t* value, size_t count) {
    const int chars = static_cast<int>(count);
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, chars,
                                        nullptr, 0, nullptr, nullptr);
    if (!size)
        return {};
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, chars,
                        &result[0], size, nullptr, nullptr);
    return result;
}

std::string ProviderName(const Bytes& bytes, ULONG offset) {
    if (offset >= bytes.size() || offset % sizeof(wchar_t))
        return {};
    const auto* name = reinterpret_cast<const wchar_t*>(bytes.data() + offset);
    const size_t capacity = (bytes.size() - offset) / sizeof(wchar_t);
    size_t count = 0;
    while (count < capacity && name[count])
        ++count;
    if (!count || count == capacity)
        return {};
    return Utf8(name, count);
}

struct RawRecord {
    Source source = Source::Kernel;
    uint64_t seq = 0;
    unsigned clock = 0;
    unsigned pointerBytes = 0;
    size_t budget = 0;
    EVENT_HEADER header{};
    ETW_BUFFER_CONTEXT buffer{};
    Bytes payload;
    std::vector<EVENT_HEADER_EXTENDED_DATA_ITEM> items;
    Bytes extended;
};

struct SourceCounters {
    uint64_t received = 0;
    uint64_t queueDropped = 0;
    uint64_t copyFailed = 0;
    uint64_t firstDropped = 0;
    uint64_t lastDropped = 0;
    uint64_t observed = 0;
    uint64_t catalogOverflow = 0;
};

struct CatalogEntry {
    GUID provider{};
    EVENT_DESCRIPTOR descriptor{};
    USHORT headerFlags = 0;
    uint64_t observed = 0;
    uint64_t stacks = 0;
    ULONG metadataStatus = ERROR_NOT_FOUND;
    ULONG propertyCount = 0;
};

struct StackKey {
    uint64_t time;
    uint32_t pid;
    uint32_t tid;
    bool operator<(const StackKey& other) const {
        return std::tie(time, pid, tid) < std::tie(other.time, other.pid, other.tid);
    }
};

struct TimedKey {
    uint64_t seq;
    StackKey key;
};

struct PendingStack {
    TimedKey event;
    int extendedIndex;
    unsigned pointerBytes;
    std::vector<uint64_t> frames;
};

// Turn common ETW paths into paths that the legacy initImages reader can
// consume. All lookups are for this machine's drive aliases.
class LocalImagePaths {
public:
    LocalImagePaths() {
        wchar_t windows[MAX_PATH];
        const UINT size = GetWindowsDirectoryW(windows, MAX_PATH);
        if (size && size < MAX_PATH)
            aliases_.emplace_back(L"\\SystemRoot", windows);
        const DWORD drives = GetLogicalDrives();
        for (unsigned i = 0; i < 26; ++i) {
            if (!(drives & (1u << i)))
                continue;
            const wchar_t drive[] = {static_cast<wchar_t>(L'A' + i), L':', 0};
            wchar_t target[4096];
            if (QueryDosDeviceW(drive, target, 4096))
                aliases_.emplace_back(target, drive);
        }
    }

    std::string Translate(const std::wstring& raw) const {
        auto path = raw;
        if (path.compare(0, 4, L"\\??\\") == 0)
            path.erase(0, 4);
        for (const auto& alias : aliases_) {
            const auto len = alias.first.size();
            if (path.size() > len && path[len] == L'\\' &&
                CompareStringOrdinal(path.data(), static_cast<int>(len), alias.first.data(),
                                     static_cast<int>(len), TRUE) == CSTR_EQUAL) {
                path.replace(0, len, alias.second);
                break;
            }
        }
        if (path.size() < 4 || path[1] != L':' || path[2] != L'\\' ||
            !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) ||
            path.find_first_of(L"\r\n") != std::wstring::npos)
            return {};
        return Utf8(path.data(), path.size());
    }

private:
    std::vector<std::pair<std::wstring, std::wstring>> aliases_;
};

// All file I/O and JSON construction are owned by the archive worker.
class Journal {
public:
    ~Journal() { if (file_ != INVALID_HANDLE_VALUE) CloseHandle(file_); }

    bool Open(const std::string& path) {
        file_ = CreateFileA(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        return file_ != INVALID_HANDLE_VALUE;
    }

    void Write(const json& record) {
        if (error == ERROR_SUCCESS) {
            buffer_ += record.dump();
            buffer_ += '\n';
            ++pending_;
            if (buffer_.size() >= 256 * 1024)
                FlushBatch();
        } else {
            ++failed;
        }
    }

    void FlushBatch() {
        if (buffer_.empty())
            return;
        DWORD written = 0;
        const DWORD size = static_cast<DWORD>(buffer_.size());
        const BOOL ok = WriteFile(file_, buffer_.data(), size, &written, nullptr);
        if (!ok || written != size) {
            error = ok ? ERROR_WRITE_FAULT : GetLastError();
            failed += pending_;
            std::cerr << "Evidence journal write failed (" << error << ").\n";
        } else {
            persisted += pending_;
        }
        buffer_.clear();
        pending_ = 0;
    }

    bool Finish() {
        FlushBatch();
        return FlushFileBuffers(file_) && error == ERROR_SUCCESS;
    }

    uint64_t persisted = 0;
    uint64_t failed = 0;
    DWORD error = ERROR_SUCCESS;

private:
    HANDLE file_ = INVALID_HANDLE_VALUE;
    std::string buffer_;
    uint64_t pending_ = 0;
};

class Archive {
public:
    Archive() : queue_(kQueueRecords) {}
    bool Start(const std::string& directory, const std::string& profile,
               const std::string& hostUuid, ULONG flags, const GUID& provider, bool kernelEtl);
    uint64_t Capture(Source source, const EVENT_RECORD& record);
    bool Finish();
    const std::string& RunId() const { return run_; }
    const std::wstring& KernelEtlPath() const { return kernelEtlPath_; }
    bool replay = false;

    std::array<SessionStatus, 2> status;

private:
    void Work();
    void DiscoverProviders(const GUID& userProvider);
    void Process(RawRecord& record);
    void Observe(RawRecord& record, unsigned stacks);
    void WriteStack(const RawRecord& record, const CapturedStack& stack, int item);
    void ObserveLifecycle(const RawRecord& record);
    void ResolveFrames(const PendingStack& stack, bool drain);
    void WriteRecommendations();
    bool Reserve(size_t budget);
    void Expire(uint64_t seq, bool drain);

    std::array<SourceCounters, 2> counters_;
    std::array<std::map<std::string, CatalogEntry>, 2> catalog_;
    moodycamel::ConcurrentQueue<RawRecord> queue_;
    std::atomic<size_t> bytes_{0};
    std::atomic<size_t> records_{0};
    std::atomic<bool> stop_{false};
    std::condition_variable available_;
    std::mutex waitMutex_;
    std::thread worker_;
    std::map<StackKey, std::deque<uint64_t>> candidates_;
    std::deque<TimedKey> candidateOrder_;
    std::deque<PendingStack> pendingStacks_;
    ModuleHistory modules_;
    bool moduleScopeUnknown_ = false;
    size_t pendingFrames_ = 0;
    uint64_t invalidLifecycle_ = 0;
    uint64_t unsupportedLifecycle_ = 0;
    uint64_t resolvedFrames_ = 0;
    uint64_t unresolvedFrames_ = 0;
    uint64_t omittedFrames_ = 0;
    uint64_t untrackedHotFrames_ = 0;
    std::map<std::wstring, uint64_t> hotImages_;
    unsigned recommendations_ = 0;
    bool recommendationWriteFailed_ = false;
    std::string run_;
    std::string path_;
    std::wstring kernelEtlPath_;
    Journal raw_;
    Journal stacks_;
    Journal enrichment_;
    Journal report_;
    uint64_t processingErrors_ = 0;
};

std::unique_ptr<Archive> archive;
std::array<SessionStatus, 2> inactiveStatus;

bool Archive::Start(const std::string& directory, const std::string& profile,
                    const std::string& hostUuid, ULONG flags, const GUID& provider, bool kernelEtl) {
    GUID guid{};
    if (FAILED(CoCreateGuid(&guid)))
        return false;
    run_ = GuidString(guid);
    char absolute[MAX_PATH];
    const DWORD size = GetFullPathNameA(directory.c_str(), MAX_PATH, absolute, nullptr);
    if (!size || size >= MAX_PATH)
        return false;
    path_ = std::string(absolute) + "\\" + run_;
    if (kernelEtl) {
        const std::string etl = path_ + "\\kernel.etl";
        wchar_t wide[MAX_PATH];
        if (!MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, etl.c_str(), -1, wide, MAX_PATH))
            return false;
        kernelEtlPath_ = wide;
    }
    Tools::ensureParentDirectory(path_);
    if (!CreateDirectoryA(path_.c_str(), nullptr) ||
        !raw_.Open(path_ + "\\raw.jsonl") ||
        !stacks_.Open(path_ + "\\stacks.jsonl") ||
        !enrichment_.Open(path_ + "\\enrichment.jsonl") ||
        !report_.Open(path_ + "\\coverage.jsonl"))
        return false;
    const auto os = schema::DetectOs();
    report_.Write({{"record_type", "capture_start"}, {"schema_version", 1},
                   {"run_id", run_}, {"host_uuid", hostUuid}, {"profile", profile},
                   {"windows_build", os.build}, {"windows_ubr", os.ubr}, {"legacy_schema", os.schemaFile},
                   {"requested_kernel_flags", flags}, {"requested_user_provider", GuidString(provider)},
                   {"kernel_etl_requested", kernelEtl}, {"replay", replay},
                   {"association_window_records", kAssociationWindow},
                   {"queue_byte_limit", kQueueBytes}, {"queue_record_limit", kQueueRecords}});
    if (!replay)
        DiscoverProviders(provider);
    report_.FlushBatch();
    if (report_.error != ERROR_SUCCESS)
        return false;
    worker_ = std::thread(&Archive::Work, this);
    std::cout << "Evidence archive: " << path_ << '\n';
    return true;
}

void Archive::DiscoverProviders(const GUID& userProvider) {
    ULONG size = 0;
    ULONG status = TdhEnumerateProviders(nullptr, &size);
    if (status == ERROR_INSUFFICIENT_BUFFER && size <= 16 * 1024 * 1024) {
        Bytes bytes(size);
        auto* providers = reinterpret_cast<PROVIDER_ENUMERATION_INFO*>(bytes.data());
        status = TdhEnumerateProviders(providers, &size);
        if (status == ERROR_SUCCESS) {
            for (ULONG i = 0; i < providers->NumberOfProviders; ++i) {
                const auto& provider = providers->TraceProviderInfoArray[i];
                report_.Write({{"record_type", "registered_provider"},
                               {"provider_guid", GuidString(provider.ProviderGuid)},
                               {"provider_name", ProviderName(bytes, provider.ProviderNameOffset)},
                               {"schema_source", provider.SchemaSource},
                               {"selected_user_provider", !!IsEqualGUID(provider.ProviderGuid, userProvider)}});
            }
        }
    }
    report_.Write({{"record_type", "provider_discovery"}, {"tdh_status", status}});
}

bool Archive::Reserve(size_t budget) {
    if (budget > kQueueBytes)
        return false;
    do {
        const auto oldBytes = bytes_.fetch_add(budget);
        const auto oldRecords = records_.fetch_add(1);
        if (oldBytes <= kQueueBytes - budget && oldRecords < kQueueRecords)
            return true;
        records_.fetch_sub(1);
        bytes_.fetch_sub(budget);
        if (replay)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } while (replay);
    return false;
}

uint64_t Archive::Capture(Source source, const EVENT_RECORD& record) {
    auto& counts = counters_[Index(source)];
    const auto seq = ++counts.received;
    size_t extBytes = 0;
    bool valid = (!record.ExtendedDataCount || record.ExtendedData) &&
                 (!record.UserDataLength || record.UserData);
    for (USHORT i = 0; valid && i < record.ExtendedDataCount; ++i) {
        const auto& item = record.ExtendedData[i];
        valid = !item.DataSize || item.DataPtr;
        extBytes += item.DataSize;
    }
    const size_t budget = sizeof(RawRecord) + record.UserDataLength + extBytes +
                          record.ExtendedDataCount * sizeof(EVENT_HEADER_EXTENDED_DATA_ITEM);
    if (!valid) {
        ++counts.copyFailed;
    } else if (Reserve(budget)) {
        try {
            RawRecord copy;
            copy.source = source;
            copy.seq = seq;
            copy.budget = budget;
            copy.clock = status[Index(source)].clock;
            copy.pointerBytes = status[Index(source)].pointerBytes;
            copy.header = record.EventHeader;
            copy.buffer = record.BufferContext;
            if (record.UserDataLength) {
                const auto* data = static_cast<const unsigned char*>(record.UserData);
                copy.payload.assign(data, data + record.UserDataLength);
            }
            if (record.ExtendedDataCount)
                copy.items.assign(record.ExtendedData, record.ExtendedData + record.ExtendedDataCount);
            copy.extended.reserve(extBytes);
            for (auto& item : copy.items) {
                const auto* data = reinterpret_cast<const unsigned char*>(static_cast<uintptr_t>(item.DataPtr));
                item.DataPtr = copy.extended.size();
                if (item.DataSize)
                    copy.extended.insert(copy.extended.end(), data, data + item.DataSize);
            }
            if (queue_.enqueue(std::move(copy))) {
                available_.notify_one();
                return seq;
            }
            ++counts.copyFailed;
        } catch (const std::bad_alloc&) {
            ++counts.copyFailed;
        }
        records_.fetch_sub(1);
        bytes_.fetch_sub(budget);
    } else {
        ++counts.queueDropped;
    }
    if (!counts.firstDropped)
        counts.firstDropped = seq;
    counts.lastDropped = seq;
    return 0;
}

void Archive::Work() {
    for (;;) {
        RawRecord record;
        if (queue_.try_dequeue(record)) {
            try {
                Process(record);
            } catch (const std::exception&) {
                ++processingErrors_;
            }
            bytes_.fetch_sub(record.budget);
            records_.fetch_sub(1);
            continue;
        }
        if (stop_.load() && records_.load() == 0)
            break;
        raw_.FlushBatch();
        stacks_.FlushBatch();
        enrichment_.FlushBatch();
        std::unique_lock<std::mutex> lock(waitMutex_);
        available_.wait_for(lock, std::chrono::milliseconds(10), [this] {
            return stop_.load() || records_.load() != 0;
        });
    }
    try {
        Expire(0, true);
        WriteRecommendations();
    } catch (const std::exception&) {
        ++processingErrors_;
    }
}

void Archive::Expire(uint64_t seq, bool drain) {
    while (!pendingStacks_.empty() && (drain || seq - pendingStacks_.front().event.seq > kAssociationWindow)) {
        auto pending = std::move(pendingStacks_.front());
        pendingStacks_.pop_front();
        pendingFrames_ -= pending.frames.size();
        ResolveFrames(pending, drain);
        if (pending.extendedIndex >= 0)
            continue;
        const auto& stack = pending.event;
        json refs = json::array();
        size_t count = 0;
        const auto iter = candidates_.find(stack.key);
        if (iter != candidates_.end()) {
            const uint64_t first = stack.seq > kAssociationWindow ? stack.seq - kAssociationWindow : 0;
            const auto begin = std::lower_bound(iter->second.begin(), iter->second.end(), first);
            const auto end = std::upper_bound(begin, iter->second.end(), stack.seq + kAssociationWindow);
            count = static_cast<size_t>(end - begin);
            for (size_t i = 0; i < (std::min)(count, size_t(16)); ++i)
                refs.push_back(begin[i]);
        }
        stacks_.Write({{"record_type", "stack_association"}, {"stack_raw_seq", stack.seq},
                       {"source", Name(Source::Kernel)}, {"candidate_count", count},
                       {"event_raw_seq", count == 1 ? refs[0] : json(nullptr)},
                       {"candidate_raw_seqs", std::move(refs)},
                       {"association_status", count == 1 ? "unique_in_window" :
                                              count == 0 ? "unmatched" : "ambiguous"}});
    }
    // A candidate can match a future stack until that stack's window closes.
    while (!candidateOrder_.empty() && (drain || seq - candidateOrder_.front().seq > 2 * kAssociationWindow)) {
        const auto iter = candidates_.find(candidateOrder_.front().key);
        iter->second.pop_front();
        if (iter->second.empty())
            candidates_.erase(iter);
        candidateOrder_.pop_front();
    }
}

void Archive::WriteStack(const RawRecord& record, const CapturedStack& stack, int item) {
    const bool embedded = item >= 0;
    const char* association = embedded ? "embedded" : !stack.complete ? "invalid_layout" :
        record.clock != 1 && record.clock != 2 ? "unmatched_clock" :
        stack.pid == UINT32_MAX || stack.tid == UINT32_MAX ? "unmatched_identity" : "pending";
    json frames = json::array();
    for (auto ip : stack.frames)
        frames.push_back(Address(ip));
    stacks_.Write({{"record_type", "stack_artifact"}, {"source", Name(record.source)},
                   {"raw_seq", record.seq}, {"extended_index", item},
                   {"capture_method", embedded ? "extended_stack" : "kernel_stackwalk"},
                   {"frame_byte_offset", embedded ? 8 : 16},
                   {"pointer_bytes", stack.pointerBytes}, {"frame_count", frames.size()},
                   {"frames", std::move(frames)}, {"resolution_status", "address_only"},
                   {"capture_status", stack.complete ? "decoded" : "invalid_layout"},
                   {"event_timestamp_raw", std::to_string(stack.timestamp)},
                   {"pid", stack.pid}, {"tid", stack.tid},
                   {"match_id", embedded ? json(Address(stack.matchId)) : json(nullptr)},
                   {"association_status", association},
                   {"event_raw_seq", embedded ? json(record.seq) : json(nullptr)}});
    if (record.source != Source::Kernel || !stack.complete || stack.pid == UINT32_MAX ||
        (record.clock != 1 && record.clock != 2))
        return;
    if (!embedded && stack.tid == UINT32_MAX)
        return;
    if (embedded && stack.frames.empty())
        return;
    PendingStack pending{{record.seq, {stack.timestamp, stack.pid, stack.tid}}, item, stack.pointerBytes, {}};
    if (pendingStacks_.size() < kPendingStackLimit && stack.frames.size() <= kPendingFrameLimit - pendingFrames_) {
        pending.frames = stack.frames;
    } else {
        omittedFrames_ += stack.frames.size();
        enrichment_.Write({{"record_type", "stack_resolution"}, {"stack_raw_seq", record.seq},
                           {"source", Name(record.source)},
                           {"extended_index", item}, {"status", "resolution_queue_full"},
                           {"frame_count", stack.frames.size()}});
        if (embedded)
            return;
    }
    pendingStacks_.push_back(std::move(pending));
    pendingFrames_ += pendingStacks_.back().frames.size();
}

void Archive::ObserveLifecycle(const RawRecord& record) {
    if (record.clock != 1 && record.clock != 2)
        return;
    auto event = DecodeLifecycle(record.header, record.payload.data(), record.payload.size(),
                                 record.pointerBytes, record.seq);
    const char* kind;
    switch (event.kind) {
        case LifecycleKind::None:
            return;
        case LifecycleKind::Unsupported:
            ++unsupportedLifecycle_;
            moduleScopeUnknown_ = true;
            kind = "unsupported_version";
            break;
        case LifecycleKind::Invalid:
            ++invalidLifecycle_;
            moduleScopeUnknown_ = moduleScopeUnknown_ || !event.imageBoundary;
            kind = "invalid_layout";
            break;
        case LifecycleKind::ProcessStart: kind = "process_start"; break;
        case LifecycleKind::ProcessEnd: kind = "process_end"; break;
        case LifecycleKind::ImageLoad: kind = "image_load"; break;
        case LifecycleKind::ImageUnload: kind = "image_unload"; break;
        case LifecycleKind::ImageRundown: kind = "image_rundown"; break;
    }
    enrichment_.Write({{"record_type", "lifecycle_observation"}, {"source", Name(record.source)},
                       {"raw_seq", event.seq}, {"timestamp_raw", std::to_string(event.timestamp)},
                       {"kind", kind}, {"pid", event.pid}, {"parent_pid", event.parentPid},
                       {"process_key", Address(event.processKey)}, {"image_base", Address(event.base)},
                       {"image_size", event.size}, {"pe_timestamp", event.imageTimestamp},
                       {"pe_checksum", event.checksum}, {"image_path", Utf8(event.path.data(), event.path.size())}});
    modules_.Observe(std::move(event));
}

void Archive::ResolveFrames(const PendingStack& stack, bool drain) {
    if (stack.frames.empty())
        return;
    const auto& event = stack.event;
    json frames = json::array();
    size_t resolved = 0;
    for (size_t i = 0; i < stack.frames.size(); ++i) {
        const uint64_t ip = stack.frames[i];
        const auto match = moduleScopeUnknown_
            ? ModuleMatch{nullptr, nullptr, "module_index_incomplete"}
            : modules_.Resolve(event.key.pid, event.key.time, ip, stack.pointerBytes);
        json frame = {{"index", i}, {"status", match.status}};
        if (match.image) {
            const auto& image = *match.image;
            frame["image_raw_seq"] = image.seq;
            frame["rva"] = ip - image.base;
            auto found = hotImages_.find(image.path);
            if (found != hotImages_.end()) {
                ++found->second;
            } else if (hotImages_.size() < kHotImageLimit) {
                hotImages_.emplace(image.path, 1);
            } else {
                ++untrackedHotFrames_;
            }
            ++resolved;
        }
        if (match.process)
            frame["process_start_raw_seq"] = match.process->seq;
        frames.push_back(std::move(frame));
    }
    resolvedFrames_ += resolved;
    unresolvedFrames_ += stack.frames.size() - resolved;
    enrichment_.Write({{"record_type", "stack_resolution"}, {"source", Name(Source::Kernel)},
                       {"stack_raw_seq", event.seq}, {"extended_index", stack.extendedIndex},
                       {"status", resolved ? "module_observed" : "address_only"},
                       {"window_closed_by_stop", drain}, {"frames", std::move(frames)}});
}

void Archive::WriteRecommendations() {
    if (hotImages_.empty())
        return;
    LocalImagePaths paths;
    std::map<std::string, uint64_t> translated;
    for (const auto& image : hotImages_) {
        auto path = paths.Translate(image.first);
        if (!path.empty())
            translated[std::move(path)] += image.second;
    }
    std::vector<std::pair<std::string, uint64_t>> ordered(translated.begin(), translated.end());
    std::sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) {
        if (a.second != b.second)
            return a.second > b.second;
        return a.first < b.first;
    });
    if (ordered.empty())
        return;
    std::ofstream out(path_ + "\\initImages.recommended.txt", std::ios::binary);
    for (size_t i = 0; i < ordered.size() && i < kRecommendedImages; ++i) {
        out << ordered[i].first << '\n';
        enrichment_.Write({{"record_type", "hot_image"}, {"image_path", ordered[i].first},
                           {"frame_hits", ordered[i].second}, {"rank", i + 1}});
        ++recommendations_;
    }
    out.close();
    recommendationWriteFailed_ = !out;
}

void Archive::Process(RawRecord& record) {
    auto& counts = counters_[Index(record.source)];
    ++counts.observed;
    const auto& header = record.header;
    const auto& desc = header.EventDescriptor;
    const auto timestamp = static_cast<uint64_t>(header.TimeStamp.QuadPart);
    json items = json::array();
    for (const auto& item : record.items) {
        const void* data = item.DataSize ? record.extended.data() + static_cast<size_t>(item.DataPtr) : nullptr;
        items.push_back({{"type", item.ExtType}, {"linkage", item.Linkage},
                         {"data_hex", Hex(data, item.DataSize)}});
    }
    raw_.Write({{"record_type", "raw_event"}, {"source", Name(record.source)}, {"raw_seq", record.seq},
                {"provider_guid", GuidString(header.ProviderId)}, {"event_id", desc.Id},
                {"event_version", desc.Version}, {"opcode", desc.Opcode}, {"channel", desc.Channel},
                {"level", desc.Level}, {"task", desc.Task}, {"keyword", Address(desc.Keyword)},
                {"timestamp_raw", std::to_string(timestamp)}, {"clock", record.clock},
                {"pid", header.ProcessId}, {"tid", header.ThreadId},
                {"activity_id", GuidString(header.ActivityId)}, {"header_flags", header.Flags},
                {"header_type", header.HeaderType}, {"event_property", header.EventProperty},
                {"header_size", header.Size}, {"processor_time", std::to_string(header.ProcessorTime)},
                {"processor_index", record.buffer.ProcessorIndex}, {"logger_id", record.buffer.LoggerId},
                {"trace_pointer_bytes", record.pointerBytes},
                {"payload_hex", Hex(record.payload.data(), record.payload.size())},
                {"extended_data", std::move(items)}});

    unsigned stacks = 0;
    if (record.source == Source::Kernel) {
        Expire(record.seq, false);
        ObserveLifecycle(record);
        if (IsClassicStackWalk(header)) {
            const auto stack = DecodeClassicStack(record.payload.data(), record.payload.size(),
                EventPointerBytes(header.Flags, record.pointerBytes));
            WriteStack(record, stack, -1);
            if (stack.complete && !stack.frames.empty())
                ++stacks;
        } else if ((record.clock == 1 || record.clock == 2) &&
                   header.ProcessId != UINT32_MAX && header.ThreadId != UINT32_MAX) {
            const StackKey key{timestamp, header.ProcessId, header.ThreadId};
            candidates_[key].push_back(record.seq);
            candidateOrder_.push_back({record.seq, key});
        }
    }
    for (size_t i = 0; i < record.items.size(); ++i) {
        const auto& item = record.items[i];
        const unsigned width = item.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE32 ? 4 :
                               item.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64 ? 8 : 0;
        if (width == 0)
            continue;
        const void* data = item.DataSize ? record.extended.data() + static_cast<size_t>(item.DataPtr) : nullptr;
        auto stack = DecodeExtendedStack(data, item.DataSize, width);
        stack.timestamp = timestamp;
        stack.pid = header.ProcessId;
        stack.tid = header.ThreadId;
        WriteStack(record, stack, static_cast<int>(i));
        if (stack.complete && !stack.frames.empty())
            ++stacks;
    }
    Observe(record, stacks);
}

void Archive::Observe(RawRecord& record, unsigned stacks) {
    const auto& header = record.header;
    const std::string key = GuidString(header.ProviderId) + "/" +
                            Hex(&header.EventDescriptor, sizeof(EVENT_DESCRIPTOR)) + "/" +
                            std::to_string(header.Flags);
    auto& catalog = catalog_[Index(record.source)];
    auto iter = catalog.find(key);
    if (iter == catalog.end()) {
        if (catalog.size() == kCatalogLimit) {
            ++counters_[Index(record.source)].catalogOverflow;
            return;
        }
        CatalogEntry entry;
        entry.provider = header.ProviderId;
        entry.descriptor = header.EventDescriptor;
        entry.headerFlags = header.Flags;
        EVENT_RECORD event{};
        event.EventHeader = header;
        event.BufferContext = record.buffer;
        event.UserData = record.payload.data();
        event.UserDataLength = static_cast<USHORT>(record.payload.size());
        auto items = record.items;
        for (auto& item : items)
            item.DataPtr = item.DataSize ? reinterpret_cast<ULONG_PTR>(record.extended.data() +
                           static_cast<size_t>(item.DataPtr)) : 0;
        event.ExtendedData = items.data();
        event.ExtendedDataCount = static_cast<USHORT>(items.size());
        ULONG size = 0;
        entry.metadataStatus = TdhGetEventInformation(&event, 0, nullptr, nullptr, &size);
        if (entry.metadataStatus == ERROR_INSUFFICIENT_BUFFER && size <= 1024 * 1024) {
            Bytes metadata(size);
            auto* info = reinterpret_cast<TRACE_EVENT_INFO*>(metadata.data());
            entry.metadataStatus = TdhGetEventInformation(&event, 0, nullptr, info, &size);
            if (entry.metadataStatus == ERROR_SUCCESS)
                entry.propertyCount = info->PropertyCount;
        }
        iter = catalog.emplace(key, entry).first;
    }
    ++iter->second.observed;
    iter->second.stacks += stacks;
}

bool Archive::Finish() {
    stop_.store(true);
    available_.notify_one();
    worker_.join();
    const bool rawFlushed = raw_.Finish();
    const bool stacksFlushed = stacks_.Finish();
    const bool enrichmentFlushed = enrichment_.Finish();
    bool degraded = processingErrors_ || !rawFlushed || !stacksFlushed || !enrichmentFlushed ||
                    stats::decodeQueueDropped.load() != 0;
    for (auto source : {Source::Kernel, Source::User}) {
        const auto index = Index(source);
        const auto& counts = counters_[index];
        const auto& session = status[index];
        const auto failed = [](ULONG value) {
            return value != ERROR_SUCCESS && value != ERROR_NOT_READY && value != ERROR_CANCELLED;
        };
        const bool sessionDegraded = counts.queueDropped || counts.copyFailed || counts.catalogOverflow ||
            (session.start == ERROR_SUCCESS && !session.lossAvailable) ||
            failed(session.start) || failed(session.enable) || failed(session.stack) ||
            failed(session.consume) || failed(session.stop) ||
            session.etlEventsLost || session.etlBuffersLost ||
            session.eventsLost || session.logBuffersLost || session.realTimeBuffersLost;
        degraded = degraded || sessionDegraded;
        report_.Write({{"record_type", "session_ledger"}, {"source", Name(source)},
                       {"start_status", session.start}, {"enable_status", session.enable},
                       {"stack_status", session.stack}, {"consume_status", session.consume},
                       {"stop_status", session.stop}, {"clock", session.clock},
                       {"enabled_flags", session.enabledFlags}, {"buffer_size_kb", session.bufferSizeKb},
                       {"minimum_buffers", session.minimumBuffers}, {"maximum_buffers", session.maximumBuffers},
                       {"flush_seconds", session.flushSeconds},
                       {"etl_events_lost", session.etlHeaderAvailable ? json(session.etlEventsLost) : json(nullptr)},
                       {"etl_buffers_lost", session.etlHeaderAvailable ? json(session.etlBuffersLost) : json(nullptr)},
                       {"etw_events_lost", session.lossAvailable ? json(session.eventsLost) : json(nullptr)},
                       {"etw_log_buffers_lost", session.lossAvailable ? json(session.logBuffersLost) : json(nullptr)},
                       {"etw_realtime_buffers_lost", session.lossAvailable ? json(session.realTimeBuffersLost) : json(nullptr)},
                       {"received", counts.received}, {"observed", counts.observed},
                       {"queue_dropped", counts.queueDropped}, {"copy_failed", counts.copyFailed},
                       {"first_dropped_seq", counts.firstDropped}, {"last_dropped_seq", counts.lastDropped},
                       {"catalog_overflow", counts.catalogOverflow}});
        for (const auto& item : catalog_[index]) {
            const auto& entry = item.second;
            report_.Write({{"record_type", "observed_event"}, {"source", Name(source)},
                           {"provider_guid", GuidString(entry.provider)}, {"event_id", entry.descriptor.Id},
                           {"event_version", entry.descriptor.Version}, {"opcode", entry.descriptor.Opcode},
                           {"task", entry.descriptor.Task}, {"channel", entry.descriptor.Channel},
                           {"level", entry.descriptor.Level}, {"keyword", Address(entry.descriptor.Keyword)},
                           {"header_flags", entry.headerFlags}, {"observed", entry.observed},
                           {"stack_records_captured", entry.stacks}, {"tdh_status", entry.metadataStatus},
                           {"tdh_property_count", entry.propertyCount}});
        }
    }
    report_.Write({{"record_type", "module_resolution_ledger"},
                   {"degraded", modules_.Full() || moduleScopeUnknown_ || invalidLifecycle_ ||
                                omittedFrames_ || untrackedHotFrames_ || recommendationWriteFailed_},
                   {"invalid_lifecycle", invalidLifecycle_}, {"unsupported_lifecycle", unsupportedLifecycle_},
                   {"module_index_full", modules_.Full()}, {"module_index_incomplete", moduleScopeUnknown_},
                   {"module_resolved_frames", resolvedFrames_}, {"address_only_frames", unresolvedFrames_},
                   {"resolution_queue_omitted_frames", omittedFrames_},
                   {"hot_image_overflow_frames", untrackedHotFrames_},
                   {"recommended_images", recommendations_}, {"recommendation_write_failed", recommendationWriteFailed_},
                   {"enrichment_written", enrichment_.persisted}, {"enrichment_write_failed", enrichment_.failed},
                   {"enrichment_flushed", enrichmentFlushed}});
    report_.Write({{"record_type", "capture_end"}, {"run_id", run_}, {"degraded", degraded},
                   {"raw_written", raw_.persisted}, {"raw_write_failed", raw_.failed}, {"raw_flushed", rawFlushed},
                   {"stack_lines_written", stacks_.persisted}, {"stack_write_failed", stacks_.failed},
                   {"stack_flushed", stacksFlushed}, {"processing_errors", processingErrors_},
                   {"decode_queue_dropped", stats::decodeQueueDropped.load()},
                   {"legacy_kernel_parsed", stats::eventsParsed.load()},
                   {"legacy_unknown", stats::eventsUnknown.load()},
                   {"legacy_filtered", stats::eventsFiltered.load()},
                   {"legacy_parse_or_policy_dropped", stats::eventsDroppedParse.load()}});
    const bool reportFlushed = report_.Finish();
    if (degraded || !reportFlushed)
        std::cerr << "Evidence capture degraded. Review " << path_ << "\\coverage.jsonl.\n";
    return reportFlushed && !degraded;
}

} // namespace

bool Start(const std::string& directory, const std::string& profile, const std::string& hostUuid,
           ULONG flags, const GUID& provider, bool kernelEtl) {
    auto writer = std::make_unique<Archive>();
    if (!writer->Start(directory, profile, hostUuid, flags, provider, kernelEtl))
        return false;
    archive = std::move(writer);
    return true;
}

bool Active() { return archive != nullptr; }

const std::string& RunId() { return archive->RunId(); }

const std::wstring& KernelEtlPath() {
    static const std::wstring empty;
    return archive ? archive->KernelEtlPath() : empty;
}

namespace {
void WINAPI ReplayCallback(PEVENT_RECORD event) {
    Capture(Source::Kernel, *event);
}
}

int ReplayKernelEtl(const std::string& input, const std::string& directory) {
    EVENT_TRACE_LOGFILEA logfile{};
    logfile.LogFileName = const_cast<char*>(input.c_str());
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    logfile.EventRecordCallback = ReplayCallback;
    TRACEHANDLE consumer = OpenTraceA(&logfile);
    if (consumer == INVALID_PROCESSTRACE_HANDLE) {
        const auto error = GetLastError();
        std::cerr << "OpenTrace failed for " << input << " (" << error << ").\n";
        return error;
    }
    if (!logfile.IsKernelTrace) {
        CloseTrace(consumer);
        std::cerr << "Replay expects an NT Kernel Logger ETL file.\n";
        return ERROR_INVALID_DATA;
    }
    auto writer = std::make_unique<Archive>();
    writer->replay = true;
    if (!writer->Start(directory, "etl_replay", "", 0, GUID{}, false)) {
        CloseTrace(consumer);
        std::cerr << "Could not open replay evidence archive in " << directory << ".\n";
        return ERROR_WRITE_FAULT;
    }
    archive = std::move(writer);
    auto& result = Status(Source::Kernel);
    result.pointerBytes = logfile.LogfileHeader.PointerSize;
    result.clock = logfile.LogfileHeader.ReservedFlags;
    result.etlHeaderAvailable = true;
    result.etlEventsLost = logfile.LogfileHeader.EventsLost;
    result.etlBuffersLost = logfile.LogfileHeader.BuffersLost;
    const ULONG code = ProcessTrace(&consumer, 1, nullptr, nullptr);
    result.consume = code;
    CloseTrace(consumer);
    const bool complete = Finish();
    return code != ERROR_SUCCESS ? code : complete ? 0 : ERROR_WRITE_FAULT;
}

uint64_t Capture(Source source, const EVENT_RECORD& record) {
    return archive ? archive->Capture(source, record) : 0;
}

SessionStatus& Status(Source source) {
    return archive ? archive->status[Index(source)] : inactiveStatus[Index(source)];
}

bool Finish() {
    if (!archive)
        return true;
    const bool ok = archive->Finish();
    archive.reset();
    return ok;
}

} // namespace evidence
} // namespace kellect
