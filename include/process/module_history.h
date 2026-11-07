#pragma once

#include <windows.h>
#include <evntcons.h>
#include <cstdint>
#include <map>
#include <string>

namespace kellect {

enum class LifecycleKind {
    None, Unsupported, Invalid, ProcessStart, ProcessEnd, ImageLoad, ImageUnload, ImageRundown
};

struct LifecycleEvent {
    LifecycleKind kind = LifecycleKind::None;
    uint64_t seq = 0;
    uint64_t timestamp = 0;
    uint32_t pid = UINT32_MAX;
    uint32_t parentPid = UINT32_MAX;
    uint64_t processKey = 0;
    uint64_t base = 0;
    uint64_t size = 0;
    uint32_t checksum = 0;
    uint32_t imageTimestamp = 0;
    std::wstring path;
    bool imageBoundary = false;
};

LifecycleEvent DecodeLifecycle(const EVENT_HEADER& header, const void* data, size_t size,
                               unsigned tracePointerBytes, uint64_t seq);

struct ModuleMatch {
    const LifecycleEvent* image = nullptr;
    const LifecycleEvent* process = nullptr;
    const char* status = "module_not_observed";
};

// Stores bounded observations for one kernel clock. A full index fails closed
// so later lookups cannot silently reuse a stale mapping.
class ModuleHistory {
public:
    explicit ModuleHistory(size_t limit = 65536) : limit_(limit) {}
    void Observe(LifecycleEvent event);
    ModuleMatch Resolve(uint32_t pid, uint64_t timestamp, uint64_t ip, unsigned pointerBytes) const;
    bool Full() const { return full_; }

private:
    struct Change {
        LifecycleEvent event;
        bool conflict = false;
    };
    using Timeline = std::map<uint64_t, Change>;
    struct AddressSpace {
        Timeline processes;
        std::map<uint64_t, Timeline> images;
        uint64_t widestImage = 0;
    };

    ModuleMatch ResolveSpace(uint32_t pid, uint64_t timestamp, uint64_t ip) const;
    std::map<uint32_t, AddressSpace> spaces_;
    size_t size_ = 0;
    size_t limit_;
    bool full_ = false;
};

} // namespace kellect
