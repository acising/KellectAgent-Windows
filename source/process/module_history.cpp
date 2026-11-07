#include "process/module_history.h"

#include <algorithm>
#include <cstring>
#include <iterator>
#include <utility>

#include "process/stack_capture.h"

namespace kellect {
namespace {

constexpr GUID kImage = {0x2cb15d1d, 0x5fc1, 0x11d2, {0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18}};
constexpr GUID kProcess = {0x3d6fa8d0, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
constexpr size_t kMaxPathChars = 1024;

template <typename T>
T Read(const unsigned char* data) {
    T value;
    std::memcpy(&value, data, sizeof(value));
    return value;
}

uint64_t ReadPointer(const unsigned char* data, unsigned width) {
    return width == 4 ? Read<uint32_t>(data) : Read<uint64_t>(data);
}

} // namespace

LifecycleEvent DecodeLifecycle(const EVENT_HEADER& header, const void* data, size_t size,
                               unsigned tracePointerBytes, uint64_t seq) {
    LifecycleEvent event;
    const bool image = IsEqualGUID(header.ProviderId, kImage);
    const bool process = IsEqualGUID(header.ProviderId, kProcess);
    const auto& desc = header.EventDescriptor;
    if ((!image && !process) || (image && desc.Opcode != 2 && desc.Opcode != 3 && desc.Opcode != 10) ||
        (process && desc.Opcode != 1 && desc.Opcode != 2))
        return event;

    event.seq = seq;
    event.timestamp = static_cast<uint64_t>(header.TimeStamp.QuadPart);
    // Image v3 splits the reserved DWORD into signature fields. Its total
    // size is unchanged. Process v2 through v4 share the identity prefix.
    if (desc.Version < 2 || desc.Version > (image ? 3 : 4)) {
        event.kind = LifecycleKind::Unsupported;
        return event;
    }
    event.kind = LifecycleKind::Invalid;
    const unsigned width = EventPointerBytes(header.Flags, tracePointerBytes);
    if (!data || (width != 4 && width != 8))
        return event;
    const auto* bytes = static_cast<const unsigned char*>(data);

    if (process) {
        if (size < width + 2 * sizeof(uint32_t))
            return event;
        event.processKey = ReadPointer(bytes, width);
        event.pid = Read<uint32_t>(bytes + width);
        event.parentPid = Read<uint32_t>(bytes + width + 4);
        if (event.pid != UINT32_MAX)
            event.kind = desc.Opcode == 1 ? LifecycleKind::ProcessStart : LifecycleKind::ProcessEnd;
        return event;
    }

    if (size < 2 * width + sizeof(uint32_t))
        return event;
    event.base = ReadPointer(bytes, width);
    event.size = ReadPointer(bytes + width, width);
    event.pid = Read<uint32_t>(bytes + 2 * width);
    event.imageBoundary = event.pid != UINT32_MAX;
    if (!event.imageBoundary)
        return event;
    if (desc.Opcode == 2) {
        event.kind = LifecycleKind::ImageUnload;
        return event;
    }

    const size_t nameOffset = 3 * width + 8 * sizeof(uint32_t);
    if (!event.size || event.size > UINT32_MAX || event.size > UINT64_MAX - event.base ||
        size < nameOffset + sizeof(wchar_t))
        return event;
    event.checksum = Read<uint32_t>(bytes + 2 * width + 4);
    event.imageTimestamp = Read<uint32_t>(bytes + 2 * width + 8);
    for (size_t offset = nameOffset; size - offset >= sizeof(wchar_t); offset += sizeof(wchar_t)) {
        const auto ch = Read<wchar_t>(bytes + offset);
        if (!ch) {
            if (!event.path.empty())
                event.kind = desc.Opcode == 3 ? LifecycleKind::ImageRundown : LifecycleKind::ImageLoad;
            return event;
        }
        if (event.path.size() == kMaxPathChars)
            break;
        event.path.push_back(ch);
    }
    return event;
}

void ModuleHistory::Observe(LifecycleEvent event) {
    const bool process = event.kind == LifecycleKind::ProcessStart || event.kind == LifecycleKind::ProcessEnd;
    if (full_ || (!process && !event.imageBoundary))
        return;
    if (size_ >= limit_) {
        full_ = true;
        spaces_.clear();
        return;
    }
    auto& space = spaces_[event.pid];
    if (event.kind == LifecycleKind::ImageLoad || event.kind == LifecycleKind::ImageRundown)
        space.widestImage = (std::max)(space.widestImage, event.size);
    auto& history = process ? space.processes : space.images[event.base];
    const auto timestamp = event.timestamp;
    const auto inserted = history.emplace(timestamp, Change{std::move(event)});
    if (inserted.second)
        ++size_;
    else
        inserted.first->second.conflict = true;
}

ModuleMatch ModuleHistory::ResolveSpace(uint32_t pid, uint64_t timestamp, uint64_t ip) const {
    ModuleMatch match;
    const auto space = spaces_.find(pid);
    if (space == spaces_.end())
        return match;
    const auto& processes = space->second.processes;
    auto process = processes.upper_bound(timestamp);
    if (process != processes.begin()) {
        const auto& boundary = std::prev(process)->second;
        if (boundary.conflict || boundary.event.timestamp == timestamp) {
            match.status = "ambiguous_process_boundary";
            return match;
        }
        if (boundary.event.kind == LifecycleKind::ProcessEnd) {
            match.status = "process_ended";
            return match;
        }
        match.process = &boundary.event;
    }
    const auto& images = space->second.images;
    unsigned examined = 0;
    for (auto next = images.upper_bound(ip); next != images.begin();) {
        --next;
        const uint64_t rva = ip - next->first;
        if (rva >= space->second.widestImage)
            break;
        if (++examined > 512)
            return {nullptr, match.process, "module_lookup_limit"};
        const auto& changes = next->second;
        auto change = changes.upper_bound(timestamp);
        if (change == changes.begin())
            continue;
        const auto& boundary = std::prev(change)->second;
        const auto& image = boundary.event;
        if (match.process && image.timestamp < match.process->timestamp)
            continue;
        if (boundary.conflict)
            return {nullptr, match.process, "ambiguous_image_boundary"};
        // An invalid later observation poisons the old range, including when
        // the malformed record did not contain a reliable length.
        if (image.kind != LifecycleKind::ImageUnload &&
            (image.kind == LifecycleKind::Invalid || rva < image.size)) {
            if (image.timestamp == timestamp ||
                (match.process && image.timestamp == match.process->timestamp) || match.image) {
                match.image = nullptr;
                match.status = "ambiguous_image_boundary";
                return match;
            }
            if (image.kind == LifecycleKind::Invalid) {
                match.image = nullptr;
                match.status = "invalid_image_boundary";
                return match;
            }
            match.image = &image;
        } else if (image.kind == LifecycleKind::ImageUnload &&
                   image.timestamp == timestamp &&
                   (!image.size || rva < image.size)) {
            match.image = nullptr;
            match.status = "ambiguous_image_boundary";
            return match;
        }
    }
    if (match.image)
        match.status = match.image->kind == LifecycleKind::ImageRundown ? "rundown_observed" : "load_observed";
    return match;
}

ModuleMatch ModuleHistory::Resolve(uint32_t pid, uint64_t timestamp, uint64_t ip, unsigned pointerBytes) const {
    if (full_)
        return {nullptr, nullptr, "module_index_full"};
    // On the x64 target, only high-half 64-bit frames can use the kernel
    // image map. A WOW64 frame may legitimately use a high 32-bit user VA.
    if (pointerBytes == 8 && ip >= 0xffff800000000000ull) {
        const auto system = ResolveSpace(4, timestamp, ip);
        const auto kernel = ResolveSpace(0, timestamp, ip);
        if (system.image && kernel.image) {
            if (system.image->base == kernel.image->base && system.image->size == kernel.image->size &&
                system.image->path == kernel.image->path && system.image->checksum == kernel.image->checksum &&
                system.image->imageTimestamp == kernel.image->imageTimestamp)
                return system;
            return {nullptr, nullptr, "ambiguous_kernel_image"};
        }
        if (system.image && std::strcmp(kernel.status, "module_not_observed") == 0)
            return system;
        if (kernel.image && std::strcmp(system.status, "module_not_observed") == 0)
            return kernel;
        return {nullptr, nullptr, "kernel_image_unconfirmed"};
    }
    return ResolveSpace(pid, timestamp, ip);
}

} // namespace kellect
