#include "process/stack_capture.h"

#include <cstring>

namespace kellect {
namespace {

constexpr GUID kStackWalk = {0xdef2fe46, 0x7bd6, 0x4b80,
                            {0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3}};

template <typename T>
T Read(const unsigned char* data) {
    T value;
    std::memcpy(&value, data, sizeof(value));
    return value;
}

void ReadFrames(CapturedStack& stack, const unsigned char* bytes, size_t size) {
    const auto width = stack.pointerBytes;
    if (width != 4 && width != 8)
        return;
    stack.complete = size % width == 0;
    stack.frames.reserve(size / width);
    for (size_t offset = 0; size - offset >= width; offset += width)
        stack.frames.push_back(width == 4 ? Read<uint32_t>(bytes + offset)
                                         : Read<uint64_t>(bytes + offset));
}

} // namespace

bool IsClassicStackWalk(const EVENT_HEADER& header) {
    return IsEqualGUID(header.ProviderId, kStackWalk) &&
           header.EventDescriptor.Opcode == 32;
}

unsigned EventPointerBytes(USHORT flags, unsigned tracePointerBytes) {
    const bool is32 = (flags & EVENT_HEADER_FLAG_32_BIT_HEADER) != 0;
    const bool is64 = (flags & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0;
    if (is32 && is64)
        return 0;
    return is32 ? 4 : is64 ? 8 : tracePointerBytes;
}

CapturedStack DecodeClassicStack(const void* data, size_t size, unsigned pointerBytes) {
    CapturedStack stack;
    stack.pointerBytes = pointerBytes;
    constexpr size_t prefix = sizeof(uint64_t) + 2 * sizeof(uint32_t);
    if (!data || size < prefix)
        return stack;
    const auto* bytes = static_cast<const unsigned char*>(data);
    stack.timestamp = Read<uint64_t>(bytes);
    stack.pid = Read<uint32_t>(bytes + 8);
    stack.tid = Read<uint32_t>(bytes + 12);
    ReadFrames(stack, bytes + prefix, size - prefix);
    return stack;
}

CapturedStack DecodeExtendedStack(const void* data, size_t size, unsigned pointerBytes) {
    CapturedStack stack;
    stack.pointerBytes = pointerBytes;
    if (!data || size < sizeof(uint64_t))
        return stack;
    const auto* bytes = static_cast<const unsigned char*>(data);
    stack.matchId = Read<uint64_t>(bytes);
    ReadFrames(stack, bytes + sizeof(uint64_t), size - sizeof(uint64_t));
    return stack;
}

} // namespace kellect
