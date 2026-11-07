#pragma once

#include <windows.h>
#include <evntcons.h>
#include <cstdint>
#include <vector>

namespace kellect {

struct CapturedStack {
    uint64_t timestamp = 0;
    uint32_t pid = 0;
    uint32_t tid = 0;
    uint64_t matchId = 0;
    unsigned pointerBytes = 0;
    bool complete = false;
    std::vector<uint64_t> frames;
};

bool IsClassicStackWalk(const EVENT_HEADER& header);
unsigned EventPointerBytes(USHORT flags, unsigned tracePointerBytes);
CapturedStack DecodeClassicStack(const void* data, size_t size, unsigned pointerBytes);
CapturedStack DecodeExtendedStack(const void* data, size_t size, unsigned pointerBytes);

} // namespace kellect
