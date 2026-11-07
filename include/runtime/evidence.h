#pragma once

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <cstdint>
#include <string>

namespace kellect {
namespace evidence {

enum class Source { Kernel, User };

struct SessionStatus {
    ULONG start = ERROR_NOT_READY;
    ULONG enable = ERROR_NOT_READY;
    ULONG stack = ERROR_NOT_READY;
    ULONG consume = ERROR_NOT_READY;
    ULONG stop = ERROR_NOT_READY;
    bool lossAvailable = false;
    ULONG eventsLost = 0;
    ULONG logBuffersLost = 0;
    ULONG realTimeBuffersLost = 0;
    unsigned clock = 0;
    unsigned pointerBytes = 0;
    ULONG enabledFlags = 0;
    ULONG bufferSizeKb = 0;
    ULONG minimumBuffers = 0;
    ULONG maximumBuffers = 0;
    ULONG flushSeconds = 0;
    bool etlHeaderAvailable = false;
    ULONG etlEventsLost = 0;
    ULONG etlBuffersLost = 0;
};

bool Start(const std::string& directory, const std::string& profile,
           const std::string& hostUuid, ULONG requestedFlags, const GUID& userProvider,
           bool kernelEtl = false);
bool Active();
const std::string& RunId();
const std::wstring& KernelEtlPath();
int ReplayKernelEtl(const std::string& input, const std::string& directory);
// Called by one ProcessTrace producer per source. A nonzero return is the
// source-local receive sequence assigned to a queued raw record.
uint64_t Capture(Source source, const EVENT_RECORD& record);
SessionStatus& Status(Source source);
bool Finish();

} // namespace evidence
} // namespace kellect
