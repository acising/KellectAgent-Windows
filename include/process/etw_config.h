#pragma once

#include <windows.h>

class ETWConfiguration {
public:
    ETWConfiguration(ULONG kernelFlags, GUID userProvider)
        : kernelFlags_(kernelFlags), userProvider_(userProvider) {}

    int Run();
    // Stops only the logger handles opened by this process.
    static void StopSessions();

    // Adaptive controls (kernel logger only).
    struct KernelBufferStats {
        ULONG allocated = 0;
        ULONG freeBuffers = 0;
        ULONG maxBuffers = 0;
        ULONG eventsLost = 0;
    };
    static bool QueryKernel(KernelBufferStats& stats);
    static bool SetKernelMaximumBuffers(ULONG maximumBuffers);

private:
    ULONG kernelFlags_;
    GUID userProvider_;
};
