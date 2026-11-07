#include <windows.h>
#include <initguid.h>
#include <evntrace.h>
#include "process/etw_config.h"
#include "process/event_parse.h"

#include <array>
#include <atomic>
#include <algorithm>
#include <iostream>
#include <mutex>
#include <thread>

#include "runtime/collector.h"
#include "runtime/evidence.h"
#include "tools/stats.h"

namespace {

using kellect::evidence::Source;

struct TraceProperties {
    EVENT_TRACE_PROPERTIES value{};
    wchar_t loggerName[1024]{};
    wchar_t logfileName[MAX_PATH]{};
};

struct Session {
    TRACEHANDLE handle = 0;
    TraceProperties properties;
};

std::mutex sessionMutex;
std::atomic<bool> g_consumerOpened{ false };
std::array<Session, 2> sessions;

const wchar_t* LoggerName(Source source) {
    return source == Source::Kernel ? KERNEL_LOGGER_NAMEW : L"MyTrace";
}

Session& SessionFor(Source source) {
    return sessions[static_cast<size_t>(source)];
}

ULONG StopSessionLocked(Source source) {
    auto& session = SessionFor(source);
    if (!session.handle)
        return ERROR_SUCCESS;
    auto& result = kellect::evidence::Status(source);
    auto& props = session.properties.value;
    result.stop = ControlTraceW(session.handle, nullptr, &props, EVENT_TRACE_CONTROL_STOP);
    if (result.stop == ERROR_SUCCESS) {
        result.lossAvailable = true;
        result.eventsLost = props.EventsLost;
        result.logBuffersLost = props.LogBuffersLost;
        result.realTimeBuffersLost = props.RealTimeBuffersLost;
    }
    if (result.stop == ERROR_SUCCESS || result.stop == ERROR_WMI_INSTANCE_NOT_FOUND ||
        result.stop == ERROR_WMI_GUID_NOT_FOUND)
        session.handle = 0;
    else
        std::cerr << "ControlTrace(stop) failed with " << result.stop << '\n';
    return result.stop;
}

BOOL WINAPI ConsoleCtrlHandler(DWORD type) {
    switch (type) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            kellect::RequestStop();
            return TRUE;
        default:
            return FALSE;
    }
}

void WINAPI ConsumeUser(PEVENT_RECORD event) {
    EventParser::ConsumeUserEvent(event);
}

ULONG Consume(Source source) {
    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName = const_cast<LPWSTR>(LoggerName(source));
    logfile.EventRecordCallback = source == Source::Kernel ? EventParser::ConsumeEventMain : ConsumeUser;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
    if (kellect::evidence::Active())
        logfile.ProcessTraceMode |= PROCESS_TRACE_MODE_RAW_TIMESTAMP;

    TRACEHANDLE consumer;
    {
        std::lock_guard<std::mutex> lock(sessionMutex);
        if (!SessionFor(source).handle || kellect::IsStopRequested())
            return ERROR_CANCELLED;
        consumer = OpenTraceW(&logfile);
        if (consumer == INVALID_PROCESSTRACE_HANDLE)
            return GetLastError();
    }
    g_consumerOpened.store(true);
    kellect::evidence::Status(source).pointerBytes = logfile.LogfileHeader.PointerSize;
    std::cout << (source == Source::Kernel ? "Kernel" : "User")
              << " ETW consumer ready." << std::endl;
    const ULONG status = ProcessTrace(&consumer, 1, nullptr, nullptr);
    CloseTrace(consumer);
    g_consumerOpened.store(false);
    return status;
}

ULONG RunSession(Source source, ULONG flags, const GUID& provider, ULONG keywords) {
    const bool kernel = source == Source::Kernel;
    auto& result = kellect::evidence::Status(source);
    ULONG status = ERROR_SUCCESS;
    TRACEHANDLE handle = 0;
    ULONG deferredFlags = 0;
    {
        std::lock_guard<std::mutex> lock(sessionMutex);
        if (kellect::IsStopRequested())
            return ERROR_CANCELLED;
        auto& session = SessionFor(source);
        session.properties = {};
        auto& props = session.properties.value;
        props.Wnode.BufferSize = sizeof(TraceProperties);
        props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        // Keep the kernel clock compatible with existing normalized output.
        // Evidence-enabled user traces use system time for the same reason.
        props.Wnode.ClientContext = kernel || kellect::evidence::Active() ? 2 : 1;
        props.LoggerNameOffset = offsetof(TraceProperties, loggerName);
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props.MinimumBuffers = 128;
        props.MaximumBuffers = 512;   // adaptive controller can grow up to 2048
        props.BufferSize = kernel ? 1024 : 5120;
        props.FlushTimer = 1;
        if (kernel) {
            props.Wnode.Guid = SystemTraceControlGuid;
            // Phase 1: only process/thread/TCPIP. The big DCStart/rundown
            // providers (Image/Registry/File) are added after the consumer is
            // attached, so their enumeration cannot overflow an unconsumed
            // buffer at StartTrace time.
            // Only Image rundown is deferred. File/Registry/TCP are enabled in
            // phase 1 so no behaviour event class has an observation gap.
            const ULONG kDeferred = EVENT_TRACE_FLAG_IMAGE_LOAD;
            deferredFlags = flags & kDeferred;
            const ULONG initialFlags = flags & ~kDeferred;
            props.EnableFlags = initialFlags;
            props.LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE;
            const auto& etl = kellect::evidence::KernelEtlPath();
            if (!etl.empty()) {
                props.LogFileNameOffset = offsetof(TraceProperties, logfileName);
                std::copy(etl.begin(), etl.end(), session.properties.logfileName);
                props.LogFileMode |= EVENT_TRACE_FILE_MODE_SEQUENTIAL;
            }
        }

        // A previous collector/tool may still hold the singleton NT Kernel
        // Logger. Stop it automatically once, then retry; a stale session from
        // a crashed kellect is the common case.
        for (int attempt = 0; attempt < 4; ++attempt) {
            status = StartTraceW(&handle, LoggerName(source), &props);
            if (status != ERROR_ALREADY_EXISTS)
                break;
            if (attempt == 0) {
                TraceProperties stale{};
                stale.value.Wnode.BufferSize = sizeof(TraceProperties);
                stale.value.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
                stale.value.Wnode.Guid = SystemTraceControlGuid;
                stale.value.LoggerNameOffset = offsetof(TraceProperties, loggerName);
                std::copy(LoggerName(source), LoggerName(source) + wcslen(LoggerName(source)) + 1,
                          stale.loggerName);
                const ULONG stopped = ControlTraceW(0, LoggerName(source), &stale.value,
                                                    EVENT_TRACE_CONTROL_STOP);
                std::cout << "Stale NT Kernel Logger detected; auto-stop returned "
                          << stopped << ", retrying StartTrace..." << std::endl;
            }
            if (attempt < 3)
                Sleep(250);
        }
        result.start = status;
        if (status != ERROR_SUCCESS) {
            std::cerr << (kernel ? "Kernel" : "User") << " StartTrace failed with " << status;
            if (status == ERROR_ALREADY_EXISTS)
                std::cerr << ": NT Kernel Logger is already in use. Stop the other "
                             "kellect/WPR/xperf/Defender kernel trace and retry "
                             "(check: logman query -ets)";
            std::cerr << '\n';
            return status;
        }
        session.handle = handle;
        result.clock = props.Wnode.ClientContext;
        result.enabledFlags = props.EnableFlags;
        result.bufferSizeKb = props.BufferSize;
        result.minimumBuffers = props.MinimumBuffers;
        result.maximumBuffers = props.MaximumBuffers;
        result.flushSeconds = props.FlushTimer;
        result.enable = ERROR_SUCCESS;

        // ETW may silently lower the buffer size/count when the non-paged pool
        // limit is hit. Query what was actually granted; a request that was not
        // honoured is a common reason for large EventsLost.
        TraceProperties actual{};
        actual.value.Wnode.BufferSize = sizeof(TraceProperties);
        actual.value.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        actual.value.Wnode.Guid = SystemTraceControlGuid;
        actual.value.LoggerNameOffset = offsetof(TraceProperties, loggerName);
        std::copy(LoggerName(source), LoggerName(source) + wcslen(LoggerName(source)) + 1,
                  actual.loggerName);
        ULONG query = ControlTraceW(handle, LoggerName(source), &actual.value,
                                    EVENT_TRACE_CONTROL_QUERY);
        if (query != ERROR_SUCCESS) {
            actual = TraceProperties{};
            actual.value.Wnode.BufferSize = sizeof(TraceProperties);
            actual.value.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            actual.value.Wnode.Guid = SystemTraceControlGuid;
            actual.value.LoggerNameOffset = offsetof(TraceProperties, loggerName);
            std::copy(LoggerName(source), LoggerName(source) + wcslen(LoggerName(source)) + 1,
                      actual.loggerName);
            query = ControlTraceW(0, LoggerName(source), &actual.value,
                                  EVENT_TRACE_CONTROL_QUERY);
        }
        if (query == ERROR_SUCCESS) {
            std::cout << (kernel ? "ETW kernel" : "ETW user")
                      << " session: flags=0x" << std::hex << actual.value.EnableFlags << std::dec
                      << " buffer=" << actual.value.BufferSize << "KB"
                      << " min=" << actual.value.MinimumBuffers
                      << " max=" << actual.value.MaximumBuffers
                      << " allocated=" << actual.value.NumberOfBuffers
                      << " free=" << actual.value.FreeBuffers
                      << " flush=" << actual.value.FlushTimer << "s" << std::endl;
        } else {
            std::cerr << "Warning: cannot query ETW session properties (" << query << ')\n';
        }

        if (kernel && Initializer::getListenCallStack()) {
            result.stack = EventCallstack::initCallStackTracing(handle);
            if (result.stack != ERROR_SUCCESS)
                std::cerr << "TraceStackTracingInfo failed with " << result.stack << '\n';
            else
                std::cout << "callstack tracing: armed" << std::endl;
        }
        if (!kernel) {
            ENABLE_TRACE_PARAMETERS options{};
            options.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
            if (Initializer::getListenCallStack() && kellect::evidence::Active())
                options.EnableProperty = EVENT_ENABLE_PROPERTY_STACK_TRACE;
            result.enable = EnableTraceEx2(handle, &provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                           TRACE_LEVEL_INFORMATION, keywords, 0, 0, &options);
            if (options.EnableProperty != 0)
                result.stack = result.enable;
            status = result.enable;
        }
    }

    ULONG consumeStatus = ERROR_SUCCESS;
    std::thread consumerThread;
    const bool twoPhase = kernel && deferredFlags != 0;
    if (status == ERROR_SUCCESS && !kellect::IsStopRequested()) {
        if (twoPhase) {
            g_consumerOpened.store(false);
            consumerThread = std::thread([&] { consumeStatus = Consume(source); });
            for (int i = 0; i < 3000 && !g_consumerOpened.load() &&
                            !kellect::IsStopRequested(); ++i)
                Sleep(1);
            if (!g_consumerOpened.load())
                std::cerr << "Warning: ETW consumer was not ready before phase 2; "
                             "flags update may still drop the first rundown\n";

            // UPDATE requires a full properties buffer and, when Wnode.Guid is
            // SystemTraceControlGuid, InstanceName must be KERNEL_LOGGER_NAME.
            TraceProperties update{};
            update.value.Wnode.BufferSize = sizeof(TraceProperties);
            update.value.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            update.value.Wnode.Guid = SystemTraceControlGuid;
            update.value.LoggerNameOffset = offsetof(TraceProperties, loggerName);
            update.value.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            update.value.EnableFlags = flags;
            std::copy(LoggerName(source), LoggerName(source) + wcslen(LoggerName(source)) + 1,
                      update.loggerName);
            const ULONG updated = ControlTraceW(handle, LoggerName(source), &update.value,
                                                EVENT_TRACE_CONTROL_UPDATE);
            if (updated == ERROR_SUCCESS) {
                result.enabledFlags = flags;
                SessionFor(Source::Kernel).properties.value.EnableFlags = flags;
                std::cout << "ETW phase 2: flags updated to 0x" << std::hex << flags
                          << std::dec << " after consumer attach" << std::endl;
            } else {
                std::cerr << "Error: two-phase ETW flag update failed with " << updated
                          << "; continuing with process/thread/tcpip only" << std::endl;
            }

            // Stay in the real-time collection loop until the user stops the
            // collector or the consumer dies. Without this the function fell
            // straight through to StopSession and the run lasted ~200 ms.
            while (!kellect::IsStopRequested() && g_consumerOpened.load())
                Sleep(20);
        } else {
            result.consume = Consume(source);
            if (!kellect::IsStopRequested() || (result.consume != ERROR_WMI_INSTANCE_NOT_FOUND &&
                    result.consume != ERROR_WMI_GUID_NOT_FOUND && result.consume != ERROR_CANCELLED))
                status = result.consume;
        }
    }
    {
        std::lock_guard<std::mutex> lock(sessionMutex);
        const ULONG stop = StopSessionLocked(source);
        if (status == ERROR_SUCCESS)
            status = stop;
    }
    if (consumerThread.joinable())
        consumerThread.join();
    if (twoPhase) {
        result.consume = consumeStatus;
        if (!kellect::IsStopRequested() || (consumeStatus != ERROR_WMI_INSTANCE_NOT_FOUND &&
                consumeStatus != ERROR_WMI_GUID_NOT_FOUND && consumeStatus != ERROR_CANCELLED))
            status = consumeStatus;
    }
    if (status != ERROR_SUCCESS)
        std::cerr << (kernel ? "Kernel" : "User") << " ETW session failed with " << status << '\n';
    return status;
}

} // namespace

void ETWConfiguration::StopSessions() {
    std::lock_guard<std::mutex> lock(sessionMutex);
    StopSessionLocked(Source::Kernel);
    StopSessionLocked(Source::User);
}

bool ETWConfiguration::QueryKernel(KernelBufferStats& stats) {
    std::lock_guard<std::mutex> lock(sessionMutex);
    auto& session = SessionFor(Source::Kernel);
    if (!session.handle)
        return false;

    TraceProperties query{};
    query.value.Wnode.BufferSize = sizeof(TraceProperties);
    query.value.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    query.value.Wnode.Guid = SystemTraceControlGuid;
    query.value.LoggerNameOffset = offsetof(TraceProperties, loggerName);
    const wchar_t* name = LoggerName(Source::Kernel);
    std::copy(name, name + wcslen(name) + 1, query.loggerName);

    const ULONG status = ControlTraceW(session.handle, name, &query.value,
                                       EVENT_TRACE_CONTROL_QUERY);
    if (status != ERROR_SUCCESS)
        return false;

    stats.allocated = query.value.NumberOfBuffers;
    stats.freeBuffers = query.value.FreeBuffers;
    stats.maxBuffers = query.value.MaximumBuffers;
    stats.eventsLost = query.value.EventsLost;
    return true;
}

bool ETWConfiguration::SetKernelMaximumBuffers(ULONG maximumBuffers) {
    std::lock_guard<std::mutex> lock(sessionMutex);
    auto& session = SessionFor(Source::Kernel);
    if (!session.handle)
        return false;

    TraceProperties update{};
    update.value.Wnode.BufferSize = sizeof(TraceProperties);
    update.value.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    update.value.Wnode.Guid = SystemTraceControlGuid;
    update.value.LoggerNameOffset = offsetof(TraceProperties, loggerName);
    update.value.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    update.value.EnableFlags = session.properties.value.EnableFlags;
    update.value.MaximumBuffers = maximumBuffers;
    const wchar_t* name = LoggerName(Source::Kernel);
    std::copy(name, name + wcslen(name) + 1, update.loggerName);

    const ULONG status = ControlTraceW(session.handle, name, &update.value,
                                       EVENT_TRACE_CONTROL_UPDATE);
    if (status == ERROR_SUCCESS) {
        session.properties.value.MaximumBuffers = maximumBuffers;
        return true;
    }
    return false;
}

int ETWConfiguration::Run() {
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
    int kernelStatus = ERROR_SUCCESS;
    int userStatus = ERROR_SUCCESS;
    std::thread kernel;
    if (kernelFlags_ != 0) {
        kernel = std::thread([&] {
            kernelStatus = RunSession(Source::Kernel, kernelFlags_, GUID{}, 0);
            if (kernelStatus != ERROR_SUCCESS && kernelStatus != ERROR_CANCELLED)
                kellect::RequestStop();
        });
    }
    if (!IsEqualGUID(userProvider_, GUID{})) {
        userStatus = RunSession(Source::User, 0, userProvider_, 0);
        if (userStatus != ERROR_SUCCESS && userStatus != ERROR_CANCELLED)
            kellect::RequestStop();
    }
    if (kernel.joinable())
        kernel.join();
    SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);

    const auto& status = kellect::evidence::Status(Source::Kernel);
    if (status.lossAvailable) {
        kellect::stats::etwEventsLost.store(status.eventsLost);
        kellect::stats::etwBuffersLost.store(status.realTimeBuffersLost);
    } else if (status.start == ERROR_SUCCESS) {
        std::cerr << "Kernel ETW loss counters unavailable.\n";
    }
    if (kernelStatus != ERROR_SUCCESS && kernelStatus != ERROR_CANCELLED)
        return kernelStatus;
    return userStatus == ERROR_CANCELLED ? ERROR_SUCCESS : userStatus;
}
