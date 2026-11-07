#include "supervisor.h"

#include <windows.h>
#include <evntrace.h>

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

#include "runtime/collector.h"
#include "service_util.h"
#include "tools/logger.h"

namespace kellect {
namespace svc {

namespace {

const char* const kChildExe = "kellect.exe";
const char* const kDesiredConfig = "config\\remote\\desired.json";
const char* const kFilterFile = "config\\filter.txt";

bool FileExists(const std::string& path) {
    const DWORD attributes = GetFileAttributesA(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

struct FileStamp {
    DWORD low = 0;
    DWORD high = 0;
    ULONGLONG size = 0;
    bool present = false;
};

void ReadStamp(const std::string& path, FileStamp& stamp) {
    stamp = FileStamp();

    WIN32_FILE_ATTRIBUTE_DATA data;
    ZeroMemory(&data, sizeof(data));
    if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &data))
        return;

    stamp.present = true;
    stamp.low = data.ftLastWriteTime.dwLowDateTime;
    stamp.high = data.ftLastWriteTime.dwHighDateTime;
    stamp.size = (static_cast<ULONGLONG>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
}

bool StampChanged(const std::string& path, FileStamp& stamp) {
    FileStamp now;
    ReadStamp(path, now);
    if (!now.present && !stamp.present)
        return false;
    if (now.present != stamp.present || now.low != stamp.low ||
        now.high != stamp.high || now.size != stamp.size) {
        stamp = now;
        return true;
    }
    return false;
}

std::string Quote(const std::string& value) { return "\"" + value + "\""; }

HANDLE CreateKillJob() {
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (job == nullptr)
        return nullptr;

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;
    ZeroMemory(&info, sizeof(info));
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info,
                                 sizeof(info))) {
        CloseHandle(job);
        return nullptr;
    }
    return job;
}

// A crashed collector can leave the NT Kernel Logger session behind; a new
// process would then fail StartTrace with ERROR_ALREADY_EXISTS. Stop it before
// the restart (the supervisor runs as LocalSystem, so it has the right).
void StopStaleKernelSession() {
    EVENT_TRACE_PROPERTIES properties;
    ZeroMemory(&properties, sizeof(properties));
    properties.Wnode.BufferSize = sizeof(properties);
    properties.Wnode.ClientContext = 2;
    properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    ControlTraceW(0, KERNEL_LOGGER_NAMEW, &properties, EVENT_TRACE_CONTROL_STOP);
}

bool SpawnChild(const std::string& exePath, const std::vector<std::string>& args,
                const std::string& stopEventName, HANDLE job,
                PROCESS_INFORMATION& process, std::string& error) {
    std::string commandLine = Quote(exePath);
    for (const std::string& arg : args)
        commandLine += " " + Quote(arg);
    commandLine += " " + Quote("--stop-event") + " " + Quote(stopEventName);

    STARTUPINFOA startup;
    ZeroMemory(&startup, sizeof(startup));
    startup.cb = sizeof(startup);
    ZeroMemory(&process, sizeof(process));

    const BOOL ok = CreateProcessA(
        exePath.c_str(), &commandLine[0], nullptr, nullptr, FALSE,
        CREATE_NEW_PROCESS_GROUP, nullptr, nullptr, &startup, &process);
    if (!ok) {
        error = WinErrorText(GetLastError());
        return false;
    }

    if (job != nullptr)
        AssignProcessToJobObject(job, process.hProcess);

    return true;
}

void StopChild(PROCESS_INFORMATION& process, HANDLE stopEvent, DWORD timeoutMs) {
    if (stopEvent != nullptr)
        SetEvent(stopEvent);

    if (WaitForSingleObject(process.hProcess, timeoutMs) == WAIT_OBJECT_0)
        return;

    MyLogger::writeLog("supervisor: collector did not stop in time; terminating");
    TerminateProcess(process.hProcess, 1);
    WaitForSingleObject(process.hProcess, 5000);
}

} // namespace

int RunSupervisor(const ServiceOptions& options,
                  const std::function<bool()>& stopRequested) {
    const std::string exeDir = ModuleDirectory();
    SetCurrentDirectoryW(Utf8ToWide(exeDir).c_str());
    MyLogger::initLogger(JoinPath(exeDir, "config\\log.conf"));

    const std::string exePath = JoinPath(exeDir, kChildExe);
    if (!FileExists(exePath)) {
        MyLogger::writeLog("supervisor: collector not found: " + exePath);
        return 4;
    }

    const std::vector<std::string> baseArgs = BuildCollectorArgs(options);

    HANDLE job = CreateKillJob();
    if (job == nullptr)
        MyLogger::writeLog("supervisor: job object unavailable; orphan protection disabled");

    int backoffMs = 5000;
    unsigned generation = 0;
    int result = 0;

    while (!stopRequested()) {
        char eventName[128];
        snprintf(eventName, sizeof(eventName), "Local\\kellect-stop-%lu-%u",
                 static_cast<unsigned long>(GetCurrentProcessId()), ++generation);

        HANDLE stopEvent = CreateEventA(nullptr, TRUE, FALSE, eventName);

        PROCESS_INFORMATION process;
        std::string error;
        if (!SpawnChild(exePath, baseArgs, eventName, job, process, error)) {
            MyLogger::writeLog("supervisor: cannot start collector: " + error);
            if (stopEvent != nullptr)
                CloseHandle(stopEvent);
            if (stopRequested())
                break;
            Sleep(static_cast<DWORD>(backoffMs));
            backoffMs = (std::min)(backoffMs * 2, 60000);
            continue;
        }

        MyLogger::writeLog("supervisor: collector started pid=" +
                           std::to_string(process.dwProcessId));
        const ULONGLONG startedAt = GetTickCount64();

        FileStamp desiredStamp;
        FileStamp filterStamp;
        ReadStamp(kDesiredConfig, desiredStamp);
        ReadStamp(kFilterFile, filterStamp);

        bool restartForConfig = false;
        DWORD exitCode = 0;

        for (;;) {
            if (stopRequested()) {
                StopChild(process, stopEvent, 20000);
                exitCode = 0;
                break;
            }

            const DWORD wait = WaitForSingleObject(process.hProcess, 1000);
            if (wait == WAIT_OBJECT_0) {
                GetExitCodeProcess(process.hProcess, &exitCode);
                break;
            }

            if (StampChanged(kDesiredConfig, desiredStamp) ||
                StampChanged(kFilterFile, filterStamp)) {
                MyLogger::writeLog(
                    "supervisor: configuration changed; restarting collector");
                restartForConfig = true;
                StopChild(process, stopEvent, 20000);
                exitCode = 0;
                break;
            }
        }

        const ULONGLONG ranMs = GetTickCount64() - startedAt;

        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        if (stopEvent != nullptr)
            CloseHandle(stopEvent);

        if (stopRequested()) {
            result = 0;
            break;
        }

        if (restartForConfig) {
            backoffMs = 5000;
            Sleep(1000);
            continue;
        }

        MyLogger::writeLog("supervisor: collector exited, code=" +
                           std::to_string(exitCode));
        if (exitCode == 0) {
            // Clean exit without a stop request: the operator stopped the
            // service, so do not fight it by restarting.
            break;
        }

        StopStaleKernelSession();
        if (ranMs > 60000)
            backoffMs = 5000;

        MyLogger::writeLog("supervisor: restarting in " + std::to_string(backoffMs) + " ms");
        for (int slept = 0; slept < backoffMs && !stopRequested(); slept += 500)
            Sleep(500);
        backoffMs = (std::min)(backoffMs * 2, 60000);
    }

    if (job != nullptr)
        CloseHandle(job);
    return result;
}

} // namespace svc
} // namespace kellect
