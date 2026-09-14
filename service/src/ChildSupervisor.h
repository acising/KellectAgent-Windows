// service/src/ChildSupervisor.h
// Owns the kellect.exe child process: launches it suspended, resumes it once
// the service has reported RUNNING, watches for unexpected exit (restarts up
// to 3x in a 5-minute window), and terminates it on service STOP.
//
// stdout/stderr are redirected to a log file because Windows services have no
// console. Stop uses TerminateProcess because kellect.exe exposes no graceful
// stop IPC (adding one would violate the "do not modify the collector" rule),
// so in-flight ETW buffer contents may be lost on stop.
#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace kellect::svc {

class ChildSupervisor {
public:
    ChildSupervisor();
    ~ChildSupervisor();

    ChildSupervisor(const ChildSupervisor&) = delete;
    ChildSupervisor& operator=(const ChildSupervisor&) = delete;

    // Launch the child suspended (resume via Resume() after RUNNING is reported).
    // Returns false (and logs) on launch failure.
    bool Start(const std::wstring& exePath,
               const std::vector<std::wstring>& args,
               const std::wstring& workDir,
               const std::wstring& stdoutLogFile);

    void Resume();     // unsuspend the child after the service reports RUNNING

    // Signal the wait loop to terminate the child and return. Non-blocking.
    void RequestStop();

    // Block until the child exits for good or the service is asked to stop.
    void WaitForEnd(HANDLE hStopEvent);

private:
    bool LaunchSuspended();   // (re)spawn the child; fills proc_/si_
    void CloseChildHandles();
    void KillChild(DWORD waitMs);

    // Restart policy constants.
    static constexpr int   kMaxRestarts    = 3;
    static constexpr DWORD kRestartWindow  = 5 * 60 * 1000; // 5 min
    static constexpr DWORD kRestartDelay   = 5 * 1000;       // 5 s

    PROCESS_INFORMATION proc_ = {};
    STARTUPINFOW        si_   = {};
    HANDLE              hStdout_      = nullptr; // child stdout/stderr target
    bool                started_       = false;
    bool                stopRequested_ = false;

    DWORD restartEpochFirst_ = 0; // GetTickCount of first restart in window
    int   restartCount_      = 0;

    // Re-launch inputs (kept so restarts can re-spawn identically).
    std::wstring              exePath_;
    std::vector<std::wstring> args_;
    std::wstring              workDir_;
    std::wstring              stdoutLogFile_;
};

} // namespace kellect::svc
