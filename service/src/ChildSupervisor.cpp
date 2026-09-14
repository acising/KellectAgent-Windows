// service/src/ChildSupervisor.cpp
#include "ChildSupervisor.h"
#include "EventLog.h"

namespace kellect::svc {

namespace {
// Quote a single argv token for CreateProcessW's lpCommandLine if it needs it
// (empty or contains whitespace). Inner quotes are doubled per Win32 rules.
std::wstring QuoteArg(const std::wstring& a) {
    if (!a.empty() && a.find_first_of(L" \t") == std::wstring::npos)
        return a; // no quoting needed
    std::wstring r = L"\"";
    for (wchar_t c : a) {
        if (c == L'"') r += L"\"\"";
        else           r += c;
    }
    r += L"\"";
    return r;
}

std::wstring BuildCommandLine(const std::wstring& exe,
                              const std::vector<std::wstring>& args) {
    std::wstring cmd = QuoteArg(exe);
    for (const auto& a : args) {
        cmd += L" ";
        cmd += QuoteArg(a);
    }
    return cmd;
}
} // namespace

ChildSupervisor::ChildSupervisor() {
    ZeroMemory(&proc_, sizeof(proc_));
    ZeroMemory(&si_, sizeof(si_));
}

ChildSupervisor::~ChildSupervisor() {
    // If the wait loop didn't run to completion, make sure the child is gone.
    if (proc_.hProcess) {
        TerminateProcess(proc_.hProcess, 1);
        WaitForSingleObject(proc_.hProcess, 3000);
        CloseChildHandles();
    }
    if (hStdout_ && hStdout_ != INVALID_HANDLE_VALUE) CloseHandle(hStdout_);
}

bool ChildSupervisor::Start(const std::wstring& exePath,
                            const std::vector<std::wstring>& args,
                            const std::wstring& workDir,
                            const std::wstring& stdoutLogFile) {
    exePath_        = exePath;
    args_           = args;
    workDir_        = workDir;
    stdoutLogFile_  = stdoutLogFile;
    return LaunchSuspended();
}

bool ChildSupervisor::LaunchSuspended() {
    CloseChildHandles();

    // Open the stdout log (append, inheritable so the child inherits it).
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    if (hStdout_ && hStdout_ != INVALID_HANDLE_VALUE) {
        CloseHandle(hStdout_);
        hStdout_ = nullptr;
    }
    hStdout_ = CreateFileW(stdoutLogFile_.c_str(), FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hStdout_ == INVALID_HANDLE_VALUE) {
        // Continue without redirection rather than fail the whole service.
        hStdout_ = nullptr;
        EventLog::Warn(L"Could not open stdout log " + stdoutLogFile_ +
                       L"; child output will be discarded.");
    }

    ZeroMemory(&si_, sizeof(si_));
    si_.cb = sizeof(si_);
    si_.dwFlags     = STARTF_USESTDHANDLES;
    si_.hStdInput   = nullptr;
    si_.hStdOutput  = hStdout_;
    si_.hStdError   = hStdout_;

    const std::wstring cmd = BuildCommandLine(exePath_, args_);
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(L'\0');

    const BOOL ok = CreateProcessW(
        exePath_.c_str(),                 // lpApplicationName
        buf.data(),                       // lpCommandLine (mutable)
        nullptr, nullptr,
        TRUE,                             // bInheritHandles (for stdout)
        CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
        nullptr,
        workDir_.empty() ? nullptr : workDir_.c_str(),
        &si_, &proc_);

    if (!ok) {
        started_ = false;
        return false;
    }
    started_ = true;
    return true;
}

void ChildSupervisor::Resume() {
    if (proc_.hThread) {
        if (ResumeThread(proc_.hThread) == static_cast<DWORD>(-1))
            EventLog::Warn(L"ResumeThread failed.");
    }
}

void ChildSupervisor::RequestStop() { stopRequested_ = true; }

void ChildSupervisor::CloseChildHandles() {
    if (proc_.hProcess) { CloseHandle(proc_.hProcess); proc_.hProcess = nullptr; }
    if (proc_.hThread)  { CloseHandle(proc_.hThread);  proc_.hThread  = nullptr; }
}

void ChildSupervisor::KillChild(DWORD waitMs) {
    if (proc_.hProcess) {
        if (!TerminateProcess(proc_.hProcess, 1))
            EventLog::Warn(L"TerminateProcess(kellect.exe) failed; it may already be gone.");
        WaitForSingleObject(proc_.hProcess, waitMs);
    }
    CloseChildHandles();
}

void ChildSupervisor::WaitForEnd(HANDLE hStopEvent) {
    while (started_) {
        const HANDLE handles[2] = { proc_.hProcess, hStopEvent };
        const DWORD wait = WaitForMultipleObjects(2, handles, FALSE, INFINITE);

        if (wait == WAIT_OBJECT_0 + 1 || stopRequested_) {
            // Service STOP: terminate the child and exit.
            KillChild(3000);
            return;
        }
        if (wait != WAIT_OBJECT_0) {
            // WAIT_FAILED or unexpected -> bail out safely.
            EventLog::Warn(L"ChildSupervisor wait returned unexpected value; stopping child.");
            KillChild(3000);
            return;
        }

        // Child exited unexpectedly.
        DWORD code = 0;
        GetExitCodeProcess(proc_.hProcess, &code);
        CloseChildHandles();
        EventLog::Warn(L"kellect.exe exited unexpectedly (code " +
                       std::to_wstring(code) + L").");

        if (stopRequested_) return;

        // Restart policy: up to kMaxRestarts within a kRestartWindow window.
        const DWORD now = GetTickCount();
        if (restartCount_ == 0 || (now - restartEpochFirst_) > kRestartWindow) {
            restartEpochFirst_ = now;
            restartCount_ = 0;
        }
        if (restartCount_ >= kMaxRestarts) {
            EventLog::Error(L"kellect.exe exceeded " + std::to_wstring(kMaxRestarts) +
                            L" restarts within 5 minutes; giving up.");
            return;
        }

        // Delay before restart, but stay responsive to STOP.
        if (WaitForSingleObject(hStopEvent, kRestartDelay) == WAIT_OBJECT_0 ||
            stopRequested_) {
            return;
        }
        ++restartCount_;
        if (!LaunchSuspended()) {
            EventLog::Error(GetLastError(), L"Restart of kellect.exe failed.");
            return;
        }
        Resume(); // restarts don't need the RUNNING gate; resume immediately
        EventLog::Info(L"kellect.exe restarted (attempt " +
                       std::to_wstring(restartCount_) + L" of " +
                       std::to_wstring(kMaxRestarts) + L").");
    }
}

} // namespace kellect::svc
