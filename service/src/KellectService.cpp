// service/src/KellectService.cpp
// KellectService — thin Windows service that hosts kellect.exe as a child
// process. Console-subsystem binary: with no args it connects to the SCM via
// StartServiceCtrlDispatcherW; --install/--uninstall are dev conveniences
// (production registration is done by the MSI's ServiceInstall element).
#include "EventLog.h"
#include "ServiceConfig.h"
#include "ChildSupervisor.h"

#include <windows.h>
#include <cstdio>

namespace {

// KellectService.cpp lives at global scope (SCM entry points must), so pull the
// EventLog class name in explicitly; the other kellect::svc types stay
// fully-qualified for readability.
using kellect::svc::EventLog;

constexpr const wchar_t* kServiceName  = L"KellectService";
constexpr const wchar_t* kDisplayName  = L"Kellect ETW Collector";

SERVICE_STATUS        g_status    = {};
SERVICE_STATUS_HANDLE g_hStatus    = nullptr;
HANDLE                g_hStop      = nullptr;
HANDLE                g_hWorker    = nullptr;
kellect::svc::ChildSupervisor* g_supervisor = nullptr;
kellect::svc::ServiceConfig    g_config     = {};

void SetState(DWORD state, DWORD win32Exit = 0, DWORD waitHint = 0,
              DWORD checkPoint = 0) {
    g_status.dwCurrentState    = state;
    g_status.dwWin32ExitCode   = win32Exit;
    g_status.dwWaitHint        = waitHint;
    g_status.dwCheckPoint      = checkPoint;
    // Only accept controls while running (not during start/stop transitions).
    g_status.dwControlsAccepted =
        (state == SERVICE_RUNNING || state == SERVICE_PAUSED)
            ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE)
            : 0;
    if (g_hStatus) SetServiceStatus(g_hStatus, &g_status);
}

DWORD WINAPI CtrlHandlerEx(DWORD ctrl, DWORD eventType,
                           LPVOID eventData, LPVOID context) {
    (void)eventType; (void)eventData; (void)context;
    switch (ctrl) {
        case SERVICE_CONTROL_STOP:
            SetState(SERVICE_STOP_PENDING, 0, 8000, 1);
            EventLog::Info(L"Service stop requested.");
            if (g_supervisor) g_supervisor->RequestStop();
            if (g_hStop) SetEvent(g_hStop);
            break;
        case SERVICE_CONTROL_INTERROGATE:
            if (g_hStatus) SetServiceStatus(g_hStatus, &g_status);
            break;
        default:
            break; // uninteresting controls (e.g. SHUTDOWN) -> best-effort ignore
    }
    return NO_ERROR;
}

std::wstring ServiceExePath() {
    wchar_t path[MAX_PATH] = {0};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    return path;
}

std::wstring ServiceExeDir() {
    std::wstring p = ServiceExePath();
    const size_t slash = p.find_last_of(L"\\/");
    return (slash != std::wstring::npos) ? p.substr(0, slash) : p;
}

void EnsureDirs(const std::wstring& base) {
    // Best-effort; errors are non-fatal (CreateDirectory fails if it exists).
    CreateDirectoryW(base.c_str(), nullptr);
    CreateDirectoryW((base + L"\\logs").c_str(), nullptr);
    CreateDirectoryW((base + L"\\collect").c_str(), nullptr);
}

DWORD WINAPI ServiceWorker(LPVOID) {
    SetState(SERVICE_START_PENDING, 0, 8000, 1);

    if (!kellect::svc::ServiceConfig::Load(g_config, ServiceExeDir())) {
        // Console mode or missing required fields -> refuse to run.
        SetState(SERVICE_STOPPED, ERROR_INVALID_PARAMETER);
        return ERROR_INVALID_PARAMETER;
    }
    EnsureDirs(g_config.workDir);
    const std::wstring log = g_config.workDir + L"\\logs\\kellect-stdout.log";

    g_supervisor = new kellect::svc::ChildSupervisor();
    if (!g_supervisor->Start(g_config.exePath, g_config.buildArgs(),
                             g_config.workDir, log)) {
        const DWORD e = GetLastError();
        EventLog::Error(e, L"Failed to start " + g_config.exePath);
        delete g_supervisor; g_supervisor = nullptr;
        SetState(SERVICE_STOPPED, e);
        return e;
    }

    SetState(SERVICE_RUNNING);
    EventLog::Info(L"KellectService started; child: " + g_config.exePath);
    g_supervisor->Resume();
    g_supervisor->WaitForEnd(g_hStop); // returns when child is gone or STOP fires

    delete g_supervisor; g_supervisor = nullptr;
    SetState(SERVICE_STOPPED);
    EventLog::Info(L"KellectService stopped.");
    return 0;
}

VOID WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
    (void)argc; (void)argv;
    g_hStatus = RegisterServiceCtrlHandlerExW(kServiceName, CtrlHandlerEx, nullptr);
    if (!g_hStatus) return;

    g_status.dwServiceType              = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwServiceSpecificExitCode  = 0;
    g_hStop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_hStop) { SetState(SERVICE_STOPPED, GetLastError()); return; }

    // The real work runs on its own thread so this dispatch thread can stay
    // responsive (the SCM dispatch thread must not block on long work).
    g_hWorker = CreateThread(nullptr, 0, ServiceWorker, nullptr, 0, nullptr);
    if (!g_hWorker) {
        SetState(SERVICE_STOPPED, GetLastError());
        return;
    }
    WaitForSingleObject(g_hWorker, INFINITE);
    CloseHandle(g_hWorker); g_hWorker = nullptr;
    CloseHandle(g_hStop);   g_hStop   = nullptr;
}

// ---- dev install / uninstall (production uses the MSI) ----
int DevInstall() {
    const std::wstring path = ServiceExePath();
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        fwprintf(stderr, L"OpenSCManager failed: %lu (run elevated).\n", GetLastError());
        return 1;
    }
    // Register the event source so Event Viewer renders our messages.
    kellect::svc::EventLog::RegisterSource(path);

    SC_HANDLE svc = CreateServiceW(
        scm, kServiceName, kDisplayName,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        path.c_str(), nullptr, nullptr, L"Tcpip\0", nullptr, nullptr);
    if (!svc) {
        const DWORD e = GetLastError();
        CloseServiceHandle(scm);
        if (e == ERROR_SERVICE_EXISTS)
            fwprintf(stderr, L"Service already exists.\n");
        else
            fwprintf(stderr, L"CreateService failed: %lu\n", e);
        return 1;
    }
    fwprintf(stdout, L"Installed '%s' (%s).\n", kDisplayName, path.c_str());
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

int DevUninstall() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) { fwprintf(stderr, L"OpenSCManager failed: %lu\n", GetLastError()); return 1; }
    SC_HANDLE svc = OpenServiceW(scm, kServiceName,
                                 SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!svc) {
        const DWORD e = GetLastError();
        CloseServiceHandle(scm);
        fwprintf(stderr, L"OpenService failed: %lu (not installed?)\n", e);
        return 1;
    }
    // Stop if running.
    SERVICE_STATUS st = {};
    if (ControlService(svc, SERVICE_CONTROL_STOP, &st))
        fwprintf(stdout, L"Stopping...\n");
    for (int i = 0; i < 30; ++i) {
        if (!QueryServiceStatus(svc, &st)) break;
        if (st.dwCurrentState == SERVICE_STOPPED) break;
        Sleep(500);
    }
    const BOOL ok = DeleteService(svc);
    if (ok) fwprintf(stdout, L"Uninstalled '%s'.\n", kServiceName);
    else    fwprintf(stderr, L"DeleteService failed: %lu\n", GetLastError());
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok ? 0 : 1;
}

void PrintUsage() {
    fwprintf(stderr,
        L"KellectService - Windows service hosting kellect.exe\n"
        L"Usage:\n"
        L"  KellectService --install     Register the service (dev)\n"
        L"  KellectService --uninstall   Remove the service (dev)\n"
        L"  KellectService               Run as a service (launched by SCM)\n");
}

} // namespace

int wmain(int argc, wchar_t* argv[]) {
    if (argc >= 2) {
        const std::wstring a = argv[1];
        if (a == L"--install"   || a == L"-i") return DevInstall();
        if (a == L"--uninstall" || a == L"-u") return DevUninstall();
        if (a == L"--help"      || a == L"-h") { PrintUsage(); return 0; }
    }

    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<LPWSTR>(kServiceName), ServiceMain },
        { nullptr, nullptr }
    };
    if (!StartServiceCtrlDispatcherW(table)) {
        const DWORD e = GetLastError();
        if (e == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
            PrintUsage(); // run from a console, not by SCM
        else
            fwprintf(stderr, L"StartServiceCtrlDispatcherW failed: %lu\n", e);
        return static_cast<int>(e);
    }
    return 0;
}
