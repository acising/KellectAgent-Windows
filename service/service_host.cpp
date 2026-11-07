#include "service_host.h"

#include <cstdio>
#include <vector>

#include "runtime/collector.h"
#include "service_util.h"
#include "supervisor.h"
#include "tools/logger.h"

namespace kellect {
namespace svc {

namespace {

ServiceOptions g_options;
SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS g_status = {};
DWORD g_processExitCode = 0;

void ReportStatus(DWORD state, DWORD exitCode = NO_ERROR, DWORD waitHint = 0) {
    static DWORD checkpoint = 1;

    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = exitCode;
    g_status.dwServiceSpecificExitCode = 0;

    if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) {
        g_status.dwControlsAccepted = 0;
        g_status.dwWaitHint = waitHint ? waitHint : 30000;
        g_status.dwCheckPoint = checkpoint++;
    } else {
        g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
        g_status.dwWaitHint = 0;
        g_status.dwCheckPoint = 0;
    }

    if (g_statusHandle)
        SetServiceStatus(g_statusHandle, &g_status);
}

DWORD WINAPI ControlHandler(DWORD control, DWORD /*eventType*/, LPVOID /*eventData*/,
                            LPVOID /*context*/) {
    switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
        case SERVICE_CONTROL_PRESHUTDOWN:
            // Stopping the ETW session unblocks ProcessTrace on the collector
            // thread, which then flushes output and returns.
            ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 30000);
            kellect::RequestStop();
            return NO_ERROR;

        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;

        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

void WINAPI ServiceMain(DWORD /*argc*/, LPWSTR* /*argv*/) {
    const std::wstring serviceName = Utf8ToWide(g_options.name);
    g_statusHandle = RegisterServiceCtrlHandlerExW(serviceName.c_str(), ControlHandler, nullptr);
    if (!g_statusHandle)
        return;

    ReportStatus(SERVICE_START_PENDING, NO_ERROR, 30000);

    // The SCM starts services in %SystemRoot%\System32. The collector resolves
    // config/ (schema xml, filter.txt, uuid, initImages.txt, log.conf) against
    // the working directory, so pin it to the installation folder.
    const std::string exeDir = ModuleDirectory();
    SetCurrentDirectoryW(Utf8ToWide(exeDir).c_str());

    MyLogger::initLogger(JoinPath(exeDir, "config\\log.conf"));

    std::vector<std::string> args = BuildCollectorArgs(g_options);
    if (!g_options.schemaProbe.empty())
        EnsureParentDirectory(g_options.schemaProbe);

    ReportStatus(SERVICE_RUNNING);

    int rc;
    if (g_options.supervisor) {
        // Process-level supervision: one child at a time, restart to apply
        // config, graceful stop through the named event.
        rc = RunSupervisor(g_options, [] { return kellect::IsStopRequested(); });
    } else {
        rc = kellect::RunCollector(args);
    }
    g_processExitCode = (rc == 0) ? 0 : static_cast<DWORD>(rc);

    // Non-zero: let the SCM failure actions (restart) handle it.
    ReportStatus(SERVICE_STOPPED, rc == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR);
    g_status.dwServiceSpecificExitCode = g_processExitCode;
    if (g_statusHandle) SetServiceStatus(g_statusHandle, &g_status);
}

} // namespace

int RunService(const ServiceOptions& options) {
    g_options = options;

    std::wstring serviceName = Utf8ToWide(options.name);
    SERVICE_TABLE_ENTRYW table[2];
    table[0].lpServiceName = const_cast<LPWSTR>(serviceName.c_str());
    table[0].lpServiceProc = ServiceMain;
    table[1].lpServiceName = nullptr;
    table[1].lpServiceProc = nullptr;

    if (!StartServiceCtrlDispatcherW(table)) {
        const DWORD error = GetLastError();
        if (error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            fprintf(stderr,
                    "KellectService is not running under the Service Control Manager.\n"
                    "  install:   KellectService.exe --install\n"
                    "  foreground: KellectService.exe --console\n");
        } else {
            fprintf(stderr, "StartServiceCtrlDispatcher failed: %s\n",
                    WinErrorText(error).c_str());
        }
        return 1;
    }

    return static_cast<int>(g_processExitCode);
}

bool InstallService(const ServiceOptions& options, std::string& error) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        error = "OpenSCManager failed: " + WinErrorText(GetLastError()) +
                " (run this from an elevated prompt)";
        return false;
    }

    DWORD startType = SERVICE_AUTO_START;
    if (options.startType == "demand") startType = SERVICE_DEMAND_START;
    else if (options.startType == "disabled") startType = SERVICE_DISABLED;

    const std::wstring name = Utf8ToWide(options.name);
    const std::wstring displayName = Utf8ToWide(options.displayName);
    const std::wstring binPath = L"\"" + Utf8ToWide(ModulePath()) + L"\"";

    SC_HANDLE service = CreateServiceW(
        scm, name.c_str(), displayName.c_str(),
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, startType, SERVICE_ERROR_NORMAL,
        binPath.c_str(), nullptr, nullptr, nullptr, nullptr /* LocalSystem */, nullptr);

    if (!service && GetLastError() == ERROR_SERVICE_EXISTS) {
        // Re-registering: update the binary path so an upgrade works.
        service = OpenServiceW(scm, name.c_str(), SERVICE_ALL_ACCESS);
        if (service)
            ChangeServiceConfigW(service, SERVICE_NO_CHANGE, startType, SERVICE_NO_CHANGE,
                                 binPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr,
                                 nullptr);
    }

    if (!service) {
        error = "CreateService/OpenService failed: " + WinErrorText(GetLastError());
        CloseServiceHandle(scm);
        return false;
    }

    const std::wstring description = Utf8ToWide(options.description);
    SERVICE_DESCRIPTIONW descriptionInfo = {};
    descriptionInfo.lpDescription = const_cast<LPWSTR>(description.c_str());
    ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &descriptionInfo);

    // Restart on failure, reset the counter daily.
    SC_ACTION actions[3] = {
        { SC_ACTION_RESTART, 5000 },
        { SC_ACTION_RESTART, 10000 },
        { SC_ACTION_RESTART, 30000 },
    };
    SERVICE_FAILURE_ACTIONSW failureActions = {};
    failureActions.dwResetPeriod = 86400;
    failureActions.cActions = 3;
    failureActions.lpsaActions = actions;
    ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, &failureActions);

    if (!StartServiceW(service, 0, nullptr)) {
        const DWORD errorCode = GetLastError();
        if (errorCode != ERROR_SERVICE_ALREADY_RUNNING) {
            error = "StartService failed: " + WinErrorText(errorCode);
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return false;
        }
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}

bool UninstallService(const std::string& name, std::string& error) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        error = "OpenSCManager failed: " + WinErrorText(GetLastError());
        return false;
    }

    const std::wstring wideName = Utf8ToWide(name);
    SC_HANDLE service = OpenServiceW(scm, wideName.c_str(),
                                     SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!service) {
        const DWORD errorCode = GetLastError();
        CloseServiceHandle(scm);
        if (errorCode == ERROR_SERVICE_DOES_NOT_EXIST)
            return true;
        error = "OpenService failed: " + WinErrorText(errorCode);
        return false;
    }

    SERVICE_STATUS status = {};
    ControlService(service, SERVICE_CONTROL_STOP, &status);

    if (!DeleteService(service)) {
        const DWORD errorCode = GetLastError();
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        error = "DeleteService failed: " + WinErrorText(errorCode);
        return false;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}

bool QueryServiceState(const std::string& name, DWORD& state, std::string& error) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        error = "OpenSCManager failed: " + WinErrorText(GetLastError());
        return false;
    }

    const std::wstring wideName = Utf8ToWide(name);
    SC_HANDLE service = OpenServiceW(scm, wideName.c_str(), SERVICE_QUERY_STATUS);
    if (!service) {
        const DWORD errorCode = GetLastError();
        CloseServiceHandle(scm);
        if (errorCode == ERROR_SERVICE_DOES_NOT_EXIST) {
            state = 0;
            return true;
        }
        error = "OpenService failed: " + WinErrorText(errorCode);
        return false;
    }

    SERVICE_STATUS status = {};
    const BOOL ok = QueryServiceStatus(service, &status);
    const DWORD queryError = ok ? ERROR_SUCCESS : GetLastError();
    if (ok) state = status.dwCurrentState;

    // Capture the error before the handles close: CloseServiceHandle
    // overwrites the thread's last-error value.
    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    if (!ok) {
        error = "QueryServiceStatus failed: " + WinErrorText(queryError);
        return false;
    }
    return true;
}

} // namespace svc
} // namespace kellect
