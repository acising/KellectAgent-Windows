// src/process/WindowsServiceClient.cpp
#include "WindowsServiceClient.h"

#include <QCoreApplication>
#include <QElapsedTimer>

// windows.h after Qt headers (guarded) — the GUI build already defines NOMINMAX.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace kellect {

namespace {
constexpr const wchar_t* kRegKey = L"SOFTWARE\\Kellect\\Service";

WindowsServiceClient::State mapState(DWORD dwCurrentState) {
    using S = WindowsServiceClient::State;
    switch (dwCurrentState) {
        case SERVICE_STOPPED:          return S::Stopped;
        case SERVICE_START_PENDING:    return S::StartPending;
        case SERVICE_RUNNING:          return S::Running;
        case SERVICE_PAUSE_PENDING:    return S::PausePending;
        case SERVICE_PAUSED:           return S::Paused;
        case SERVICE_CONTINUE_PENDING: return S::ContinuePending;
        case SERVICE_STOP_PENDING:     return S::StopPending;
        default:                       return S::Unknown;
    }
}

// One-shot quiet query. Returns NotInstalled if the service can't be opened.
WindowsServiceClient::State queryState(const QString& serviceName) {
    const SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hScm) return WindowsServiceClient::State::Unknown;
    const SC_HANDLE hSvc = OpenServiceW(
        hScm, reinterpret_cast<LPCWSTR>(serviceName.utf16()), SERVICE_QUERY_STATUS);
    if (!hSvc) {
        const DWORD e = GetLastError();
        CloseServiceHandle(hScm);
        return (e == ERROR_SERVICE_DOES_NOT_EXIST)
                   ? WindowsServiceClient::State::NotInstalled
                   : WindowsServiceClient::State::Unknown;
    }
    SERVICE_STATUS_PROCESS ssp = {};
    DWORD needed = 0;
    const BOOL ok = QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                                         reinterpret_cast<LPBYTE>(&ssp),
                                         sizeof(ssp), &needed);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return ok ? mapState(ssp.dwCurrentState) : WindowsServiceClient::State::Unknown;
}

// Poll hSvc until dwCurrentState == targetState (or abortState is hit). Spins
// the event loop between checks so the UI stays responsive. hSvc held by caller.
WindowsServiceClient::State pollUntil(SC_HANDLE hSvc, DWORD targetState,
                                      DWORD abortState, int timeoutMs) {
    QElapsedTimer t;
    t.start();
    while (true) {
        SERVICE_STATUS_PROCESS ssp = {};
        DWORD needed = 0;
        if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                                 reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed)) {
            if (ssp.dwCurrentState == targetState)
                return mapState(ssp.dwCurrentState);
            if (abortState != 0 && ssp.dwCurrentState == abortState)
                return mapState(ssp.dwCurrentState);
        }
        if (t.hasExpired(timeoutMs))
            return queryState(QString()); // fall back to a fresh quiet query
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
        ::Sleep(200);
    }
}

bool regWriteSz(const wchar_t* name, const QString& value) {
    HKEY h = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kRegKey, 0, nullptr, 0,
                        KEY_WRITE | KEY_WOW64_64KEY, nullptr, &h, nullptr) != ERROR_SUCCESS)
        return false;
    const std::wstring w = value.toStdWString();
    const LSTATUS rc = RegSetValueExW(h, name, 0, REG_SZ,
                                      reinterpret_cast<const BYTE*>(w.c_str()),
                                      static_cast<DWORD>((w.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(h);
    return rc == ERROR_SUCCESS;
}

bool regWriteDword(const wchar_t* name, DWORD value) {
    HKEY h = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kRegKey, 0, nullptr, 0,
                        KEY_WRITE | KEY_WOW64_64KEY, nullptr, &h, nullptr) != ERROR_SUCCESS)
        return false;
    const LSTATUS rc = RegSetValueExW(h, name, 0, REG_DWORD,
                                      reinterpret_cast<const BYTE*>(&value), sizeof(value));
    RegCloseKey(h);
    return rc == ERROR_SUCCESS;
}
} // namespace

WindowsServiceClient::WindowsServiceClient(QString serviceName, QObject* parent)
    : QObject(parent), serviceName_(std::move(serviceName)) {
    connect(&pollTimer_, &QTimer::timeout, this, &WindowsServiceClient::poll);
}

WindowsServiceClient::~WindowsServiceClient() = default;

bool WindowsServiceClient::isInstalled() {
    const SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hScm) return false;
    const SC_HANDLE hSvc = OpenServiceW(
        hScm, reinterpret_cast<LPCWSTR>(serviceName_.utf16()), SERVICE_QUERY_STATUS);
    const bool ok = hSvc != nullptr;
    if (hSvc) CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return ok;
}

WindowsServiceClient::State WindowsServiceClient::state() {
    return queryState(serviceName_);
}

WindowsServiceClient::State WindowsServiceClient::start(int timeoutMs) {
    const SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hScm) {
        emit errorOccurred(tr("OpenSCManager failed (error %1). Run as administrator.")
                               .arg(GetLastError()));
        return State::Unknown;
    }
    const SC_HANDLE hSvc = OpenServiceW(
        hScm, reinterpret_cast<LPCWSTR>(serviceName_.utf16()),
        SERVICE_QUERY_STATUS | SERVICE_START);
    if (!hSvc) {
        const DWORD e = GetLastError();
        CloseServiceHandle(hScm);
        emit errorOccurred(e == ERROR_SERVICE_DOES_NOT_EXIST
                           ? tr("Service '%1' is not installed.").arg(serviceName_)
                           : tr("OpenService('%1') failed (error %2).").arg(serviceName_).arg(e));
        return (e == ERROR_SERVICE_DOES_NOT_EXIST) ? State::NotInstalled : State::Unknown;
    }

    if (queryState(serviceName_) != State::Running) {
        if (!StartServiceW(hSvc, 0, nullptr)) {
            const DWORD e = GetLastError();
            if (e != ERROR_SERVICE_ALREADY_RUNNING) {
                CloseServiceHandle(hSvc);
                CloseServiceHandle(hScm);
                emit errorOccurred(tr("StartService failed (error %1).").arg(e));
                return state();
            }
        }
    }
    // Wait for Running; abort if it falls back to Stopped (failed to start).
    const State result = pollUntil(hSvc, SERVICE_RUNNING, SERVICE_STOPPED, timeoutMs);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    emitIfChanged(result);
    return result;
}

WindowsServiceClient::State WindowsServiceClient::stop(int timeoutMs) {
    const SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hScm) {
        emit errorOccurred(tr("OpenSCManager failed (error %1).").arg(GetLastError()));
        return State::Unknown;
    }
    const SC_HANDLE hSvc = OpenServiceW(
        hScm, reinterpret_cast<LPCWSTR>(serviceName_.utf16()),
        SERVICE_QUERY_STATUS | SERVICE_STOP);
    if (!hSvc) {
        const DWORD e = GetLastError();
        CloseServiceHandle(hScm);
        emit errorOccurred(tr("OpenService('%1') failed (error %2).")
                               .arg(serviceName_).arg(e));
        return (e == ERROR_SERVICE_DOES_NOT_EXIST) ? State::NotInstalled : State::Unknown;
    }
    SERVICE_STATUS st = {};
    ControlService(hSvc, SERVICE_CONTROL_STOP, &st); // best-effort; ignore "not running"
    const State result = pollUntil(hSvc, SERVICE_STOPPED, 0, timeoutMs);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    emitIfChanged(result);
    return result;
}

void WindowsServiceClient::startPolling(int intervalMs) { pollTimer_.start(intervalMs); }
void WindowsServiceClient::stopPolling() { pollTimer_.stop(); }

void WindowsServiceClient::poll() {
    emitIfChanged(state());
}

void WindowsServiceClient::emitIfChanged(State s) {
    if (s != lastState_) {
        lastState_ = s;
        emit stateChanged(s);
    }
}

bool WindowsServiceClient::installRegistryConfig(const OutputConfig& cfg) {
    bool ok = true;
    ok &= regWriteSz(L"OutputMode", cfg.outputMode);
    ok &= regWriteSz(L"EventMask",  cfg.eventMask.isEmpty() ? QStringLiteral("0xFF") : cfg.eventMask);
    if (!cfg.outputFile.isEmpty())  ok &= regWriteSz(L"OutputFile",  cfg.outputFile);
    if (!cfg.socketHost.isEmpty())  ok &= regWriteSz(L"SocketHost",  cfg.socketHost);
    if (cfg.socketPort != 0)        ok &= regWriteDword(L"SocketPort", cfg.socketPort);
    if (!cfg.kafkaBroker.isEmpty()) ok &= regWriteSz(L"KafkaBroker", cfg.kafkaBroker);
    if (!cfg.kafkaTopic.isEmpty())  ok &= regWriteSz(L"KafkaTopic",  cfg.kafkaTopic);
    if (!cfg.exePath.isEmpty())     ok &= regWriteSz(L"ExePath",     cfg.exePath);
    if (!cfg.workDir.isEmpty())     ok &= regWriteSz(L"WorkDir",     cfg.workDir);
    return ok;
}

bool WindowsServiceClient::clearRegistryConfig() {
    const LSTATUS rc = RegDeleteTreeW(HKEY_LOCAL_MACHINE, kRegKey);
    return rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND;
}

} // namespace kellect
