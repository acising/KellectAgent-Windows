// service/src/EventLog.h
// Thin wrapper over the Windows Event Log API (RegisterEventSourceW /
// ReportEventW). The "KellectService" event source is registered (with an
// EventMessageFile pointing at KellectService.exe, whose message table is
// compiled from messages.mc) by the MSI's ServiceInstall and by the dev
// --install path. Until registered, ReportEventW fails benignly and these
// helpers silently no-op — the service never crashes over logging.
#pragma once
#include <windows.h>
#include <string>

namespace kellect::svc {

class EventLog {
public:
    enum class Severity : WORD { Info, Warn, Error };

    static void Info(const std::wstring& msg);
    static void Warn(const std::wstring& msg);
    static void Error(const std::wstring& msg);
    // Append the formatted Win32 error text for `win32Error` after `context`.
    static void Error(DWORD win32Error, const std::wstring& context);

    // Register the "KellectService" event source in the registry so Event
    // Viewer can render our messages. Idempotent. Used by dev --install.
    static void RegisterSource(const std::wstring& owningExePath);

private:
    static void Report(Severity sev, const std::wstring& msg);
};

} // namespace kellect::svc
