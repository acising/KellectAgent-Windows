// service/src/EventLog.cpp
#include "EventLog.h"

namespace kellect::svc {

namespace {
constexpr const wchar_t* kSourceName = L"KellectService";

// These MUST match the MessageId values in messages.mc (EVT_INFO/WARN/ERROR).
constexpr DWORD kEvtInfo  = 1;
constexpr DWORD kEvtWarn  = 2;
constexpr DWORD kEvtError = 3;
} // namespace

void EventLog::Info(const std::wstring& msg)  { Report(Severity::Info,  msg); }
void EventLog::Warn(const std::wstring& msg)  { Report(Severity::Warn,  msg); }
void EventLog::Error(const std::wstring& msg) { Report(Severity::Error, msg); }

void EventLog::Error(DWORD win32Error, const std::wstring& context) {
    LPWSTR raw = nullptr;
    const DWORD formatted = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, win32Error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&raw), 0, nullptr);

    std::wstring full = context;
    full += L" (error ";
    full += std::to_wstring(win32Error);
    if (formatted && raw) {
        full += L": ";
        full += raw;
        full += L")";
    } else {
        full += L")";
    }
    if (raw) LocalFree(raw);
    Report(Severity::Error, full);
}

void EventLog::Report(Severity sev, const std::wstring& msg) {
    HANDLE h = RegisterEventSourceW(nullptr, kSourceName);
    if (!h) return; // Source not registered yet — silent no-op.

    WORD type = EVENTLOG_INFORMATION_TYPE;
    DWORD id  = kEvtInfo;
    switch (sev) {
        case Severity::Warn:  type = EVENTLOG_WARNING_TYPE;     id = kEvtWarn;  break;
        case Severity::Error: type = EVENTLOG_ERROR_TYPE;       id = kEvtError; break;
        case Severity::Info:  type = EVENTLOG_INFORMATION_TYPE; id = kEvtInfo;  break;
    }
    const wchar_t* strings[1] = { msg.c_str() };
    ReportEventW(h, type, 0, id, nullptr, 1, 0, strings, nullptr);
    DeregisterEventSource(h);
}

void EventLog::RegisterSource(const std::wstring& owningExePath) {
    // HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\KellectService
    const wchar_t* key =
        L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\KellectService";
    HKEY h = nullptr;
    DWORD disposition = 0;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, key, 0, nullptr, 0,
                        KEY_WRITE, nullptr, &h, &disposition) != ERROR_SUCCESS) {
        return;
    }
    const DWORD typesSupported =
        EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
    RegSetValueExW(h, L"EventMessageFile", 0, REG_EXPAND_SZ,
                   reinterpret_cast<const BYTE*>(owningExePath.c_str()),
                   static_cast<DWORD>((owningExePath.size() + 1) * sizeof(wchar_t)));
    RegSetValueExW(h, L"TypesSupported", 0, REG_DWORD,
                   reinterpret_cast<const BYTE*>(&typesSupported), sizeof(typesSupported));
    RegCloseKey(h);
}

} // namespace kellect::svc
