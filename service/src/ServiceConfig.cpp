// service/src/ServiceConfig.cpp
#include "ServiceConfig.h"
#include "EventLog.h"
#include <shlobj.h>
#include <algorithm>

namespace kellect::svc {

namespace {
constexpr const wchar_t* kRegKey      = L"SOFTWARE\\Kellect\\Service";
constexpr const wchar_t* kConfFile    = L"service.conf";
constexpr const wchar_t* kCollectDir  = L"collect";
constexpr const wchar_t* kDefaultJson = L"kellect.json";

std::wstring DefaultProgramData() {
    wchar_t base[MAX_PATH] = {0};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, base))) {
        return std::wstring(base) + L"\\Kellect";
    }
    return L"C:\\ProgramData\\Kellect"; // fallback if SHGetFolderPath ever fails
}

std::wstring Trim(const std::wstring& s) {
    const size_t a = s.find_first_not_of(L" \t\r\n");
    if (a == std::wstring::npos) return L"";
    const size_t b = s.find_last_not_of(L" \t\r\n");
    return s.substr(a, b - a + 1);
}

// ---- registry readers (native 64-bit view) ----
bool RegReadString(HKEY root, const wchar_t* subkey, const wchar_t* value,
                   std::wstring& out) {
    HKEY h = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS)
        return false;
    wchar_t buf[MAX_PATH] = {0};
    DWORD sz = sizeof(buf);
    DWORD type = 0;
    const LSTATUS rc = RegQueryValueExW(h, value, nullptr, &type,
                                        reinterpret_cast<LPBYTE>(buf), &sz);
    RegCloseKey(h);
    if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || sz < sizeof(wchar_t))
        return false;
    out.assign(buf, (sz / sizeof(wchar_t)) - 1); // drop trailing NUL
    return true;
}

bool RegReadDword(HKEY root, const wchar_t* subkey, const wchar_t* value, DWORD& out) {
    HKEY h = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS)
        return false;
    DWORD v = 0, sz = sizeof(v), type = 0;
    const LSTATUS rc = RegQueryValueExW(h, value, nullptr, &type,
                                        reinterpret_cast<LPBYTE>(&v), &sz);
    RegCloseKey(h);
    if (rc != ERROR_SUCCESS || type != REG_DWORD) return false;
    out = v;
    return true;
}

// ---- INI reader ([service] section) ----
std::wstring IniRead(const std::wstring& dir, const wchar_t* key) {
    const std::wstring file = dir + L"\\" + kConfFile;
    wchar_t buf[MAX_PATH] = {0};
    GetPrivateProfileStringW(L"service", key, L"", buf, MAX_PATH, file.c_str());
    return Trim(buf);
}

// Parse a string into the OutputMode enum; returns false if "console".
bool ParseMode(const std::wstring& raw, OutputMode& out) {
    std::wstring m = raw;
    std::transform(m.begin(), m.end(), m.begin(), ::towlower);
    if (m == L"file")        { out = OutputMode::File;   return true; }
    if (m == L"socket")      { out = OutputMode::Socket; return true; }
    if (m == L"kafka")       { out = OutputMode::Kafka;  return true; }
    if (m == L"console")     { return false; } // rejected in service context
    // Unknown -> default to file (caller logs a warning).
    out = OutputMode::File;
    return true;
}
} // namespace

bool ServiceConfig::Load(ServiceConfig& out, const std::wstring& serviceExeDir) {
    // ---- defaults ----
    out.exePath    = serviceExeDir + L"\\kellect.exe";
    out.workDir    = DefaultProgramData();
    out.mode       = OutputMode::File;
    out.eventMask  = L"0xFF";
    out.outputFile = out.workDir + L"\\" + kCollectDir + L"\\" + kDefaultJson;
    out.socketHost.clear(); out.socketPort = 0;
    out.kafkaBroker.clear(); out.kafkaTopic.clear();

    // ---- layer 2: INI file overrides defaults ----
    std::wstring v;
    if (!(v = IniRead(out.workDir, L"ExePath")).empty())     out.exePath = v;
    if (!(v = IniRead(out.workDir, L"WorkDir")).empty())     out.workDir = v;
    if (!(v = IniRead(out.workDir, L"EventMask")).empty())   out.eventMask = v;
    if (!(v = IniRead(out.workDir, L"OutputFile")).empty())  out.outputFile = v;
    if (!(v = IniRead(out.workDir, L"SocketHost")).empty())  out.socketHost = v;
    if (!(v = IniRead(out.workDir, L"KafkaBroker")).empty()) out.kafkaBroker = v;
    if (!(v = IniRead(out.workDir, L"KafkaTopic")).empty())  out.kafkaTopic = v;
    if (!(v = IniRead(out.workDir, L"SocketPort")).empty()) {
        try { out.socketPort = std::stoi(v); } catch (...) { out.socketPort = 0; }
    }
    std::wstring modeRaw = IniRead(out.workDir, L"OutputMode");

    // ---- layer 1: registry overrides everything ----
    DWORD dw = 0;
    if (RegReadString(HKEY_LOCAL_MACHINE, kRegKey, L"ExePath", v))     out.exePath = v;
    if (RegReadString(HKEY_LOCAL_MACHINE, kRegKey, L"WorkDir", v))     out.workDir = v;
    if (RegReadString(HKEY_LOCAL_MACHINE, kRegKey, L"EventMask", v))   out.eventMask = v;
    if (RegReadString(HKEY_LOCAL_MACHINE, kRegKey, L"OutputFile", v))  out.outputFile = v;
    if (RegReadString(HKEY_LOCAL_MACHINE, kRegKey, L"SocketHost", v))  out.socketHost = v;
    if (RegReadString(HKEY_LOCAL_MACHINE, kRegKey, L"KafkaBroker", v)) out.kafkaBroker = v;
    if (RegReadString(HKEY_LOCAL_MACHINE, kRegKey, L"KafkaTopic", v))  out.kafkaTopic = v;
    if (RegReadDword  (HKEY_LOCAL_MACHINE, kRegKey, L"SocketPort", dw)) out.socketPort = static_cast<int>(dw);
    std::wstring regMode;
    if (RegReadString(HKEY_LOCAL_MACHINE, kRegKey, L"OutputMode", regMode) && !regMode.empty())
        modeRaw = regMode;

    // ---- resolve mode ----
    if (modeRaw.empty()) modeRaw = L"file";
    const bool knownMode = ParseMode(modeRaw, out.mode);
    if (!knownMode) {
        // ParseMode returns false ONLY for "console".
        EventLog::Error(L"OutputMode=console is not supported in the service "
                        L"context (no interactive console). Stopping.");
        return false;
    }
    {
        std::wstring lm = modeRaw;
        std::transform(lm.begin(), lm.end(), lm.begin(), ::towlower);
        if (lm != L"file" && lm != L"socket" && lm != L"kafka")
            EventLog::Warn(L"Unknown OutputMode '" + modeRaw + L"'; defaulting to file.");
    }

    // ---- sanity per mode ----
    if (out.mode == OutputMode::Socket && (out.socketHost.empty() || out.socketPort == 0)) {
        EventLog::Error(L"OutputMode=socket requires SocketHost and SocketPort. Stopping.");
        return false;
    }
    if (out.mode == OutputMode::Kafka && (out.kafkaBroker.empty() || out.kafkaTopic.empty())) {
        EventLog::Error(L"OutputMode=kafka requires KafkaBroker and KafkaTopic. Stopping.");
        return false;
    }
    return true;
}

std::vector<std::wstring> ServiceConfig::buildArgs() const {
    std::vector<std::wstring> a;
    a.push_back(L"-e");
    a.push_back(eventMask);
    switch (mode) {
        case OutputMode::Socket:
            a.push_back(L"-s");
            a.push_back(socketHost + L":" + std::to_wstring(socketPort));
            break;
        case OutputMode::Kafka:
            a.push_back(L"-k");
            a.push_back(kafkaBroker + L"/" + kafkaTopic);
            break;
        case OutputMode::File:
        default:
            a.push_back(L"-f");
            a.push_back(outputFile);
            break;
    }
    return a;
}

} // namespace kellect::svc
