#pragma once
//
// Small Win32 helpers shared by the service host and its installer.
// C++14, no <filesystem>, static CRT.
//
#include <windows.h>

#include <string>
#include <vector>

namespace kellect {
namespace svc {

inline std::string WideToUtf8(const wchar_t* w) {
    if (!w) return std::string();
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1) return std::string();
    // Reserve len (including the terminator), then drop it: writing at
    // out[size()] through &out[0] would be out of bounds.
    std::string out(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &out[0], len, nullptr, nullptr);
    out.resize(static_cast<size_t>(len - 1));
    return out;
}

inline std::string WideToUtf8(const std::wstring& w) {
    return WideToUtf8(w.c_str());
}

inline std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (len <= 1) return std::wstring();
    std::wstring out(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &out[0], len);
    out.resize(static_cast<size_t>(len - 1));
    return out;
}

inline std::string ModulePath() {
    wchar_t buffer[MAX_PATH * 2] = { 0 };
    DWORD len = GetModuleFileNameW(nullptr, buffer, static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0])));
    if (len == 0) return std::string();
    return WideToUtf8(std::wstring(buffer, len));
}

inline std::string ModuleDirectory() {
    std::string path = ModulePath();
    size_t slash = path.find_last_of("\\/");
    return slash == std::string::npos ? std::string(".") : path.substr(0, slash);
}

inline std::string ExpandEnv(const std::string& value) {
    if (value.find('%') == std::string::npos) return value;
    std::wstring wide = Utf8ToWide(value);
    wchar_t buffer[4096] = { 0 };
    DWORD n = ExpandEnvironmentStringsW(wide.c_str(), buffer,
                                        static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0])));
    if (n == 0 || n > sizeof(buffer) / sizeof(buffer[0])) return value;
    return WideToUtf8(std::wstring(buffer, n - 1));
}

inline std::string JoinPath(const std::string& a, const std::string& b) {
    if (a.empty()) return b;
    if (b.empty()) return a;
    if (b[0] == '\\' || b[0] == '/') return b;
    if (a.back() == '\\' || a.back() == '/') return a + b;
    return a + "\\" + b;
}

// Create `path` and every missing parent. Returns false only on a real error.
inline bool EnsureDirectory(const std::string& path) {
    if (path.empty()) return false;
    std::string normalized = path;
    for (char& c : normalized) if (c == '/') c = '\\';

    // Walk the prefix, creating each component.
    std::string current;
    size_t i = 0;
    if (normalized.size() >= 2 && normalized[1] == ':') {
        current = normalized.substr(0, 2);   // "C:"
        i = 2;
    }
    for (; i <= normalized.size(); ++i) {
        if (i == normalized.size() || normalized[i] == '\\') {
            if (!current.empty() && current.back() != ':') {
                std::wstring wide = Utf8ToWide(current);
                if (!CreateDirectoryW(wide.c_str(), nullptr)) {
                    DWORD err = GetLastError();
                    if (err != ERROR_ALREADY_EXISTS) return false;
                }
            }
        }
        if (i < normalized.size()) current.push_back(normalized[i]);
    }
    return true;
}

inline bool EnsureParentDirectory(const std::string& filePath) {
    size_t slash = filePath.find_last_of("\\/");
    if (slash == std::string::npos) return true;
    return EnsureDirectory(filePath.substr(0, slash));
}

inline std::string WinErrorText(DWORD error) {
    LPWSTR buffer = nullptr;
    DWORD n = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    std::string text;
    if (n && buffer) {
        text = WideToUtf8(buffer);
        while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' '))
            text.pop_back();
    }
    LocalFree(buffer);
    if (text.empty()) text = "error " + std::to_string(error);
    return text;
}

} // namespace svc
} // namespace kellect
