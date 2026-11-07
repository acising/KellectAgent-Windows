#include "secargus/util.h"

#include <windows.h>

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace kellect {
namespace secargus {

namespace {

inline uint32_t Rotr(uint32_t v, int n) { return (v >> n) | (v << (32 - n)); }

const uint32_t kSha256K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

} // namespace

std::string Sha256Hex(const std::string& data) {
    uint32_t h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

    std::string msg = data;
    const uint64_t bitLen = static_cast<uint64_t>(msg.size()) * 8;
    msg.push_back(static_cast<char>(0x80));
    while (msg.size() % 64 != 56)
        msg.push_back(static_cast<char>(0x00));
    for (int i = 7; i >= 0; --i)
        msg.push_back(static_cast<char>((bitLen >> (8 * i)) & 0xff));

    for (size_t chunk = 0; chunk < msg.size(); chunk += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(static_cast<unsigned char>(msg[chunk + 4 * i])) << 24) |
                   (static_cast<uint32_t>(static_cast<unsigned char>(msg[chunk + 4 * i + 1])) << 16) |
                   (static_cast<uint32_t>(static_cast<unsigned char>(msg[chunk + 4 * i + 2])) << 8) |
                   (static_cast<uint32_t>(static_cast<unsigned char>(msg[chunk + 4 * i + 3])));
        }
        for (int i = 16; i < 64; ++i) {
            const uint32_t s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const uint32_t s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

        for (int i = 0; i < 64; ++i) {
            const uint32_t s1 = Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25);
            const uint32_t ch = (e & f) ^ ((~e) & g);
            const uint32_t t1 = hh + s1 + ch + kSha256K[i] + w[i];
            const uint32_t s0 = Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22);
            const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t t2 = s0 + maj;

            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (int i = 0; i < 8; ++i) {
        for (int shift = 28; shift >= 0; shift -= 4)
            out.push_back(hex[(h[i] >> shift) & 0x0f]);
    }
    return out;
}

std::string IsoNowUtc() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%04u-%02u-%02uT%02u:%02u:%02u.%03u+00:00",
             static_cast<unsigned>(st.wYear), static_cast<unsigned>(st.wMonth),
             static_cast<unsigned>(st.wDay), static_cast<unsigned>(st.wHour),
             static_cast<unsigned>(st.wMinute), static_cast<unsigned>(st.wSecond),
             static_cast<unsigned>(st.wMilliseconds));
    return buffer;
}

std::string Trim(const std::string& s) {
    const size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return std::string();
    const size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::string Lower(const std::string& s) {
    std::string out = s;
    for (char& c : out)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

bool EnsureDirectory(const std::string& path) {
    if (path.empty()) return false;

    std::string normalized = path;
    for (char& c : normalized)
        if (c == '/') c = '\\';

    std::string current;
    size_t i = 0;
    if (normalized.size() >= 2 && normalized[1] == ':') {
        current = normalized.substr(0, 2);
        i = 2;
    }
    for (; i <= normalized.size(); ++i) {
        if (i == normalized.size() || normalized[i] == '\\') {
            if (!current.empty() && current.back() != ':') {
                if (!CreateDirectoryA(current.c_str(), nullptr)) {
                    const DWORD err = GetLastError();
                    if (err != ERROR_ALREADY_EXISTS)
                        return false;
                }
            }
        }
        if (i < normalized.size())
            current.push_back(normalized[i]);
    }
    return true;
}

bool WriteFileAtomic(const std::string& path, const std::string& content,
                     std::string& error) {
    const std::string tmp = path + ".tmp";
    const std::string parent = path.substr(0, path.find_last_of("\\/"));
    if (!parent.empty())
        EnsureDirectory(parent);

    HANDLE h = CreateFileA(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        error = "cannot create " + tmp + " (" + std::to_string(GetLastError()) + ")";
        return false;
    }

    DWORD written = 0;
    const BOOL ok = WriteFile(h, content.data(), static_cast<DWORD>(content.size()),
                              &written, nullptr);
    if (!ok || written != static_cast<DWORD>(content.size())) {
        error = "cannot write " + tmp;
        CloseHandle(h);
        DeleteFileA(tmp.c_str());
        return false;
    }
    FlushFileBuffers(h);
    CloseHandle(h);

    if (!MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        error = "cannot replace " + path + " (" + std::to_string(GetLastError()) + ")";
        DeleteFileA(tmp.c_str());
        return false;
    }
    return true;
}

bool ReadTextFile(const std::string& path, std::string& out) {
    HANDLE file = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return false;

    LARGE_INTEGER size;
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 || size.QuadPart > (8 << 20)) {
        CloseHandle(file);
        return false;
    }

    out.resize(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    const BOOL ok = out.empty() || ReadFile(file, &out[0],
                                            static_cast<DWORD>(out.size()), &read, nullptr);
    CloseHandle(file);
    if (!ok)
        return false;
    out.resize(read);
    return true;
}

bool ParseIsoUtc(const std::string& text, unsigned long long& filetimeOut) {
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    int consumed = 0;
    if (sscanf(text.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d%n", &year, &month, &day,
               &hour, &minute, &second, &consumed) != 6) {
        return false;
    }

    int milliseconds = 0;
    const std::string rest = text.substr(consumed);
    if (rest.size() > 1 && rest[0] == '.') {
        if (sscanf(rest.c_str() + 1, "%3d", &milliseconds) != 1)
            return false;
        if (milliseconds < 0 || milliseconds > 999)
            return false;
    }

    // Only UTC forms are accepted; offsets would silently shift the check.
    const bool utc = rest.empty() ||
                     rest.find('Z') != std::string::npos ||
                     rest.find("+00:00") != std::string::npos;
    if (!utc)
        return false;

    SYSTEMTIME st;
    ZeroMemory(&st, sizeof(st));
    st.wYear = static_cast<WORD>(year);
    st.wMonth = static_cast<WORD>(month);
    st.wDay = static_cast<WORD>(day);
    st.wHour = static_cast<WORD>(hour);
    st.wMinute = static_cast<WORD>(minute);
    st.wSecond = static_cast<WORD>(second);
    st.wMilliseconds = static_cast<WORD>(milliseconds);

    FILETIME ft;
    if (!SystemTimeToFileTime(&st, &ft))
        return false;

    ULARGE_INTEGER value;
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    filetimeOut = value.QuadPart;
    return true;
}

std::string JsonEscape(const std::string& s) {    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

} // namespace secargus
} // namespace kellect
