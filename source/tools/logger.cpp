#include "tools/logger.h"
#include "tools/easylogging++.h"

#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <mutex>

//
// Diagnostics logger.
//
// easylogging++ was turned off for the hot path (every write flushed
// synchronously and cost an order of magnitude of throughput). A service,
// however, is unobservable without a log file: operators cannot attach a
// console. This implementation is deliberately small and safe to call from
// anywhere:
//   * one file, log\agent.log, appended and flushed at most twice a second,
//   * rotated to agent.1.log when it exceeds 16 MB,
//   * rate limited (200 lines/s) so a busy error path cannot stall parsing;
//     dropped lines are counted and reported.
//
namespace {

std::mutex g_mutex;
std::ofstream g_file;
std::string g_path = "log\\agent.log";
bool g_opened = false;
ULONGLONG g_size = 0;
std::chrono::steady_clock::time_point g_lastFlush;

constexpr ULONGLONG kMaxFileBytes = 16ull * 1024 * 1024;
constexpr int kMaxLinesPerSecond = 200;

int g_linesThisSecond = 0;
std::chrono::steady_clock::time_point g_secondStart;
std::atomic<uint64_t> g_dropped{ 0 };

void OpenLocked() {
    if (g_opened) return;

    // Create "log" (and any parent) relative to the working directory.
    size_t slash = g_path.find_last_of("\\/");
    if (slash != std::string::npos)
        CreateDirectoryA(g_path.substr(0, slash).c_str(), nullptr);

    g_file.open(g_path, std::ios::out | std::ios::app | std::ios::binary);
    if (!g_file.is_open())
        return;

    g_opened = true;
    g_size = static_cast<ULONGLONG>(g_file.tellp());
    g_lastFlush = std::chrono::steady_clock::now();
}

void RotateLocked() {
    if (!g_opened) return;

    g_file.close();
    g_opened = false;

    const std::string backup = g_path + ".1";
    DeleteFileA(backup.c_str());
    MoveFileA(g_path.c_str(), backup.c_str());

    OpenLocked();
}

void Timestamp(char* buffer, size_t size) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(buffer, size, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
             st.wMilliseconds);
}

} // namespace

void MyLogger::initLogger(std::string confile) {

    std::lock_guard<std::mutex> lock(g_mutex);

    // easylogging++ keeps its own (disabled, TO_FILE=false) configuration; it
    // is still initialised so a future re-enable does not change behaviour.
    if (!confile.empty()) {
        Configurations conf(confile);
        Loggers::reconfigureAllLoggers(conf);
        el::Loggers::setDefaultConfigurations(conf);
    }

    g_secondStart = std::chrono::steady_clock::now();
    OpenLocked();
}

void MyLogger::writeLog(std::string msg) {

    std::lock_guard<std::mutex> lock(g_mutex);

    const auto now = std::chrono::steady_clock::now();

    // Token-bucket style rate limit (per wall second).
    if (now - g_secondStart >= std::chrono::seconds(1)) {
        g_secondStart = now;
        g_linesThisSecond = 0;
    }
    if (g_linesThisSecond >= kMaxLinesPerSecond) {
        g_dropped.fetch_add(1);
        return;
    }
    ++g_linesThisSecond;

    OpenLocked();
    if (!g_opened)
        return;   // cannot log; do not throw/abort the application

    if (g_size > kMaxFileBytes)
        RotateLocked();

    char stamp[64];
    Timestamp(stamp, sizeof(stamp));

    char line[2048];
    const uint64_t dropped = g_dropped.exchange(0);
    if (dropped > 0) {
        snprintf(line, sizeof(line), "%s | WARN  | logger dropped %llu message(s)\n",
                 stamp, static_cast<unsigned long long>(dropped));
        g_file << line;
        g_size += strlen(line);
    }

    snprintf(line, sizeof(line), "%s | INFO  | [%lu] %s\n",
             stamp, static_cast<unsigned long>(GetCurrentThreadId()), msg.c_str());
    g_file << line;
    g_size += strlen(line);

    if (now - g_lastFlush >= std::chrono::milliseconds(500)) {
        g_file.flush();
        g_lastFlush = now;
    }
}
