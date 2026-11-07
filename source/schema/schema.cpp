#include "schema/schema.h"

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <vector>

#include "tools/tinyxml2.h"

namespace kellect {
namespace schema {

namespace {

const char* kProfileNames[] = { "unknown", "win7", "win8", "win8.1", "win10", "win11" };

std::string JsonEscape(const std::string& s) {
    std::string out;
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
                    snprintf(buf, sizeof(buf), "\\u%04x", (unsigned)c);
                    out += buf;
                } else {
                    out += (char)c;
                }
        }
    }
    return out;
}

// RtlGetVersion is not affected by the exe manifest's compatibility section,
// unlike GetVersionEx (which reports 6.2 on Win8.1+/10+ without a manifest lie).
bool QueryOsVersion(unsigned& major, unsigned& minor, unsigned& build, unsigned& ubr) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) ntdll = LoadLibraryW(L"ntdll.dll");
    if (!ntdll) return false;

    typedef LONG(WINAPI * RtlGetVersionFn)(OSVERSIONINFOEXW*);
    RtlGetVersionFn fn = (RtlGetVersionFn)(void*)GetProcAddress(ntdll, "RtlGetVersion");
    if (!fn) return false;

    // OSVERSIONINFOEXW has the same layout RtlGetVersion expects; using the
    // user-mode type avoids depending on the ntddk typedef.
    OSVERSIONINFOEXW vi;
    ZeroMemory(&vi, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (fn(&vi) != 0 /* STATUS_SUCCESS */) return false;

    major = vi.dwMajorVersion;
    minor = vi.dwMinorVersion;
    // Win10+: low 16 bits build, high 16 bits UBR.
    build = vi.dwBuildNumber & 0xFFFFu;
    ubr = (unsigned)(vi.dwBuildNumber >> 16);
    return true;
}

std::string BuildDisplayName(unsigned major, unsigned minor, unsigned build, unsigned ubr) {
    char buf[128];
    const char* family = "Windows";
    if (major == 6 && minor == 1) family = "Windows 7";
    else if (major == 6 && minor == 2) family = "Windows 8";
    else if (major == 6 && minor == 3) family = "Windows 8.1";
    else if (major == 10 && build < 22000) family = "Windows 10";
    else if (major == 10) family = "Windows 11";
    else if (major > 10) family = "Windows (newer than 11)";

    if (major == 10 && build >= 22000) {
        // 21H2=22000, 22H2=22621, 23H2=22631, 24H2=26100
        const char* release = "";
        if (build >= 26100) release = "24H2+";
        else if (build >= 22631) release = "23H2";
        else if (build >= 22621) release = "22H2";
        else release = "21H2";
        snprintf(buf, sizeof(buf), "%s %s (build %u.%u)", family, release, build, ubr);
    } else {
        snprintf(buf, sizeof(buf), "%s (build %u.%u)", family, build, ubr);
    }
    return buf;
}

OsProfile ProfileFor(unsigned major, unsigned minor, unsigned build) {
    if (major == 6 && minor == 1) return OsProfile::Win7;
    if (major == 6 && minor == 2) return OsProfile::Win8;
    if (major == 6 && minor == 3) return OsProfile::Win8_1;
    if (major == 10 && build < 22000) return OsProfile::Win10;
    if (major >= 10 && build >= 22000) return OsProfile::Win11;
    return OsProfile::Unknown;
}

struct Candidate {
    std::string path;
    unsigned minBuild = 0;
    unsigned maxBuild = 0;
};

} // namespace

OsInfo DetectOs() {
    OsInfo info;
    if (!QueryOsVersion(info.major, info.minor, info.build, info.ubr)) {
        info.major = 10;
        info.minor = 0;
        info.build = 0;
        info.ubr = 0;
    }
    info.profile = ProfileFor(info.major, info.minor, info.build);
    info.displayName = BuildDisplayName(info.major, info.minor, info.build, info.ubr);
    return info;
}

const char* ProfileName(OsProfile p) {
    int i = (int)p;
    if (i < 0 || i > 5) i = 0;
    return kProfileNames[i];
}

std::string SelectSchemaFile(const std::string& configDir, unsigned build) {
    std::string dir = configDir;
    if (!dir.empty() && (dir.back() == '\\' || dir.back() == '/')) dir.pop_back();

    std::string pattern = dir + "\\eventStruct_*.xml";
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return "";

    std::vector<Candidate> candidates;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        Candidate c;
        c.path = dir + "\\" + fd.cFileName;

        tinyxml2::XMLDocument doc;
        if (doc.LoadFile(c.path.c_str()) != 0) continue;
        tinyxml2::XMLElement* root = doc.RootElement();
        if (!root) continue;

        c.minBuild = (unsigned)root->IntAttribute("MinBuild", 0);
        c.maxBuild = (unsigned)root->IntAttribute("MaxBuild", 0);
        candidates.push_back(c);
    } while (FindNextFileA(h, &fd));
    FindClose(h);

    if (candidates.empty()) return "";

    const Candidate* best = nullptr;
    for (const Candidate& c : candidates) {
        if (c.minBuild > build) continue;
        if (c.maxBuild != 0 && build > c.maxBuild) continue;
        if (!best || c.minBuild > best->minBuild) best = &c;
    }
    if (!best) {
        // Nothing declares to cover this build: use the oldest known layout so
        // the drift tracker can report what actually arrived.
        for (const Candidate& c : candidates) {
            if (!best || c.minBuild < best->minBuild) best = &c;
        }
    }
    return best ? best->path : "";
}

// ---------------------------------------------------------------------------
// Drift tracker
// ---------------------------------------------------------------------------

static std::atomic<bool> g_strict{false};

bool StrictMode() { return g_strict.load(); }
void SetStrictMode(bool on) { g_strict = on; }

static std::string g_probeReportPath;

void SetProbeReportPath(const std::string& path) { g_probeReportPath = path; }
std::string ProbeReportPath() { return g_probeReportPath; }

DriftTracker& DriftTracker::Instance() {
    static DriftTracker tracker;
    return tracker;
}

void DriftTracker::SetProbeEnabled(bool on) { probe_ = on; }
bool DriftTracker::ProbeEnabled() const { return probe_.load(); }

void DriftTracker::Record(const DriftKey& key, const char* eventName,
                          uint32_t length, uint32_t consumed, bool truncated) {
    const bool exact = (!truncated && consumed == length);

    // Fast path: a frame that fits its layout needs no bookkeeping unless the
    // operator asked for a full probe.
    if (exact && !probe_.load()) return;

    samples_.fetch_add(1);
    if (!exact) mismatches_.fetch_add(1);

    DriftInfo snapshot;
    bool warn = false;
    {
        std::lock_guard<std::mutex> g(m_);
        DriftInfo& info = info_[key];
        if (info.eventName.empty() && eventName) info.eventName = eventName;
        if (info.samples == 0) {
            info.minLength = length;
            info.maxLength = length;
        } else {
            if (length < info.minLength) info.minLength = length;
            if (length > info.maxLength) info.maxLength = length;
        }
        ++info.samples;

        if (info.lengths.size() < 64 || info.lengths.count(length) != 0)
            ++info.lengths[length];

        if (exact) {
            ++info.exact;
        } else if (truncated) {
            ++info.overflow;
            warn = warned_.insert(key).second;
        } else if (consumed < length) {
            // Newer build appended fields we do not know: layout prefix is
            // still correct, the tail is simply not decoded.
            ++info.extended;
        } else {
            ++info.overflow;
            warn = warned_.insert(key).second;
        }
        snapshot = info;
    }

    if (warn) WarnOnce(key, snapshot, length, consumed);
}

void DriftTracker::WarnOnce(const DriftKey& key, const DriftInfo& info,
                            uint32_t length, uint32_t consumed) {
    fprintf(stderr,
            "[schema] layout mismatch: provider=%llu opcode=%d event=%s "
            "frameLen=%u consumed=%u samples=%llu. "
            "Run with --schema-probe to collect a report.\n",
            (unsigned long long)key.providerId, key.opCode,
            info.eventName.empty() ? "?" : info.eventName.c_str(),
            length, consumed, (unsigned long long)info.samples);
}

std::string DriftTracker::Report() const {
    std::lock_guard<std::mutex> g(m_);

    std::ostringstream out;
    out << "schema drift report\n";
    out << "  samples=" << samples_.load() << " mismatches=" << mismatches_.load()
        << " tracked=" << info_.size() << "\n";

    for (const auto& kv : info_) {
        const DriftInfo& i = kv.second;
        if (i.overflow == 0 && i.extended == 0) continue;
        out << "  " << (i.eventName.empty() ? "?" : i.eventName)
            << " [provider=" << kv.first.providerId << " opcode=" << kv.first.opCode << "]"
            << " samples=" << i.samples
            << " exact=" << i.exact
            << " extended=" << i.extended
            << " overflow=" << i.overflow
            << " len=" << i.minLength;
        if (i.maxLength != i.minLength) out << ".." << i.maxLength;
        out << "\n";
    }
    return out.str();
}

bool DriftTracker::WriteJsonReport(const std::string& path) const {
    std::lock_guard<std::mutex> g(m_);

    std::ofstream f(path, std::ios::trunc);
    if (!f.is_open()) return false;

    f << "{\n";
    f << "  \"samples\": " << samples_.load() << ",\n";
    f << "  \"mismatches\": " << mismatches_.load() << ",\n";
    f << "  \"events\": [\n";
    bool first = true;
    for (const auto& kv : info_) {
        const DriftInfo& i = kv.second;
        if (!first) f << ",\n";
        first = false;
        f << "    {\"providerId\": " << kv.first.providerId
          << ", \"opCode\": " << kv.first.opCode
          << ", \"eventName\": \"" << JsonEscape(i.eventName) << "\""
          << ", \"samples\": " << i.samples
          << ", \"exact\": " << i.exact
          << ", \"extended\": " << i.extended
          << ", \"overflow\": " << i.overflow
          << ", \"minLength\": " << i.minLength
          << ", \"maxLength\": " << i.maxLength
          << ", \"lengths\": {";
        bool firstLen = true;
        for (const auto& lv : i.lengths) {
            if (!firstLen) f << ", ";
            firstLen = false;
            f << "\"" << lv.first << "\": " << lv.second;
        }
        f << "}}";
    }
    f << "\n  ]\n}\n";
    return true;
}

} // namespace schema
} // namespace kellect
