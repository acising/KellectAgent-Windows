#pragma once
//
// Cross-version ETW schema adaptation.
//
// Kernel (NT Kernel Logger) events have no instrumentation manifest: TDH cannot
// decode them, so kellect parses the raw UserData frame field-by-field with the
// layout declared in config/eventStruct_*.xml. Those layouts are OS-build
// dependent (Win7 -> Win10 added fields, Win11 may add/move more), which is why
// the old code hard-coded "6.1 ? win7.xml : win10.xml" and README said Win11 was
// unsupported.
//
// This module makes the layout side data-driven and self-checking:
//   * OS build -> profile (win7 / win8 / win8.1 / win10 / win11),
//   * schema-file selection from the XML root attributes
//     (MinBuild / MaxBuild), so a future eventStruct_win12.xml is picked up
//     without touching code,
//   * a drift tracker that records, per (provider, opcode), how the real frame
//     length compares with the layout. Drift is how you *find out* that a build
//     changed a frame; the --schema-probe run turns it into a report that the
//     win11 profile can be rebuilt from,
//   * a strict mode that drops (instead of best-effort parsing) frames whose
//     layout does not fit.
//
#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>

namespace kellect {
namespace schema {

enum class OsProfile : int {
    Unknown = 0,
    Win7 = 1,
    Win8 = 2,
    Win8_1 = 3,
    Win10 = 4,
    Win11 = 5,
};

struct OsInfo {
    unsigned major = 0;
    unsigned minor = 0;
    unsigned build = 0;
    unsigned ubr = 0;          // update build revision (UBR)
    OsProfile profile = OsProfile::Unknown;
    std::string displayName;   // e.g. "Windows 11 21H2 (build 22000.2538)"
    std::string schemaFile;    // resolved, e.g. "config/eventStruct_win11.xml"
};

// Detect the running OS (RtlGetVersion, not the manifest-lied
// GetVersionEx) and resolve the schema profile + schema file.
OsInfo DetectOs();

const char* ProfileName(OsProfile p);

// Pick the best <configDir>\eventStruct_*.xml for `build`:
// highest MinBuild <= build, skipping files whose MaxBuild < build.
// Falls back to the oldest profile when nothing matches. Empty if no schema
// file could be read at all.
std::string SelectSchemaFile(const std::string& configDir, unsigned build);

struct DriftKey {
    uint64_t providerId = 0;
    int opCode = 0;
    bool operator<(const DriftKey& o) const {
        if (providerId != o.providerId) return providerId < o.providerId;
        return opCode < o.opCode;
    }
};

struct DriftInfo {
    std::string eventName;
    uint64_t samples = 0;
    uint64_t exact = 0;      // layout consumed exactly UserDataLength
    uint64_t extended = 0;   // layout consumed less: unknown trailing fields
    uint64_t overflow = 0;   // layout wanted more bytes than the frame has
    uint32_t minLength = 0;
    uint32_t maxLength = 0;
    std::map<uint32_t, uint64_t> lengths;   // length histogram (capped)
};

// Process-wide drift statistics. The hot path is lock-free: Record() returns
// immediately for a matching frame unless probing is on.
class DriftTracker {
public:
    static DriftTracker& Instance();

    void SetProbeEnabled(bool on);
    bool ProbeEnabled() const;

    // `consumed` = bytes the layout actually consumed (clamped by the caller).
    // `truncated` = a field did not fit into the remaining frame.
    void Record(const DriftKey& key, const char* eventName,
                uint32_t length, uint32_t consumed, bool truncated);

    uint64_t Mismatches() const { return mismatches_.load(); }
    uint64_t Samples() const { return samples_.load(); }

    std::string Report() const;                        // human readable table
    bool WriteJsonReport(const std::string& path) const;

private:
    DriftTracker() = default;
    void WarnOnce(const DriftKey& key, const DriftInfo& info,
                  uint32_t length, uint32_t consumed);

    mutable std::mutex m_;
    std::map<DriftKey, DriftInfo> info_;
    std::set<DriftKey> warned_;
    std::atomic<uint64_t> mismatches_{0};
    std::atomic<uint64_t> samples_{0};
    std::atomic<bool> probe_{false};
};

// When true, frames whose layout does not fit are dropped instead of being
// emitted with a best-effort prefix. Default false (never lose data silently;
// the prefix is still valid, only the tail is unknown).
bool StrictMode();
void SetStrictMode(bool on);

// Optional path for the --schema-probe report, written when the collector
// stops (see collector_runner.cpp).
void SetProbeReportPath(const std::string& path);
std::string ProbeReportPath();

} // namespace schema
} // namespace kellect
