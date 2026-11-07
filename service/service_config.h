#pragma once
//
// Service configuration (config/agent.ini) -> collector argv.
//
// The service never takes a command line from the SCM: it reads one ini next to
// the executable, which makes the installed service self-describing and lets an
// operator change what is collected without touching the service registration.
//
#include <string>
#include <vector>

namespace kellect {
namespace svc {

struct ServiceOptions {
    // [service]
    std::string name = "KellectAgent";
    std::string displayName = "Kellect Agent";
    std::string description = "Kellect kernel event collector (ETW)";
    std::string startType = "auto";            // auto | demand | disabled
    std::string configPath;                    // resolved absolute path

    // [collector]
    std::string events = "all";                // -e  (hex mask or "all")
    std::string profile;                      // --profile overrides events
    std::string evidenceDirectory;            // --evidence-dir
    bool kernelEtl = false;                     // --kernel-etl
    std::string output = "file";               // file | probe | socket
    std::string file = "%ProgramData%\\Kellect\\events\\kellect-events.jsonl";
    std::string probeConfig = "config\\probe.ini";   // --probe-config
    std::string socket;                        // ip:port
    std::string userProvider;                  // 0x01 | 0x02 | 0x03
    std::string dropEvents;                    // -x comma separated
    bool wdm = false;
    int outputThreshold = 0;                   // 0 = collector default
    int maxFileMB = 1024;                      // --max-file-mb (0 = no rotation)
    bool append = true;                        // --append (keep events across restarts)
    std::string schemaProbe;                   // --schema-probe path
    bool schemaStrict = false;                 // --schema-strict
    int serializeThreads = 1;                  // --serialize-threads (1 keeps order)
    bool mqtt = false;                         // --mqtt (additive SecArgus output)
    std::string mqttConfig = "config\\secargus.ini";

    // Supervisor mode: run kellect.exe as a supervised child instead of
    // collecting in-process. Required for restart-to-apply-config and for
    // crash recovery without duplicate ETW sessions. Default off (behaviour
    // unchanged for existing installations).
    bool supervisor = false;
};

// Parse `path`. Missing file is not an error: the defaults above apply (the
// service still needs a config directory for the schema/filter files, which are
// resolved relative to the working directory set by the host).
bool LoadServiceConfig(const std::string& path, ServiceOptions& options, std::string& error);

// Build the argv handed to kellect::RunCollector (element 0 is a program name).
std::vector<std::string> BuildCollectorArgs(const ServiceOptions& options);

} // namespace svc
} // namespace kellect
