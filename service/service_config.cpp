#include "service_config.h"

#include <algorithm>
#include <cctype>
#include <fstream>

#include "service_util.h"

namespace kellect {
namespace svc {

namespace {

std::string Trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return std::string();
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::string Lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return out;
}

bool ToBool(const std::string& v) {
    const std::string lower = Lower(Trim(v));
    return lower == "1" || lower == "true" || lower == "yes" || lower == "on";
}

int ToInt(const std::string& v) {
    try { return std::stoi(Trim(v)); } catch (...) { return 0; }
}

// agent.ini is hand-edited, and the documented samples use trailing comments:
//     events=all        ; -e, or a hex mask like 0xbf
// A naive key=value reader would feed "all  ; ..." to the collector as -e and
// silently disable collection, so strip " ;"/" #"/"\t;"/"\t#" tails. Semicolons
// without leading whitespace are kept (paths can contain them).
std::string StripInlineComment(const std::string& v) {
    for (size_t i = 1; i < v.size(); ++i) {
        if ((v[i] == ';' || v[i] == '#')) {
            const char prev = v[i - 1];
            if (prev == ' ' || prev == '\t')
                return Trim(v.substr(0, i));
        }
    }
    return v;
}

} // namespace

bool LoadServiceConfig(const std::string& path, ServiceOptions& options, std::string& error) {
    options.configPath = path;

    std::ifstream in(path);
    if (!in.is_open()) {
        // Not an error: defaults are usable, and the collector falls back to
        // its own built-in defaults for filters.
        return true;
    }

    std::string section;
    std::string line;
    int lineNo = 0;

    while (std::getline(in, line)) {
        ++lineNo;
        line = Trim(line);
        if (line.empty()) continue;
        if (line[0] == '#' || line[0] == ';') continue;

        if (line.front() == '[') {
            size_t close = line.find(']');
            if (close == std::string::npos) {
                error = "line " + std::to_string(lineNo) + ": unterminated section header";
                return false;
            }
            section = Lower(Trim(line.substr(1, close - 1)));
            continue;
        }

        size_t eq = line.find('=');
        if (eq == std::string::npos) {
            error = "line " + std::to_string(lineNo) + ": expected key=value";
            return false;
        }

        const std::string key = Lower(Trim(line.substr(0, eq)));
        const std::string value = StripInlineComment(Trim(line.substr(eq + 1)));

        if (section == "service") {
            if (key == "name") options.name = value;
            else if (key == "displayname") options.displayName = value;
            else if (key == "description") options.description = value;
            else if (key == "starttype") options.startType = Lower(value);
            else if (key == "supervisor") options.supervisor = ToBool(value);
        } else if (section == "collector") {
            if (key == "events") options.events = value;
            else if (key == "profile") options.profile = value;
            else if (key == "evidencedirectory") options.evidenceDirectory = value;
            else if (key == "kerneletl") options.kernelEtl = ToBool(value);
            else if (key == "output") options.output = Lower(value);
            else if (key == "file") options.file = value;
            else if (key == "probeconfig") options.probeConfig = value;
            else if (key == "socket") options.socket = value;
            else if (key == "userprovider") options.userProvider = value;
            else if (key == "dropevents") options.dropEvents = value;
            else if (key == "wdm") options.wdm = ToBool(value);
            else if (key == "outputthreshold") options.outputThreshold = ToInt(value);
            else if (key == "maxfilemb") options.maxFileMB = ToInt(value);
            else if (key == "append") options.append = ToBool(value);
            else if (key == "schemaprobe") options.schemaProbe = value;
            else if (key == "schemastrict") options.schemaStrict = ToBool(value);
            else if (key == "serializethreads") options.serializeThreads = ToInt(value);
            else if (key == "mqtt") options.mqtt = ToBool(value);
            else if (key == "mqttconfig") options.mqttConfig = value;
        }
    }

    if (options.name.empty()) {
        error = "service name must not be empty";
        return false;
    }
    if (!options.output.empty() && options.output != "file" &&
        options.output != "probe" && options.output != "socket") {
        error = "unsupported collector output '" + options.output + "'; use file, probe or socket";
        return false;
    }

    // Resolve environment variables in paths and make relative paths absolute
    // against the executable directory (the service starts in System32).
    const std::string exeDir = ModuleDirectory();
    options.file = ExpandEnv(options.file);
    options.evidenceDirectory = ExpandEnv(options.evidenceDirectory);
    options.schemaProbe = ExpandEnv(options.schemaProbe);
    if (!options.file.empty() && options.file.find(':') == std::string::npos)
        options.file = JoinPath(exeDir, options.file);
    if (!options.schemaProbe.empty() && options.schemaProbe.find(':') == std::string::npos)
        options.schemaProbe = JoinPath(exeDir, options.schemaProbe);

    return true;
}

std::vector<std::string> BuildCollectorArgs(const ServiceOptions& options) {
    std::vector<std::string> args;
    args.push_back("kellect.exe");

    if (options.profile.empty()) {
        args.push_back("-e");
        args.push_back(options.events.empty() ? "all" : options.events);
    } else {
        args.push_back("--profile");
        args.push_back(options.profile);
    }
    if (!options.evidenceDirectory.empty()) {
        args.push_back("--evidence-dir");
        args.push_back(options.evidenceDirectory);
    }
    if (options.kernelEtl)
        args.push_back("--kernel-etl");

    if (!options.userProvider.empty()) {
        args.push_back("-u");
        args.push_back(options.userProvider);
    }

    const std::string output = options.output.empty() ? "file" : options.output;
    if (output == "socket" && !options.socket.empty()) {
        args.push_back("-s");
        args.push_back(options.socket);
    } else if (output == "probe") {
        // WebSocket + MessagePack to the Kellect backend; credentials live in
        // probe.ini so the service registration never carries a token.
        args.push_back("--probe");
        if (!options.probeConfig.empty()) {
            args.push_back("--probe-config");
            args.push_back(options.probeConfig);
        }
    } else {
        // A service has no console: file output is the fallback that never
        // silently discards events.
        if (options.append) args.push_back("--append");
        args.push_back("-f");
        args.push_back(options.file.empty() ? "kellect-events.jsonl" : options.file);
    }

    if (!options.dropEvents.empty()) {
        args.push_back("-x");
        args.push_back(options.dropEvents);
    }

    if (options.wdm) args.push_back("-wdm");

    if (options.outputThreshold > 0) {
        args.push_back("--outputThreshold");
        args.push_back(std::to_string(options.outputThreshold));
    }

    if (options.maxFileMB > 0 && output == "file") {
        args.push_back("--max-file-mb");
        args.push_back(std::to_string(options.maxFileMB));
    }

    if (options.serializeThreads > 0) {
        args.push_back("--serialize-threads");
        args.push_back(std::to_string(options.serializeThreads));
    }

    if (options.mqtt) {
        args.push_back("--mqtt");
        if (!options.mqttConfig.empty()) {
            args.push_back("--mqtt-config");
            args.push_back(options.mqttConfig);
        }
    }

    if (!options.schemaProbe.empty()) {
        args.push_back("--schema-probe");
        args.push_back(options.schemaProbe);
    }

    if (options.schemaStrict) args.push_back("--schema-strict");

    return args;
}

} // namespace svc
} // namespace kellect
