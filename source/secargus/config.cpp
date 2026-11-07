#include "secargus/config.h"

#include <fstream>

#include "nlohmann/json.hpp"
#include "secargus/util.h"

namespace kellect {
namespace secargus {

namespace {

bool ToBool(const std::string& v) {
    const std::string lower = Lower(Trim(v));
    return lower == "1" || lower == "true" || lower == "yes" || lower == "on";
}

int ToInt(const std::string& v, int fallback) {
    try { return std::stoi(Trim(v)); } catch (...) { return fallback; }
}

long long ToLongLong(const std::string& v, long long fallback) {
    try { return std::stoll(Trim(v)); } catch (...) { return fallback; }
}

// Strips a trailing " ; comment" / " # comment" (samples use them).
std::string StripInlineComment(const std::string& v) {
    for (size_t i = 1; i < v.size(); ++i) {
        if (v[i] == ';' || v[i] == '#') {
            const char prev = v[i - 1];
            if (prev == ' ' || prev == '\t')
                return Trim(v.substr(0, i));
        }
    }
    return v;
}

} // namespace

bool LoadMqttSettings(const std::string& path, MqttSettings& out, std::string& error) {
    out.configPath = path;

    std::ifstream in(path);
    if (!in.is_open())
        return true;   // disabled by absence

    std::string section;
    std::string line;
    int lineNo = 0;

    while (std::getline(in, line)) {
        ++lineNo;
        line = Trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';')
            continue;

        if (line[0] == '[') {
            const size_t close = line.find(']');
            if (close == std::string::npos) {
                error = "line " + std::to_string(lineNo) + ": unterminated section";
                return false;
            }
            section = Lower(Trim(line.substr(1, close - 1)));
            continue;
        }

        const size_t eq = line.find('=');
        if (eq == std::string::npos) {
            error = "line " + std::to_string(lineNo) + ": expected key=value";
            return false;
        }

        const std::string key = Lower(Trim(line.substr(0, eq)));
        const std::string value = StripInlineComment(Trim(line.substr(eq + 1)));

        if (section == "secargus") {
            if (key == "enabled") out.enabled = ToBool(value);
            else if (key == "endpoint_config") out.endpointConfig = value;
        } else if (section == "mqtt") {
            if (key == "host") out.host = value;
            else if (key == "port") out.port = ToInt(value, out.port);
            else if (key == "username") out.username = value;
            else if (key == "password") out.password = value;
            else if (key == "keepalive_s") out.keepaliveS = ToInt(value, out.keepaliveS);
            else if (key == "client_id") out.clientId = value;
            else if (key == "clean_start" || key == "clean_session")
                out.cleanSession = ToBool(value);
            else if (key == "qos") out.qos = ToInt(value, out.qos);
        } else if (section == "topics") {
            if (key == "prefix") out.topicPrefix = value;
        } else if (section == "events") {
            if (key == "max_batch_events") out.maxBatchEvents = ToInt(value, out.maxBatchEvents);
            else if (key == "max_batch_bytes") out.maxBatchBytes = ToInt(value, out.maxBatchBytes);
            else if (key == "flush_interval_ms") out.flushIntervalMs = ToInt(value, out.flushIntervalMs);
            else if (key == "max_queue_events") out.maxQueueEvents = ToInt(value, out.maxQueueEvents);
        } else if (section == "spool") {
            if (key == "directory") out.spoolDirectory = value;
            else if (key == "max_bytes") out.maxSpoolBytes = ToLongLong(value, out.maxSpoolBytes);
            else if (key == "ack_timeout_ms") out.ackTimeoutMs = ToInt(value, out.ackTimeoutMs);
            else if (key == "max_retries") out.maxRetries = ToInt(value, out.maxRetries);
        } else if (section == "status") {
            if (key == "interval_s") out.statusIntervalS = ToInt(value, out.statusIntervalS);
        } else if (section == "metrics") {
            if (key == "interval_s") out.metricsIntervalS = ToInt(value, out.metricsIntervalS);
        }
    }

    if (out.port <= 0 || out.port > 65535) {
        error = "invalid mqtt port";
        return false;
    }
    if (out.qos < 0 || out.qos > 1) {
        error = "only qos 0/1 are supported";
        return false;
    }
    if (out.maxBatchEvents <= 0 || out.maxBatchEvents > 5000) {
        error = "max_batch_events out of range";
        return false;
    }
    if (out.maxBatchBytes < 1024) {
        error = "max_batch_bytes too small";
        return false;
    }
    return true;
}

bool LoadOrCreateIdentity(const std::string& path, const std::string& hostUuid,
                          const std::string& hostname, const std::string& osVersion,
                          EndpointIdentity& out, std::string& error) {
    nlohmann::json doc;

    std::ifstream in(path);
    const bool existed = in.is_open();
    if (existed) {
        try {
            in >> doc;
        } catch (const std::exception& e) {
            error = std::string("invalid ") + path + ": " + e.what();
            return false;
        }
    }
    in.close();

    if (!doc.is_object())
        doc = nlohmann::json::object();

    out.hostUuid = hostUuid;
    out.endpointId = doc.value("endpoint_id", std::string());
    out.installationId = doc.value("installation_id", std::string());
    out.hostname = doc.value("hostname", hostname);
    out.platform = doc.value("platform", std::string("windows"));
    out.osVersion = doc.value("os_version", osVersion);
    out.kellectVersion = doc.value("kellect_version", std::string("2.0"));
    out.communicationVersion = doc.value("communication_version", std::string("1.0"));
    out.clientId = doc.value("mqtt_client_id", std::string());

    bool changed = false;

    if (out.endpointId.empty()) {
        // Stable default derived from the Kellect Host-UUID; can be overridden
        // by editing endpoint.json before first registration.
        out.endpointId = "ep-" + Sha256Hex("endpoint|" + hostUuid).substr(0, 12);
        changed = true;
    }
    if (out.installationId.empty()) {
        out.installationId = "inst-" + Sha256Hex("install|" + hostUuid + "|" + IsoNowUtc()).substr(0, 12);
        changed = true;
    }
    if (out.clientId.empty()) {
        out.clientId = "kellect-" + out.endpointId;
        changed = true;
    }

    if (changed || !existed) {
        nlohmann::json updated = {
            { "endpoint_id", out.endpointId },
            { "host_uuid", out.hostUuid },
            { "installation_id", out.installationId },
            { "hostname", out.hostname },
            { "platform", out.platform },
            { "os_version", out.osVersion },
            { "kellect_version", out.kellectVersion },
            { "communication_version", out.communicationVersion },
            { "mqtt_client_id", out.clientId },
            { "created_at", doc.value("created_at", IsoNowUtc()) },
        };
        if (!WriteFileAtomic(path, updated.dump(2) + "\n", error))
            return false;
    }

    return true;
}

std::string BuildTopic(const MqttSettings& settings, const std::string& endpointId,
                       const std::string& suffix) {
    std::string prefix = settings.topicPrefix;
    while (!prefix.empty() && prefix.back() == '/')
        prefix.pop_back();
    return prefix + "/" + endpointId + "/" + suffix;
}

} // namespace secargus
} // namespace kellect
