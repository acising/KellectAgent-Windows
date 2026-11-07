#include "secargus/commands.h"

#include <windows.h>

#include <algorithm>
#include <set>
#include <sstream>
#include <vector>

#include "process/event.h"
#include "secargus/util.h"

namespace kellect {
namespace secargus {

namespace {

unsigned long long NowFileTime() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER value;
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    return value.QuadPart;
}

const char* const kKnownSections[] = {
    "filteredProcessID", "droppedEventName", "filteredImageFile",
    "filteredEventIdentifier"
};

bool IsSectionName(const std::string& line) {
    for (const char* name : kKnownSections) {
        if (line == name)
            return true;
    }
    return false;
}

} // namespace

CommandProcessor::CommandProcessor(Context context) : context_(std::move(context)) {}

std::string CommandProcessor::reply(const std::string& commandId, const char* status,
                                    const nlohmann::json& result,
                                    const std::string& error) {
    nlohmann::json doc;
    doc["protocol_version"] = "1.0";
    doc["message_type"] = "command_reply";
    doc["endpoint_id"] = context_.identity.endpointId;
    doc["command_id"] = commandId;
    doc["status"] = status;
    doc["result"] = result;
    doc["error"] = error.empty() ? nlohmann::json(nullptr) : nlohmann::json(error);
    doc["finished_at"] = IsoNowUtc();

    const std::string text = doc.dump();
    if (replies_.find(commandId) == replies_.end()) {
        replies_[commandId] = text;
        replyOrder_.push_back(commandId);
        while (replyOrder_.size() > kMaxRemembered) {
            replies_.erase(replyOrder_.front());
            replyOrder_.pop_front();
        }
    }
    return text;
}

std::string CommandProcessor::capabilities() const {
    nlohmann::json caps = {
        { "commands",
          nlohmann::json::array({ "get_status", "get_capabilities",
                                  "get_collection_config", "update_collection_config",
                                  "start_collection", "stop_collection",
                                  "restart_collection", "get_metrics" }) },
        { "mqtt", { { "protocol", "3.1.1" }, { "qos", 1 } } },
        { "protocol_versions", nlohmann::json::array({ "1.0" }) },
        { "compression", nlohmann::json::array({ "none" }) },
        { "hot_reload", context_.collection.hotReload },
        { "requires_restart_for", nlohmann::json::array({ "event_mask", "filter" }) },
    };
    return caps.dump();
}

std::string CommandProcessor::collectionConfig() const {
    std::string filterContent;
    ReadTextFile(context_.collection.filterFile, filterContent);

    nlohmann::json result = {
        { "event_mask", context_.collection.eventMask },
        { "user_providers", context_.collection.userProviders },
        { "filter_file", context_.collection.filterFile },
        { "filter_sha256", Sha256Hex(filterContent) },
        { "schema", context_.collection.schemaName },
        { "schema_file", context_.collection.schemaFile },
        { "hot_reload", context_.collection.hotReload },
        { "config_version",
          "sha256:" + Sha256Hex(filterContent + "|" +
                                std::to_string(context_.collection.eventMask)) },
        { "effective_since", context_.collection.startedAt },
    };
    return result.dump();
}

bool CommandProcessor::validateEventNames(const std::vector<std::string>& names,
                                          std::string& error) const {
    std::set<std::string> known;
    for (const auto& entry : BaseEvent::eventStructMap) {
        if (entry.first != nullptr)
            known.insert(entry.first->getEventName());
    }

    // Schema not loaded (should not happen at runtime): accept syntactically
    // valid names rather than blocking the operator.
    for (const std::string& name : names) {
        if (name.empty() || name.size() > 64) {
            error = "invalid event name length";
            return false;
        }
        for (char c : name) {
            const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                            (c >= '0' && c <= '9') || c == '_';
            if (!ok) {
                error = "invalid character in event name: " + name;
                return false;
            }
        }
        if (!known.empty() && known.count(name) == 0) {
            error = "unknown event name: " + name;
            return false;
        }
    }
    return true;
}

bool CommandProcessor::rewriteDroppedEvents(const std::vector<std::string>& names,
                                            std::string& error) {
    std::string content;
    if (!ReadTextFile(context_.collection.filterFile, content)) {
        error = "cannot read " + context_.collection.filterFile;
        return false;
    }

    const std::string newline =
        content.find("\r\n") != std::string::npos ? "\r\n" : "\n";

    std::vector<std::string> lines;
    size_t offset = 0;
    while (offset <= content.size()) {
        const size_t end = content.find('\n', offset);
        std::string line = (end == std::string::npos)
                               ? content.substr(offset)
                               : content.substr(offset, end - offset);
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        lines.push_back(line);
        if (end == std::string::npos)
            break;
        offset = end + 1;
    }

    int start = -1;
    for (size_t i = 0; i < lines.size(); ++i) {
        if (Trim(lines[i]) == "droppedEventName") {
            start = static_cast<int>(i);
            break;
        }
    }

    int end = static_cast<int>(lines.size());
    if (start >= 0) {
        for (size_t j = static_cast<size_t>(start) + 1; j < lines.size(); ++j) {
            if (IsSectionName(Trim(lines[j]))) {
                end = static_cast<int>(j);
                break;
            }
        }
    }

    std::vector<std::string> section;
    section.push_back("droppedEventName");
    section.push_back("# managed by secargus at " + IsoNowUtc());
    for (const std::string& name : names)
        section.push_back(name);
    section.push_back(std::string());

    std::vector<std::string> updated;
    if (start < 0) {
        updated = lines;
        if (!updated.empty() && updated.back().empty())
            updated.pop_back();
        updated.push_back(std::string());
        updated.insert(updated.end(), section.begin(), section.end());
    } else {
        updated.insert(updated.end(), lines.begin(), lines.begin() + start);
        updated.insert(updated.end(), section.begin(), section.end());
        updated.insert(updated.end(), lines.begin() + end, lines.end());
    }

    std::string text;
    for (const std::string& line : updated) {
        text += line;
        text += newline;
    }

    // Keep the previous file for rollback before the atomic replace.
    if (!WriteFileAtomic(context_.collection.filterFile + ".bak", content, error))
        return false;
    if (!WriteFileAtomic(context_.collection.filterFile, text, error))
        return false;

    // Verify what was actually written.
    std::string check;
    if (!ReadTextFile(context_.collection.filterFile, check)) {
        error = "cannot re-read the filter file";
        return false;
    }
    std::set<std::string> present;
    std::istringstream stream(check);
    std::string line;
    while (std::getline(stream, line))
        present.insert(Trim(line));
    for (const std::string& name : names) {
        if (present.count(name) == 0) {
            error = "filter verification failed for " + name;
            return false;
        }
    }
    return true;
}

std::string CommandProcessor::updateCollection(const std::string& commandId,
                                               const nlohmann::json& args) {
    if (!args.is_object())
        return reply(commandId, "failed", nlohmann::json(nullptr),
                     "args must be an object");

    const bool hasMask = args.contains("event_mask");
    const bool hasDropped = args.contains("dropped_events");
    if (!hasMask && !hasDropped)
        return reply(commandId, "failed", nlohmann::json(nullptr),
                     "no supported keys (event_mask, dropped_events)");

    long long mask = static_cast<long long>(context_.collection.eventMask);
    if (hasMask) {
        if (!args["event_mask"].is_number_integer())
            return reply(commandId, "failed", nlohmann::json(nullptr),
                         "event_mask must be an integer");
        mask = args["event_mask"].get<long long>();
        if (mask < 0 || mask > 0x3ff)
            return reply(commandId, "failed", nlohmann::json(nullptr),
                         "event_mask out of range (0..0x3ff)");
    }

    std::vector<std::string> dropped;
    if (hasDropped) {
        if (!args["dropped_events"].is_array())
            return reply(commandId, "failed", nlohmann::json(nullptr),
                         "dropped_events must be an array");
        if (args["dropped_events"].size() > 256)
            return reply(commandId, "failed", nlohmann::json(nullptr),
                         "too many dropped_events (max 256)");
        for (const auto& item : args["dropped_events"]) {
            if (!item.is_string())
                return reply(commandId, "failed", nlohmann::json(nullptr),
                             "dropped_events must contain strings");
            dropped.push_back(item.get<std::string>());
        }
        std::string error;
        if (!validateEventNames(dropped, error))
            return reply(commandId, "failed", nlohmann::json(nullptr), error);
    }

    nlohmann::json desired;
    desired["protocol_version"] = "1.0";
    desired["endpoint_id"] = context_.identity.endpointId;
    desired["command_id"] = commandId;
    desired["event_mask"] = mask;
    desired["dropped_events"] = dropped;
    desired["received_at"] = IsoNowUtc();
    const std::string version = "sha256:" + Sha256Hex(desired.dump());
    desired["desired_version"] = version;

    std::string error;
    if (!WriteFileAtomic("config\\remote\\desired.json", desired.dump(2) + "\n", error))
        return reply(commandId, "failed", nlohmann::json(nullptr),
                     "cannot write desired.json: " + error);

    bool filterWritten = false;
    if (hasDropped) {
        if (!rewriteDroppedEvents(dropped, error))
            return reply(commandId, "failed", nlohmann::json(nullptr),
                         "filter update failed: " + error);
        filterWritten = true;
    }

    nlohmann::json applied = nlohmann::json::array();
    applied.push_back("config/remote/desired.json");
    if (filterWritten)
        applied.push_back("config/filter.txt");

    nlohmann::json pending = nlohmann::json::array();
    pending.push_back("event_mask");
    pending.push_back("filter");

    const bool restart = args.contains("restart") && args["restart"].is_boolean() &&
                          args["restart"].get<bool>();
    nlohmann::json result;
    result["requires_restart"] = !restart;
    result["restart_scheduled"] = restart;
    result["desired_version"] = version;
    result["effective_version"] =
        "sha256:" + Sha256Hex(std::to_string(context_.collection.eventMask));
    result["applied"] = applied;
    result["pending"] = pending;
    result["message"] = restart
        ? "configuration written; collector restart scheduled"
        : "event mask and filter are read at startup; restart the collector to apply";
    if (restart && context_.requestRestart)
        context_.requestRestart();

    return reply(commandId, restart ? "ok" : "requires_restart", result, "");
}

std::string CommandProcessor::dispatch(const std::string& commandId,
                                       const std::string& name,
                                       const nlohmann::json& args) {
    if (name == "get_status" || name == "get_metrics") {
        const std::string text =
            (name == "get_status") ? context_.statusJson() : context_.metricsJson();
        nlohmann::json doc = nlohmann::json::parse(text, nullptr, false);
        if (doc.is_discarded())
            return reply(commandId, "failed", nlohmann::json(nullptr),
                         "status is unavailable");
        return reply(commandId, "ok", doc, "");
    }

    if (name == "get_capabilities") {
        nlohmann::json doc = nlohmann::json::parse(capabilities(), nullptr, false);
        if (doc.is_discarded())
            return reply(commandId, "failed", nlohmann::json(nullptr),
                         "capabilities unavailable");
        return reply(commandId, "ok", doc, "");
    }

    if (name == "get_collection_config") {
        nlohmann::json doc = nlohmann::json::parse(collectionConfig(), nullptr, false);
        if (doc.is_discarded())
            return reply(commandId, "failed", nlohmann::json(nullptr),
                         "configuration unavailable");
        return reply(commandId, "ok", doc, "");
    }

    if (name == "update_collection_config")
        return updateCollection(commandId, args);

    if (name == "start_collection") {
        nlohmann::json result;
        result["state"] = "collecting";
        result["already_running"] = true;
        return reply(commandId, "ok", result, "");
    }

    if (name == "stop_collection") {
        if (!context_.requestStop)
            return reply(commandId, "failed", nlohmann::json(nullptr),
                         "stop is not available in this build");
        // Reply is published first; the callback waits briefly and then stops.
        context_.requestStop();
        nlohmann::json result;
        result["state"] = "stopping";
        result["message"] = "collector stopping; supervisor/service may restart it";
        return reply(commandId, "ok", result, "");
    }

    if (name == "restart_collection") {
        if (!context_.requestRestart)
            return reply(commandId, "failed", nlohmann::json(nullptr),
                         "restart is not available in this build");
        context_.requestRestart();
        nlohmann::json result;
        result["state"] = "restarting";
        result["requires_restart"] = true;
        result["message"] =
            "collector stopping; supervisor/service will start a new instance";
        return reply(commandId, "ok", result, "");
    }

    return reply(commandId, "unsupported", nlohmann::json(nullptr),
                 "unknown command: " + name);
}

std::string CommandProcessor::Handle(const std::string& payload, bool retained) {
    // A retained command would be replayed on every reconnect: never execute it.
    if (retained)
        return std::string();

    nlohmann::json doc = nlohmann::json::parse(payload, nullptr, false);
    if (doc.is_discarded() || !doc.is_object())
        return std::string();

    const std::string commandId = doc.value("command_id", std::string());
    const std::string name = doc.value("name", std::string());
    if (commandId.empty() || name.empty())
        return std::string();

    if (doc.value("message_type", std::string()) != "command")
        return std::string();

    if (doc.value("endpoint_id", std::string()) != context_.identity.endpointId)
        return std::string();   // not addressed to this endpoint

    if (doc.value("protocol_version", std::string()) != "1.0")
        return reply(commandId, "failed", nlohmann::json(nullptr),
                     "unsupported protocol_version");

    // Idempotency: replay the previous answer for a duplicate command_id.
    auto cached = replies_.find(commandId);
    if (cached != replies_.end())
        return cached->second;

    const std::string expiresAt = doc.value("expires_at", std::string());
    if (!expiresAt.empty()) {
        unsigned long long filetime = 0;
        if (!ParseIsoUtc(expiresAt, filetime))
            return reply(commandId, "failed", nlohmann::json(nullptr),
                         "invalid expires_at");
        if (NowFileTime() > filetime)
            return reply(commandId, "failed", nlohmann::json(nullptr), "command expired");
    }

    const std::string issuedAt = doc.value("issued_at", std::string());
    if (!issuedAt.empty()) {
        unsigned long long filetime = 0;
        if (!ParseIsoUtc(issuedAt, filetime))
            return reply(commandId, "failed", nlohmann::json(nullptr),
                         "invalid issued_at");
        // 10 minutes of tolerance for clock skew / delayed delivery.
        if (NowFileTime() > filetime + 600ull * 10000000ull)
            return reply(commandId, "failed", nlohmann::json(nullptr),
                         "stale command (issued_at too old)");
    }

    nlohmann::json args = nlohmann::json::object();
    if (doc.contains("args") && doc["args"].is_object())
        args = doc["args"];

    return dispatch(commandId, name, args);
}

} // namespace secargus
} // namespace kellect
