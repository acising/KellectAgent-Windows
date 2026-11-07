#pragma once
//
// SecArgus command channel (design doc §9.6 / §12).
//
// Safety rules implemented here:
//   * whitelist only: get_status, get_capabilities, get_collection_config,
//     update_collection_config, start_collection, stop_collection, get_metrics;
//   * retained command messages are ignored (defense in depth: the broker must
//     not retain commands, but a stale retained command must never run);
//   * endpoint_id must match this endpoint;
//   * expires_at must be in the future, issued_at must not be older than 10 min;
//   * duplicate command_id returns the previous reply (idempotent);
//   * no arbitrary paths/commands: the only write targets are
//     config\remote\desired.json and config\filter.txt.
//
#include <deque>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "nlohmann/json.hpp"
#include "secargus/config.h"

namespace kellect {
namespace secargus {

class CommandProcessor {
public:
    struct Context {
        MqttSettings settings;
        EndpointIdentity identity;
        CollectionInfo collection;
        std::function<std::string()> statusJson;
        std::function<std::string()> metricsJson;
        std::function<void()> requestStop;
        std::function<void()> requestRestart;
    };

    explicit CommandProcessor(Context context);

    // Returns the reply payload, or an empty string when the message is ignored.
    std::string Handle(const std::string& payload, bool retained);

private:
    std::string dispatch(const std::string& commandId, const std::string& name,
                         const nlohmann::json& args);
    std::string reply(const std::string& commandId, const char* status,
                      const nlohmann::json& result, const std::string& error);
    std::string capabilities() const;
    std::string collectionConfig() const;
    std::string updateCollection(const std::string& commandId,
                                 const nlohmann::json& args);
    bool validateEventNames(const std::vector<std::string>& names,
                            std::string& error) const;
    bool rewriteDroppedEvents(const std::vector<std::string>& names,
                              std::string& error);

    Context context_;
    std::map<std::string, std::string> replies_;
    std::deque<std::string> replyOrder_;
    static constexpr size_t kMaxRemembered = 128;
};

} // namespace secargus
} // namespace kellect
