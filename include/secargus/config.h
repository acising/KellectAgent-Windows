#pragma once
//
// SecArgus / MQTT configuration and endpoint identity.
//
#include <string>
#include <vector>

namespace kellect {
namespace secargus {

struct MqttSettings {
    bool enabled = false;
    std::string host = "127.0.0.1";
    int port = 1883;
    std::string username;
    std::string password;
    int keepaliveS = 30;
    std::string clientId;             // empty => kellect-<endpoint_id>
    bool cleanSession = true;
    int qos = 1;

    std::string topicPrefix = "secargus/v1/endpoints";
    std::string endpointConfig = "config\\endpoint.json";

    int maxBatchEvents = 500;
    int maxBatchBytes = 1048576;
    int flushIntervalMs = 1000;
    int maxQueueEvents = 200000;

    std::string spoolDirectory = "spool";
    long long maxSpoolBytes = 1073741824LL;
    int ackTimeoutMs = 30000;
    int maxRetries = 5;

    int statusIntervalS = 30;
    int metricsIntervalS = 60;

    std::string configPath;
};

struct EndpointIdentity {
    std::string endpointId;
    std::string hostUuid;
    std::string installationId;
    std::string hostname;
    std::string platform = "windows";
    std::string osVersion;
    std::string kellectVersion;
    std::string communicationVersion = "1.0";
    std::string clientId;             // MQTT client id
};

// Snapshot of the collector's effective configuration, provided by the
// Initializer and reported by get_collection_config. Only values that really
// exist in the running process are included.
struct CollectionInfo {
    unsigned eventMask = 0;
    unsigned userProviders = 0;
    std::string filterFile = "config\\filter.txt";
    std::string schemaName;
    std::string schemaFile;
    std::string startedAt;
    bool hotReload = false;           // the collector cannot reload in place
};

const char* const kDefaultSecargusConfig = "config\\secargus.ini";

bool LoadMqttSettings(const std::string& path, MqttSettings& out, std::string& error);

// Reads config/endpoint.json, creating it on first run. endpoint_id is derived
// from the Kellect Host-UUID unless the file already carries one, so identity
// survives restarts but stays distinct from Host-UUID (see design doc §10).
bool LoadOrCreateIdentity(const std::string& path, const std::string& hostUuid,
                          const std::string& hostname, const std::string& osVersion,
                          EndpointIdentity& out, std::string& error);

std::string BuildTopic(const MqttSettings& settings, const std::string& endpointId,
                       const std::string& suffix);

} // namespace secargus
} // namespace kellect
