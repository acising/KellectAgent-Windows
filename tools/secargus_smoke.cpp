// Development smoke test for the SecArgus modules. Not part of the product
// build (CMake only globs source/*.cpp); built manually by the verification
// script in docs/SECARGUS-BUILD-TEST.zh-CN.md.
//
//   secargus_smoke --plain <host> <port>
//   secargus_smoke --tls   <host> <port> <ca.pem>
//   secargus_smoke --commands <workdir>
//
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "secargus/batch.h"
#include "secargus/commands.h"
#include "secargus/config.h"
#include "secargus/mqtt_client.h"
#include "secargus/mqtt_output.h"
#include "secargus/util.h"
#include "process/event.h"

using namespace kellect::secargus;

namespace {

int Fail(const std::string& message) {
    std::cerr << "FAIL: " << message << std::endl;
    return 1;
}

int RunPlain(const std::string& host, int port) {
    MqttSettings settings;
    settings.host = host;
    settings.port = port;
    settings.keepaliveS = 15;

    MqttClient client;
    std::string error;
    MqttClient::Will will;
    will.enabled = true;
    will.topic = "secargus/v1/endpoints/ep-smoke/status";
    will.payload = "{\"mqtt\":{\"state\":\"offline\"}}";
    will.qos = 1;
    will.retain = true;

    if (!client.Connect(settings, "kellect-ep-smoke", will, error))
        return Fail("connect: " + error);
    if (!client.Subscribe("secargus/v1/endpoints/ep-smoke/acks", 1, error))
        return Fail("subscribe: " + error);

    BatchBuilder builder(settings, "ep-smoke", "HOST-UUID-SMOKE");
    builder.AddLine("{\"Event\":\"ProcessStart\",\"PID\":4,\"TID\":4,"
                    "\"TimeStamp\":133253085392394264,\"Host-UUID\":\"HOST-UUID-SMOKE\","
                    "\"args\":{\"ImageFileName\":\"smoke.exe\"}}");
    std::string batchId;
    const std::string envelope = builder.Build(1, batchId);

    std::vector<MqttClient::Incoming> inbox;
    if (!client.Publish("secargus/v1/endpoints/ep-smoke/events", envelope, 1, false,
                        inbox, error))
        return Fail("publish: " + error);

    const ULONGLONG deadline = GetTickCount64() + 5000;
    bool gotAck = false;
    while (GetTickCount64() < deadline && !gotAck) {
        std::vector<MqttClient::Incoming> more;
        std::string pumpError;
        if (client.Pump(more, 300, pumpError)) {
            for (const auto& message : more) {
                if (message.topic == "secargus/v1/endpoints/ep-smoke/acks") {
                    std::cout << "ACK: " << message.payload << std::endl;
                    gotAck = true;
                }
            }
        } else if (pumpError != "timeout") {
            return Fail("pump: " + pumpError);
        }
        client.KeepAlive();
    }

    client.Close();
    if (!gotAck)
        return Fail("no business ACK within 5s");
    std::cout << "MQTT SMOKE PASS" << std::endl;
    return 0;
}

std::string ReplyField(const std::string& json, const std::string& key) {
    const std::string needle = "\"" + key + "\":";
    size_t pos = json.find(needle);
    if (pos == std::string::npos)
        return std::string();
    pos += needle.size();
    if (pos < json.size() && json[pos] == '"') {
        const size_t end = json.find('"', pos + 1);
        return json.substr(pos + 1, end - pos - 1);
    }
    return json.substr(pos, 32);
}

int RunOutput(const std::string& host, int port, const std::string& workdir) {
    SetCurrentDirectoryA(workdir.c_str());

    MqttSettings settings;
    settings.host = host;
    settings.port = port;
    settings.keepaliveS = 15;
    settings.flushIntervalMs = 200;
    settings.statusIntervalS = 1;
    settings.metricsIntervalS = 1;
    settings.spoolDirectory = "spool";
    settings.maxBatchEvents = 10;

    EndpointIdentity identity;
    identity.endpointId = "ep-smoke";
    identity.hostUuid = "HOST-UUID-SMOKE";
    identity.clientId = "kellect-ep-smoke";
    identity.kellectVersion = "2.0";

    CollectionInfo info;
    info.eventMask = 0x1ff;
    info.filterFile = "config\\filter.txt";
    info.startedAt = IsoNowUtc();

    {
        MqttOutput sink(settings, identity, info);
        if (sink.init() != STATUS_SUCCESS)
            return Fail("MqttOutput::init");

        std::string blob;
        blob += "{\"Event\":\"ProcessStart\",\"PID\":4,\"args\":{\"ImageFileName\":\"a.exe\"}}\n";
        blob += "{\"Event\":\"FileIOCreate\",\"PID\":4,\"args\":{\"FileName\":\"C:\\\\x\"}}\n";
        sink.output(blob);

        // Let the worker publish the batch, status and metrics, and process
        // the business ACK (which deletes the spool file).
        Sleep(3000);
        sink.waitFlushed(3000);
    }

    // After a persisted ACK the spool must be empty.
    WIN32_FIND_DATAA data;
    HANDLE find = FindFirstFileA("spool\\*.batch", &data);
    if (find != INVALID_HANDLE_VALUE) {
        FindClose(find);
        return Fail("spool still contains unacknowledged batches");
    }

    std::cout << "OUTPUT SMOKE PASS" << std::endl;
    return 0;
}

int RunCommands(const std::string& workdir) {    SetCurrentDirectoryA(workdir.c_str());

    // Simulate a loaded schema so validateEventNames() has a known set.
    EventIdentifier* known = new EventIdentifier(0x1234, 1, "FileIODirNotify");
    BaseEvent::eventStructMap[known] = std::list<BaseEvent::PropertyInfo>();

    MqttSettings settings;
    EndpointIdentity identity;
    identity.endpointId = "ep-smoke";
    identity.hostUuid = "HOST-UUID-SMOKE";
    identity.kellectVersion = "2.0";

    CollectionInfo info;
    info.eventMask = 0x1ff;
    info.filterFile = "config\\filter.txt";
    info.schemaName = "Win11";
    info.startedAt = IsoNowUtc();

    CommandProcessor::Context context;
    context.settings = settings;
    context.identity = identity;
    context.collection = info;
    context.statusJson = [] {
        return std::string("{\"protocol_version\":\"1.0\",\"message_type\":\"status\","
                           "\"endpoint_id\":\"ep-smoke\",\"collection\":{\"state\":\"collecting\"}}");
    };
    context.metricsJson = [] {
        return std::string("{\"protocol_version\":\"1.0\",\"message_type\":\"metrics\","
                           "\"endpoint_id\":\"ep-smoke\",\"events_per_s\":1.0}");
    };
    CommandProcessor processor(context);

    auto command = [](const std::string& id, const std::string& name,
                      const std::string& args,
                      const std::string& expires = std::string(),
                      const std::string& issued = std::string()) {
        std::string text = "{\"protocol_version\":\"1.0\",\"message_type\":\"command\","
                           "\"command_id\":\"" + id + "\",\"endpoint_id\":\"ep-smoke\","
                           "\"name\":\"" + name + "\",\"args\":" + args;
        if (!expires.empty()) text += ",\"expires_at\":\"" + expires + "\"";
        if (!issued.empty()) text += ",\"issued_at\":\"" + issued + "\"";
        text += "}";
        return text;
    };

    // 1) get_status
    const std::string statusReply = processor.Handle(command("c1", "get_status", "{}"), false);
    if (statusReply.find("\"status\":\"ok\"") == std::string::npos)
        return Fail("get_status reply: " + statusReply);
    if (statusReply.find("collecting") == std::string::npos)
        return Fail("get_status result: " + statusReply);
    std::cout << "get_status OK" << std::endl;

    // 2) idempotency
    const std::string replay = processor.Handle(command("c1", "get_status", "{}"), false);
    if (replay != statusReply)
        return Fail("duplicate command_id was not idempotent");

    // 3) retained commands are ignored
    if (!processor.Handle(command("c2", "get_status", "{}"), true).empty())
        return Fail("retained command was executed");

    // 4) unknown command
    const std::string unknown = processor.Handle(command("c3", "reboot", "{}"), false);
    if (unknown.find("\"status\":\"unsupported\"") == std::string::npos)
        return Fail("unknown command reply: " + unknown);
    std::cout << "unsupported OK" << std::endl;

    // 5) expired command
    const std::string expired = processor.Handle(
        command("c4", "get_status", "{}", "2000-01-01T00:00:00.000+00:00"), false);
    if (expired.find("\"status\":\"failed\"") == std::string::npos)
        return Fail("expired command accepted: " + expired);
    std::cout << "expiry OK" << std::endl;

    // 6) stale issued_at
    const std::string stale = processor.Handle(
        command("c5", "get_status", "{}", "", "2000-01-01T00:00:00.000+00:00"), false);
    if (stale.find("\"status\":\"failed\"") == std::string::npos)
        return Fail("stale command accepted: " + stale);

    // 7) update_collection_config -> requires_restart + files
    const std::string update = processor.Handle(
        command("c6", "update_collection_config",
                "{\"event_mask\":256,\"dropped_events\":[\"FileIODirNotify\"]}"),
        false);
    if (update.find("\"status\":\"requires_restart\"") == std::string::npos)
        return Fail("update reply: " + update);

    std::ifstream desired("config\\remote\\desired.json");
    if (!desired.is_open())
        return Fail("desired.json not written");
    std::string desiredText((std::istreambuf_iterator<char>(desired)),
                            std::istreambuf_iterator<char>());
    nlohmann::json desiredDoc = nlohmann::json::parse(desiredText, nullptr, false);
    if (desiredDoc.is_discarded() || desiredDoc.value("event_mask", 0) != 256)
        return Fail("desired.json content: " + desiredText);

    std::ifstream filter("config\\filter.txt");
    std::string filterText((std::istreambuf_iterator<char>(filter)),
                           std::istreambuf_iterator<char>());
    if (filterText.find("FileIODirNotify") == std::string::npos)
        return Fail("filter.txt was not rewritten");
    std::ifstream backup("config\\filter.txt.bak");
    if (!backup.is_open())
        return Fail("filter.txt.bak missing");

    // 8) event mask out of range
    const std::string badMask = processor.Handle(
        command("c7", "update_collection_config", "{\"event_mask\":4096}"), false);
    if (badMask.find("\"status\":\"failed\"") == std::string::npos)
        return Fail("bad mask accepted: " + badMask);

    // 9) unknown event name
    const std::string badName = processor.Handle(
        command("c8", "update_collection_config",
                "{\"dropped_events\":[\"NotARealEvent\"]}"),
        false);
    if (badName.find("\"status\":\"failed\"") == std::string::npos)
        return Fail("unknown event name accepted: " + badName);

    std::cout << "COMMANDS SMOKE PASS" << std::endl;
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc >= 2 && strcmp(argv[1], "--plain") == 0 && argc >= 4)
        return RunPlain(argv[2], atoi(argv[3]));
    if (argc >= 2 && strcmp(argv[1], "--output") == 0 && argc >= 5)
        return RunOutput(argv[2], atoi(argv[3]), argv[4]);
    if (argc >= 2 && strcmp(argv[1], "--commands") == 0 && argc >= 3)
        return RunCommands(argv[2]);
    std::cerr << "usage: secargus_smoke --plain <host> <port> | --output <host> <port> "
                 "<dir> | --commands <workdir>" << std::endl;
    return 2;
}
