#include "tools/stats.h"

#include <cstdio>
#include <map>
#include <mutex>
#include <string>

#include "process/event_parse.h"
#include "secargus/mqtt_stats.h"
#include "tools/logger.h"

namespace kellect {
namespace stats {

#define KELLECT_STATS_DEF(name) alignas(64) std::atomic<uint64_t> name{ 0 }

KELLECT_STATS_DEF(eventsReceived);
KELLECT_STATS_DEF(eventsFiltered);
KELLECT_STATS_DEF(eventsUnknown);
KELLECT_STATS_DEF(eventsSchemaUnknown);
KELLECT_STATS_DEF(eventsDecodeFailed);
KELLECT_STATS_DEF(eventsFilteredThird);
KELLECT_STATS_DEF(eventsStackIncomplete);
KELLECT_STATS_DEF(fileRundown);
KELLECT_STATS_DEF(registryRundown);
KELLECT_STATS_DEF(imageRundown);
KELLECT_STATS_DEF(threadRundown);
KELLECT_STATS_DEF(threadOther);
KELLECT_STATS_DEF(diskSideEvents);
KELLECT_STATS_DEF(eventsDroppedParse);
KELLECT_STATS_DEF(eventsParsed);
KELLECT_STATS_DEF(eventsQueued);
KELLECT_STATS_DEF(outputWaits);
KELLECT_STATS_DEF(schemaDrift);
KELLECT_STATS_DEF(decodeQueueDropped);
KELLECT_STATS_DEF(etwEventsLost);
KELLECT_STATS_DEF(etwBuffersLost);

#undef KELLECT_STATS_DEF

namespace {
std::mutex g_failureMutex;
std::map<std::string, uint64_t> g_failures;
constexpr size_t kMaxFailureKeys = 512;
}

void RecordFailure(uint64_t providerId, int opcode, int version, const char* reason) {
    char key[160];
    snprintf(key, sizeof(key), "%08llx/%d/v%d/%s",
             static_cast<unsigned long long>(providerId), opcode, version,
             reason ? reason : "?");
    std::lock_guard<std::mutex> lock(g_failureMutex);
    if (g_failures.size() >= kMaxFailureKeys && g_failures.find(key) == g_failures.end())
        return;
    ++g_failures[key];
}

void DumpFailures() {
    std::lock_guard<std::mutex> lock(g_failureMutex);
    for (const auto& item : g_failures)
        MyLogger::writeLog("[decode-failure] " + item.first + " count=" +
                           std::to_string(item.second));
}


void DumpLive() {
    size_t parseDepth = 0, serializeDepth = 0, outputDepth = 0;
    EventParser::PipelineDepth(parseDepth, serializeDepth, outputDepth);

    char buffer[512];
    snprintf(buffer, sizeof(buffer),
             "[stats-live] received=%llu parsed=%llu queued=%llu "
             "filtered=%llu decode_failed=%llu image_rundown=%llu thread_rundown=%llu "
             "parse_q=%llu serialize_q=%llu output_q=%llu "
             "etw_lost=%llu mqtt_connected=%d mqtt_sent=%llu mqtt_events_sent=%llu "
             "mqtt_acked=%llu mqtt_events_acked=%llu mqtt_spool=%llu mqtt_dropped=%llu "
             "serializers=%llu",
             (unsigned long long)eventsReceived.load(std::memory_order_relaxed),
             (unsigned long long)eventsParsed.load(std::memory_order_relaxed),
             (unsigned long long)eventsQueued.load(std::memory_order_relaxed),
             (unsigned long long)eventsFiltered.load(std::memory_order_relaxed),
             (unsigned long long)eventsDecodeFailed.load(std::memory_order_relaxed),
             (unsigned long long)imageRundown.load(std::memory_order_relaxed),
             (unsigned long long)threadRundown.load(std::memory_order_relaxed),
             (unsigned long long)parseDepth,
             (unsigned long long)serializeDepth,
             (unsigned long long)outputDepth,
             (unsigned long long)etwEventsLost.load(std::memory_order_relaxed),
             kellect::secargus::g_mqttConnected.load() ? 1 : 0,
             (unsigned long long)kellect::secargus::g_mqttSent.load(),
             (unsigned long long)kellect::secargus::g_mqttEventsSent.load(),
             (unsigned long long)kellect::secargus::g_mqttAcked.load(),
             (unsigned long long)kellect::secargus::g_mqttEventsAcked.load(),
             (unsigned long long)kellect::secargus::g_mqttSpool.load(),
             (unsigned long long)kellect::secargus::g_mqttDropped.load(),
             (unsigned long long)EventParser::GetSerializerTarget());

    std::printf("%s\n", buffer);
    std::fflush(stdout);
}

void Dump(const char* when) {
    size_t parseDepth = 0, serializeDepth = 0, outputDepth = 0;
    EventParser::PipelineDepth(parseDepth, serializeDepth, outputDepth);
    const unsigned long long parseQ = parseDepth;
    const unsigned long long serializeQ = serializeDepth;
    const unsigned long long outputQ = outputDepth;

    char buffer[768];
    snprintf(buffer, sizeof(buffer),
             "[stats] %s: received=%llu filtered=%llu unknown=%llu "
             "schema_unknown=%llu decode_failed=%llu filtered_third=%llu "
             "stack_incomplete=%llu file_rundown=%llu registry_rundown=%llu image_rundown=%llu thread_rundown=%llu disk_side=%llu drop_parse=%llu "
             "parsed=%llu queued=%llu "
             "output_waits=%llu etw_lost=%llu etw_buffers_lost=%llu drift=%llu "
             "decode_queue_dropped=%llu parse_q=%llu serialize_q=%llu output_q=%llu",
             when ? when : "",
             (unsigned long long)eventsReceived.load(std::memory_order_relaxed),
             (unsigned long long)eventsFiltered.load(std::memory_order_relaxed),
             (unsigned long long)eventsUnknown.load(std::memory_order_relaxed),
             (unsigned long long)eventsSchemaUnknown.load(std::memory_order_relaxed),
             (unsigned long long)eventsDecodeFailed.load(std::memory_order_relaxed),
             (unsigned long long)eventsFilteredThird.load(std::memory_order_relaxed),
             (unsigned long long)eventsStackIncomplete.load(std::memory_order_relaxed),
             (unsigned long long)fileRundown.load(std::memory_order_relaxed),
             (unsigned long long)registryRundown.load(std::memory_order_relaxed),
             (unsigned long long)imageRundown.load(std::memory_order_relaxed),
             (unsigned long long)threadRundown.load(std::memory_order_relaxed),
             (unsigned long long)diskSideEvents.load(std::memory_order_relaxed),
             (unsigned long long)eventsDroppedParse.load(std::memory_order_relaxed),
             (unsigned long long)eventsParsed.load(std::memory_order_relaxed),
             (unsigned long long)eventsQueued.load(std::memory_order_relaxed),
             (unsigned long long)outputWaits.load(std::memory_order_relaxed),
             (unsigned long long)etwEventsLost.load(std::memory_order_relaxed),
             (unsigned long long)etwBuffersLost.load(std::memory_order_relaxed),
             (unsigned long long)schemaDrift.load(std::memory_order_relaxed),
             (unsigned long long)decodeQueueDropped.load(std::memory_order_relaxed),
             parseQ, serializeQ, outputQ);

    std::printf("%s\n", buffer);
    MyLogger::writeLog(buffer);
    DumpFailures();
}

} // namespace stats
} // namespace kellect
