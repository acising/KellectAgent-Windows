#pragma once

#include <atomic>
#include <cstdint>

// Lightweight cross-thread counters exported by the SecArgus MQTT output so the
// live stats line / GUI can show transport state without touching MqttOutput.
namespace kellect {
namespace secargus {

extern std::atomic<uint64_t> g_mqttSent;        // batches published
extern std::atomic<uint64_t> g_mqttEventsSent;  // events inside published batches
extern std::atomic<uint64_t> g_mqttEventsAcked; // events inside ACKed batches
extern std::atomic<uint64_t> g_mqttAcked;
extern std::atomic<uint64_t> g_mqttSpool;
extern std::atomic<uint64_t> g_mqttDropped;
extern std::atomic<bool> g_mqttConnected;

} // namespace secargus
} // namespace kellect
