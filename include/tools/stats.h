#pragma once
//
// Process-wide pipeline counters.
//
// Purpose: make event loss *visible*. Kernel ETW sessions drop events when the
// consumer cannot keep up (EventsLost), and the pipeline itself can slow down or
// drop at the output stage. Without these numbers "no data was lost" is a guess.
//
// All counters are relaxed atomics updated once per event; the cost is a single
// locked add on a cache line that is not shared with event data.
//
#include <atomic>
#include <cstdint>

namespace kellect {
namespace stats {

// Each counter sits on its own cache line: they are written by different
// threads (ETW callback / parse pool / serialiser pool), and sharing a line
// would turn every relaxed increment into a cache-line ping-pong.
#define KELLECT_STATS_COUNTER(name) extern alignas(64) std::atomic<uint64_t> name

KELLECT_STATS_COUNTER(eventsReceived);   // ETW callbacks entered
KELLECT_STATS_COUNTER(eventsFiltered);   // dropped by firstFilter (PID/-x)
KELLECT_STATS_COUNTER(eventsUnknown);    // provider not decoded (e.g. PerfInfo/CSwitch)
KELLECT_STATS_COUNTER(eventsSchemaUnknown); // no XML layout for (provider, opcode)
KELLECT_STATS_COUNTER(eventsDecodeFailed);  // decoded but marked not valuable
KELLECT_STATS_COUNTER(eventsFilteredThird); // dropped by provider/PID third filter
KELLECT_STATS_COUNTER(eventsStackIncomplete); // classic stack frame was short/invalid
KELLECT_STATS_COUNTER(fileRundown);      // FileIo RUNDOWN (session-start handle dump)
KELLECT_STATS_COUNTER(registryRundown);  // Registry KCB RUNDOWN (session-start key dump)
KELLECT_STATS_COUNTER(imageRundown);     // Image DCStart/DCEnd when stacks are off
KELLECT_STATS_COUNTER(threadRundown);    // Thread DCStart/DCEnd (Start/End kept)
KELLECT_STATS_COUNTER(threadOther);      // Thread CSwitch/ReadyThread etc.
KELLECT_STATS_COUNTER(diskSideEvents);   // DiskIo events pulled in by FileIO deps
KELLECT_STATS_COUNTER(eventsDroppedParse); // legacy total (kept for old consumers)
KELLECT_STATS_COUNTER(eventsParsed);     // survived parse + thirdFilter
KELLECT_STATS_COUNTER(eventsQueued);     // handed to the output queue
KELLECT_STATS_COUNTER(outputWaits);      // producer stalled on a full queue
KELLECT_STATS_COUNTER(schemaDrift);      // frames that did not fit the layout
KELLECT_STATS_COUNTER(decodeQueueDropped); // raw evidence was attempted before decode enqueue
KELLECT_STATS_COUNTER(etwEventsLost);    // ETW-reported lost events
KELLECT_STATS_COUNTER(etwBuffersLost);   // ETW-reported lost buffers

#undef KELLECT_STATS_COUNTER

inline void Bump(std::atomic<uint64_t>& counter) {
    counter.fetch_add(1, std::memory_order_relaxed);
}

// Writes one summary line to stdout and the log file.
void Dump(const char* when);
// Lightweight line for live GUI/monitoring (no log write).
void DumpLive();

// Bounded aggregation of decoding failures by provider/opcode/version/reason.
// Only called on failures, so the hot path is unaffected.
void RecordFailure(uint64_t providerId, int opcode, int version, const char* reason);
void DumpFailures();

} // namespace stats
} // namespace kellect
