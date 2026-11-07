#pragma once
//
// Collector entry point shared by the two products:
//   * kellect.exe        - console agent (GUI launches this as a child)
//   * KellectService.exe - Windows service host (no GUI)
//
// Keeping the ETW pipeline in kellect_core and this thin runner in front of it
// means both products run exactly the same collection code.
//
#include <string>
#include <vector>

namespace kellect {

// Run the collector to completion. `args` is argv including the program name
// (args[0]); the collector's own options start at args[1].
// Blocks until the ETW session has been stopped, then flushes output and writes
// a --schema-probe report if one was requested.
// Returns 0 on success, non-zero on configuration/startup failure.
int RunCollector(const std::vector<std::string>& args);

// Ask a running RunCollector() to stop. Thread-safe and idempotent: stops the
// ETW session, which unblocks ProcessTrace and lets the normal cleanup path
// run. Used by the service control handler and by console Ctrl+C handling.
void RequestStop();

bool IsStopRequested();

} // namespace kellect
