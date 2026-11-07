#pragma once
//
// Supervisor mode: KellectService.exe (or `KellectService.exe --supervise`)
// runs the collector as a supervised child process instead of in-process.
//
// Why: the collector's ETW session and Initializer state are one-shot (see
// docs/secargus-integration-design.md §7/Q7), so "restart to apply config" has
// to be a process restart. The supervisor
//   * keeps exactly one child alive (Job object with KILL_ON_JOB_CLOSE, so a
//     supervisor crash cannot leave a zombie holding the kernel session),
//   * detects config\remote\desired.json / config\filter.txt updates and
//     restarts the child to apply them,
//   * restarts a crashed child with exponential backoff,
//   * stops the child through a per-child named event, so the collector still
//     flushes its spool/output before exiting.
//
#include <functional>

#include "service_config.h"

namespace kellect {
namespace svc {

// Blocks until `stopRequested()` returns true or the child exits cleanly
// without a stop request. Returns the process exit code for the service.
int RunSupervisor(const ServiceOptions& options,
                  const std::function<bool()>& stopRequested);

} // namespace svc
} // namespace kellect
