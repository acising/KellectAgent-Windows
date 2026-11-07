#pragma once
//
// Windows service host for the Kellect collector (no GUI).
//
// The service is a thin SCM wrapper around kellect::RunCollector(): the ETW
// pipeline, filters, schema handling and outputs are identical to kellect.exe,
// so the two products cannot drift apart.
//
#include <windows.h>

#include <string>

#include "service_config.h"

namespace kellect {
namespace svc {

// Register with the SCM and run until stopped. Returns a process exit code.
int RunService(const ServiceOptions& options);

// Create/replace the service (requires an elevated token).
bool InstallService(const ServiceOptions& options, std::string& error);

// Stop and delete the service.
bool UninstallService(const std::string& name, std::string& error);

// Current SCM state of the service, e.g. SERVICE_RUNNING.
bool QueryServiceState(const std::string& name, DWORD& state, std::string& error);

} // namespace svc
} // namespace kellect
