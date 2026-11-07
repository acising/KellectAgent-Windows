// KellectService.exe - Windows service host (no GUI).
//
// Usage:
//   KellectService.exe                 run under the SCM (registered binPath)
//   KellectService.exe --install       create/replace + start the service [admin]
//   KellectService.exe --uninstall     stop + delete the service          [admin]
//   KellectService.exe --status        print the SCM state
//   KellectService.exe --console       run the collector in the foreground
//   KellectService.exe --config <ini>  use an alternative agent.ini
//
#include <windows.h>

#include <atomic>
#include <cstdio>
#include <string>
#include <vector>

#include "runtime/collector.h"
#include "service_config.h"
#include "service_host.h"
#include "service_util.h"
#include "supervisor.h"
#include "schema/schema.h"

namespace {

using namespace kellect::svc;

std::atomic<bool> g_superviseStop{ false };

BOOL WINAPI SuperviseCtrlHandler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT ||
        type == CTRL_CLOSE_EVENT || type == CTRL_SHUTDOWN_EVENT) {
        g_superviseStop.store(true);
        return TRUE;
    }
    return FALSE;
}

void PrintUsage() {
    printf(
        "KellectService - Kellect kernel event collector as a Windows service\n"
        "\n"
        "  KellectService.exe [--config <agent.ini>]   run under the SCM\n"
        "  KellectService.exe --install                install + start (elevated)\n"
        "  KellectService.exe --uninstall              stop + delete (elevated)\n"
        "  KellectService.exe --status                 print the service state\n"
        "  KellectService.exe --console                run in the foreground\n"
        "  KellectService.exe --supervise              run the supervisor in the foreground\n"
        "  KellectService.exe --help                   this text\n"
        "\n"
        "Configuration: <install dir>\\config\\agent.ini\n"
        "\n"
        "Example -e all -f D:\\events.jsonl:\n"
        "  [collector]\n"
        "  events=all\n"
        "  output=file\n"
        "  file=D:\\events.jsonl\n");
}

const char* ServiceStateName(DWORD state) {
    switch (state) {
        case 0: return "not installed";
        case SERVICE_STOPPED: return "stopped";
        case SERVICE_START_PENDING: return "start pending";
        case SERVICE_STOP_PENDING: return "stop pending";
        case SERVICE_RUNNING: return "running";
        case SERVICE_CONTINUE_PENDING: return "continue pending";
        case SERVICE_PAUSE_PENDING: return "pause pending";
        case SERVICE_PAUSED: return "paused";
        default: return "unknown";
    }
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    ServiceOptions options;
    std::string configPath = JoinPath(ModuleDirectory(), "config\\agent.ini");

    bool install = false;
    bool uninstall = false;
    bool console = false;
    bool status = false;
    bool supervise = false;

    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        if (arg == L"--install") install = true;
        else if (arg == L"--uninstall") uninstall = true;
        else if (arg == L"--console") console = true;
        else if (arg == L"--supervise") supervise = true;
        else if (arg == L"--status") status = true;
        else if (arg == L"--help" || arg == L"-h" || arg == L"/?") { PrintUsage(); return 0; }
        else if ((arg == L"--config" || arg == L"-c") && i + 1 < argc) {
            configPath = WideToUtf8(argv[++i]);
        } else {
            fwprintf(stderr, L"Unknown argument: %s\n\n", arg.c_str());
            PrintUsage();
            return 1;
        }
    }

    std::string error;
    if (!LoadServiceConfig(configPath, options, error)) {
        fprintf(stderr, "Invalid configuration %s: %s\n", configPath.c_str(), error.c_str());
        return 1;
    }

    if (status) {
        DWORD state = 0;
        if (!QueryServiceState(options.name, state, error)) {
            fprintf(stderr, "%s\n", error.c_str());
            return 1;
        }
        printf("%s: %s\n", options.name.c_str(), ServiceStateName(state));
        return 0;
    }

    if (uninstall) {
        if (!UninstallService(options.name, error)) {
            fprintf(stderr, "Uninstall failed: %s\n", error.c_str());
            return 1;
        }
        printf("%s removed.\n", options.name.c_str());
        return 0;
    }

    if (install) {
        if (!InstallService(options, error)) {
            fprintf(stderr, "Install failed: %s\n", error.c_str());
            return 1;
        }
        printf("%s installed and started (%s).\n", options.name.c_str(), configPath.c_str());
        return 0;
    }

    if (console) {
        SetConsoleOutputCP(65001);
        SetCurrentDirectoryW(Utf8ToWide(ModuleDirectory()).c_str());
        return kellect::RunCollector(BuildCollectorArgs(options));
    }

    if (supervise) {
        SetConsoleOutputCP(65001);
        SetConsoleCtrlHandler(SuperviseCtrlHandler, TRUE);
        SetCurrentDirectoryW(Utf8ToWide(ModuleDirectory()).c_str());
        return RunSupervisor(options, [] { return g_superviseStop.load(); });
    }

    return RunService(options);
}
