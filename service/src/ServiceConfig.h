// service/src/ServiceConfig.h
// Resolved launch configuration for one service start.
//
// Load precedence (highest first): registry -> INI file -> built-in default.
//   1. registry  HKLM\SOFTWARE\Kellect\Service      (written by the GUI / MSI)
//   2. INI file  %ProgramData%\Kellect\service.conf ([service] section)
//   3. default   file mode, kellect.exe beside the wrapper, mask 0xFF
//
// The collector's CLI is NOT modified; buildArgs() just composes its existing
// flags (-e/-f/-s/-k), verified against source/initialization/initializer.cpp.
#pragma once
#include <string>
#include <vector>
#include <windows.h>

namespace kellect::svc {

enum class OutputMode { File, Socket, Kafka };

struct ServiceConfig {
    std::wstring exePath;            // kellect.exe path (default: beside wrapper)
    std::wstring workDir;            // child CWD (default: %ProgramData%\Kellect)
    OutputMode   mode = OutputMode::File;
    std::wstring eventMask = L"0xFF"; // collector -e value (hex)
    std::wstring outputFile;         // file mode target
    std::wstring socketHost;         // socket mode host
    int          socketPort = 0;     // socket mode port
    std::wstring kafkaBroker;        // kafka mode "host:port"
    std::wstring kafkaTopic;         // kafka mode topic

    // Load from registry -> file -> defaults. Returns false if the chosen mode
    // is Console (rejected in service context) or required fields are missing.
    static bool Load(ServiceConfig& out, const std::wstring& serviceExeDir);

    // Build the kellect.exe argv (excluding argv[0]). Pure function of the
    // resolved config — easy to unit-test.
    std::vector<std::wstring> buildArgs() const;
};

} // namespace kellect::svc
