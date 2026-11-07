#include "runtime/collector.h"

#include <windows.h>

#include <atomic>
#include <iostream>
#include <thread>

#include "initialization/initializer.h"
#include "process/etw_config.h"
#include "process/event_parse.h"
#include "schema/schema.h"
#include "runtime/evidence.h"
#include "runtime/symbolize.h"
#include "tools/stats.h"

namespace {

std::atomic<bool> g_stopRequested{ false };

// All-zero GUID, compared field-wise so GUID_NULL (defined in uuid.lib) is not
// needed at link time.
bool IsNullGuid(const GUID& g) {
    return g.Data1 == 0 && g.Data2 == 0 && g.Data3 == 0 &&
           g.Data4[0] == 0 && g.Data4[1] == 0 && g.Data4[2] == 0 && g.Data4[3] == 0 &&
           g.Data4[4] == 0 && g.Data4[5] == 0 && g.Data4[6] == 0 && g.Data4[7] == 0;
}

} // namespace

namespace kellect {

void RequestStop() {
    if (g_stopRequested.exchange(true))
        return;   // already stopping
    // Unblocks ProcessTrace; the session cleanup then runs on the collector
    // thread (final output flush included).
    ETWConfiguration::StopSessions();
}

bool IsStopRequested() {
    return g_stopRequested.load();
}

int RunCollector(const std::vector<std::string>& args) {
    if (args.empty())
        return 1;
    if (args.size() > 1 && args[1] == "--symbolize") {
        std::string images, pdbs, output;
        bool valid = args.size() >= 3 && !args[2].empty() && (args.size() - 3) % 2 == 0;
        for (size_t i = 3; valid && i < args.size(); i += 2) {
            const auto& option = args[i];
            std::string* value = option == "--image-dir" ? &images : option == "--pdb-dir" ? &pdbs :
                                 option == "--symbols-out" ? &output : nullptr;
            valid = value && value->empty() && !args[i + 1].empty();
            if (valid)
                *value = args[i + 1];
        }
        if (valid && !images.empty() && !output.empty())
            return SymbolizeArchive(args[2], images, pdbs, output);
        std::cerr << "Usage: kellect --symbolize <archive-dir> --image-dir <directory> "
                     "[--pdb-dir <directory>] --symbols-out <new-file>\n";
        return 3;
    }
    if (args.size() > 1 && args[1] == "--replay-etl") {
        if (args.size() == 5 && args[3] == "--evidence-dir" &&
            !args[2].empty() && !args[4].empty())
            return evidence::ReplayKernelEtl(args[2], args[4]);
        std::cerr << "Usage: kellect --replay-etl <kernel.etl> --evidence-dir <directory>\n";
        return 3;
    }

    // The elevation check lives in Initializer::init(), after option parsing:
    // `-h` must work without admin, and an invalid option should report the
    // option error instead of "run as administrator". Every real run still
    // fails there before an ETW session is created.

    // Initializer takes a mutable char** (it only reads it), and the destructor
    // no longer deletes anything, so pointing into the strings is safe.
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (const std::string& a : args)
        argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);

    GUID provider = {};
    ULONG64 enabledFlags = 0;
    std::string stopEventName;
    std::string evidenceDirectory;
    std::string profile;
    bool kernelEtl = false;
    {
        Initializer initializer(static_cast<int>(args.size()), argv.data());
        enabledFlags = initializer.init(provider);
        stopEventName = initializer.getStopEventName();
        evidenceDirectory = initializer.getEvidenceDirectory();
        profile = initializer.getProfile();
        kernelEtl = initializer.getKernelEtl();
    }

    const bool userProviderSelected = !IsNullGuid(provider);
    if (enabledFlags == 0 && !userProviderSelected) {
        std::cerr << "Error: no event source selected; pass -e <mask> or -u <provider>."
                  << std::endl;
        EventParser::shutdownOutput();
        return 3;
    }
    if (kernelEtl && enabledFlags == 0) {
        std::cerr << "Error: --kernel-etl requires a kernel event source.\n";
        EventParser::shutdownOutput();
        return 3;
    }

    // A stop can arrive while initImages() is still loading DLL exports (the
    // service reports SERVICE_RUNNING before RunCollector, so the SCM is free
    // to stop us at any moment). Do not start a session that nobody would stop.
    if (IsStopRequested()) {
        std::cout << "stop requested before the session started; exiting." << std::endl;
        EventParser::shutdownOutput();
        return 0;
    }
    if (!evidenceDirectory.empty() &&
        !evidence::Start(evidenceDirectory, profile.empty() ? "custom" : profile,
                         Initializer::getUUID(), static_cast<ULONG>(enabledFlags), provider, kernelEtl)) {
        std::cerr << "Error: could not open evidence archive in " << evidenceDirectory << '\n';
        EventParser::shutdownOutput();
        return 4;
    }

    // Supervisor handshake: it creates the event before CreateProcess, so this
    // opens the same object. The wait thread turns a supervisor SetEvent() into
    // a graceful RequestStop() (ETW stop + pipeline flush), which is what a
    // service-hosted child needs because it has no console for CTRL_BREAK.
    HANDLE waitHandles[2]{};
    std::thread stopWaiter;
    if (!stopEventName.empty()) {
        waitHandles[0] = CreateEventA(nullptr, TRUE, FALSE, stopEventName.c_str());
        waitHandles[1] = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (waitHandles[0] && waitHandles[1]) {
            stopWaiter = std::thread([&waitHandles] {
                if (WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE) == WAIT_OBJECT_0)
                    kellect::RequestStop();
            });
        } else {
            std::cerr << "Warning: cannot open stop event '" << stopEventName
                      << "' (" << GetLastError() << "); supervisor stop will fall back "
                         "to process termination." << std::endl;
        }
    }

    std::cout << "evidence: " << (kellect::evidence::Active() ? "on" : "off") << std::endl;

    std::atomic<bool> liveStop{ false };
    std::thread liveThread;
    const int liveInterval = Initializer::getStatsInterval();
    if (liveInterval > 0) {
        liveThread = std::thread([&liveStop, liveInterval] {
            while (!liveStop.load()) {
                for (int i = 0; i < liveInterval * 10 && !liveStop.load(); ++i)
                    Sleep(100);
                if (!liveStop.load())
                    kellect::stats::DumpLive();
            }
        });
    }

    std::atomic<bool> adaptiveStop{ false };
    std::thread adaptiveThread;
    if (Initializer::getAdaptive() && enabledFlags != 0) {
        adaptiveThread = std::thread([&adaptiveStop] {
            int ticks = 0;
            int lowTicks = 0;
            ULONG lastLost = 0;
            while (!adaptiveStop.load()) {
                for (int i = 0; i < 10 && !adaptiveStop.load(); ++i)
                    Sleep(100);
                if (adaptiveStop.load())
                    break;
                if (++ticks < 4)
                    continue;   // let the two-phase session settle

                // Event order is part of the behaviour contract: do NOT grow
                // the serializer pool automatically. Only buffer sizing is
                // adaptive; multi-threaded JSON is opt-in (--serialize-threads).
                size_t parseQ = 0, serializeQ = 0, outputQ = 0;
                EventParser::PipelineDepth(parseQ, serializeQ, outputQ);
                (void)lowTicks;

                ETWConfiguration::KernelBufferStats etw;
                if (ETWConfiguration::QueryKernel(etw)) {
                    if (etw.eventsLost > lastLost && etw.maxBuffers < 2048) {
                        ULONG next = etw.maxBuffers + 256;
                        if (next > 2048) next = 2048;
                        if (ETWConfiguration::SetKernelMaximumBuffers(next)) {
                            std::cout << "[adaptive] max_buffers=" << next
                                      << " (etw_lost delta="
                                      << (etw.eventsLost - lastLost) << ")" << std::endl;
                        }
                    }
                    lastLost = etw.eventsLost;
                }
            }
        });
    }

    ETWConfiguration configuration(static_cast<ULONG>(enabledFlags), provider);
    const int sessionStatus = configuration.Run();
    adaptiveStop.store(true);
    if (adaptiveThread.joinable())
        adaptiveThread.join();
    liveStop.store(true);
    if (liveThread.joinable())
        liveThread.join();
    if (stopWaiter.joinable()) {
        SetEvent(waitHandles[1]);
        stopWaiter.join();
    }
    for (auto handle : waitHandles) {
        if (handle)
            CloseHandle(handle);
    }
    EventParser::shutdownOutput();
    const bool evidenceOk = evidence::Finish();
    stats::Dump("session stop");

    const std::string probeReport = schema::ProbeReportPath();
    if (!probeReport.empty()) {
        if (schema::DriftTracker::Instance().WriteJsonReport(probeReport)) {
            std::cout << "schema probe report written to " << probeReport << std::endl;
        } else {
            std::cerr << "Warning: could not write schema probe report to "
                      << probeReport << std::endl;
        }
        std::cout << schema::DriftTracker::Instance().Report() << std::flush;
    }

    return sessionStatus != ERROR_SUCCESS ? sessionStatus : evidenceOk ? 0 : 4;
}

} // namespace kellect
