#include "output/output.h"
#include "process/event_parse.h"
#include "tools/tools.h"
#include <iostream>
#include <memory>
#include <string>
#include "process/event.h"
#include "tools/stats.h"
#include "tools/providerInfo.h"
#include "runtime/evidence.h"
#include "initialization/initializer.h"
using namespace std;
Output* EventParser::op;
std::thread EventParser::outputThread;
bool EventParser::evidenceOnly = false;
atomic<ULONG64> EventParser::successParse(0);
bool EventParser::isWdm;
// Single ordered parse worker. The ETW callback only filters, allocates the
// event shell and copies the raw frame; everything below runs here, in ETW
// order, so the shared maps (tid->pid, fileObject->path, keyHandle->key) are
// updated exactly as they were back when parsing ran on the callback thread.
// The worker is single-threaded on purpose: ordering is what those maps need.
void EventParser::eventParseThreadFunc(BaseEvent* event) {

    if (event == nullptr) return;

    event = getPropertiesByParsingOffset(event, event->getRawPropertyLen(), event->getRawProperty());

    if (!event->isValueableEvent()) {
        kellect::stats::Bump(kellect::stats::eventsDecodeFailed);
        kellect::stats::Bump(kellect::stats::eventsDroppedParse);
        const EventIdentifier* id = event->getEventIdentifier();
        if (id != nullptr)
            kellect::stats::RecordFailure(id->getProviderID(), id->getOpCode(), 0,
                                          "not_valuable");
        delete event;
        return;
    }

    event->parse();

    // parse() itself can suppress an event (e.g. FileIo RUNDOWN). Count those
    // as decode failures, not as third-filter drops.
    if (!event->isValueableEvent()) {
        // parse() can mark an event non-valuable either because the PID is
        // filtered (normal), it is an intentional rundown, or the schema/fields
        // are unusable. Keep those categories apart.
        if (Filter::pidFilter(static_cast<int>(event->getProcessID()))) {
            kellect::stats::Bump(kellect::stats::eventsFiltered);
        } else if (const EventIdentifier* id = event->getEventIdentifier()) {
            if (id->getProviderID() == RegistryProvider &&
                (id->getOpCode() == 24 || id->getOpCode() == 25)) {
                kellect::stats::Bump(kellect::stats::registryRundown);
            } else {
                kellect::stats::Bump(kellect::stats::eventsDecodeFailed);
                kellect::stats::RecordFailure(id->getProviderID(), id->getOpCode(), 0,
                                              "parse_suppressed");
            }
        } else {
            kellect::stats::Bump(kellect::stats::eventsDecodeFailed);
        }
        kellect::stats::Bump(kellect::stats::eventsDroppedParse);
        delete event;
        return;
    }

    if (Filter::thirdFilter(event)) {
        kellect::stats::Bump(kellect::stats::eventsFilteredThird);
        kellect::stats::Bump(kellect::stats::eventsDroppedParse);
        delete event;
        return;
    }

    kellect::stats::Bump(kellect::stats::eventsParsed);
    if (++successParse % 100000 == 0) {
        std::cout << "parse events number:" << successParse << std::endl;
    }

    // Stats-only run: no JSON, no serializer, no output queue.
    if (op == nullptr) {
        delete event;
        return;
    }

    if (EventParser::isWdm) {
        // WDM conversion mutates shared entity maps: keep it on this thread.
        std::string* sJson = new std::string();
        if (op != nullptr && event->toWdmJsonString(sJson) == STATUS_SUCCESS)
            op->output(*sJson);
        delete sJson;
        delete event;
        return;
    }

    // JSON building only reads the event, so it goes to the serialiser pool.
    // Ownership moves with the event; inline only when the backlog is full.
    if (serializePool != nullptr && serializePool->enqueueTask(serializeThreadFunc, event))
        return;

    serializeThreadFunc(event);
}

// Runs on the serialiser pool: builds the JSON line and hands it to the output
// queue. Owns and deletes `event`. Serialisation only reads the event, so it is
// safe to run away from the ordered parse thread.
void EventParser::serializeThreadFunc(BaseEvent* event) {

    if (!event) return;

    std::string* sJson = new std::string();
    if (op != nullptr && event->toJsonString(sJson) == STATUS_SUCCESS) {
        op->pushOutputQueue(sJson);   // ownership moves to the output queue
    }
    else {
        delete sJson;
    }
    delete event;
}

void EventParser::SetSerializerTarget(size_t count) {
    if (serializePool != nullptr)
        serializePool->SetTargetWorkers(count);
}

size_t EventParser::GetSerializerTarget() {
    return serializePool != nullptr ? serializePool->TargetWorkers() : 1;
}

void EventParser::PipelineDepth(size_t& parseDepth, size_t& serializeDepth,
                               size_t& outputDepth) {
    parseDepth = parsePools ? parsePools->pending() : 0;
    serializeDepth = serializePool ? serializePool->pending() : 0;
    outputDepth = op ? op->queuedEvents() : 0;
}

void EventParser::shutdownOutput() {    delete parsePools;
    parsePools = nullptr;
    EventImage::stopApiLoader();
    delete serializePool;
    serializePool = nullptr;
    if (op != nullptr) {
        op->requestStop();
        if (outputThread.joinable())
            outputThread.join();
        op->waitFlushed(2500);
        delete op;
        op = nullptr;
    }
}

//pEvent is original event stream structure
VOID WINAPI EventParser::ConsumeEventMain(PEVENT_RECORD pEvent) {

    kellect::stats::Bump(kellect::stats::eventsReceived);
    const auto rawSeq = kellect::evidence::Capture(kellect::evidence::Source::Kernel, *pEvent);
    if (evidenceOnly)
        return;

    // FileIo "RUNDOWN" is a session-start dump of every open file handle. It
    // can be hundreds of thousands of events in one burst, is not behaviour,
    // and is exactly what overflowed the ETW buffers. Reject it before the
    // allocation/copy; the raw evidence path above still keeps it.
    if (pEvent->EventHeader.ProviderId.Data1 == FileProvider &&
        pEvent->EventHeader.EventDescriptor.Opcode == 36) {
        kellect::stats::Bump(kellect::stats::fileRundown);
        return;
    }

    // Registry KCB RUNDOWN is kept: it seeds keyHandle -> KeyName and is much
    // smaller than Image DCStart. It is parsed but not output as behaviour.

    // Thread: keep Start/End (behaviour), drop the startup DCStart/DCEnd dump.
    if (pEvent->EventHeader.ProviderId.Data1 == ThreadProvider) {
        const UCHAR op = pEvent->EventHeader.EventDescriptor.Opcode;
        if (op == 3 || op == 4) {   // THREADDCSTART / THREADDCEND
            kellect::stats::Bump(kellect::stats::threadRundown);
            return;
        }
        // Keep Thread Start/End only. CSwitch/ReadyThread/etc. are scheduling
        // noise and their schema differs between builds (crash source).
        if (op != 1 && op != 2) {
            kellect::stats::Bump(kellect::stats::threadOther);
            return;
        }
    }

    // Image DCStart/DCEnd only seed the module map used by CallStack. With
    // stacks off (behaviour default) they are pure startup volume.
    if (pEvent->EventHeader.ProviderId.Data1 == ImageProvider) {
        const UCHAR op = pEvent->EventHeader.EventDescriptor.Opcode;
        // Image DCStart/DCEnd are a startup module dump. Drop them even with
        // CallStack enabled: the module map is pre-enumerated before ETW, and
        // ImageLoad/ImageUnload still update it. This keeps DCStart out of the
        // parser/JSON queue, but Windows still generates the kernel burst.
        if (op == 3 || op == 4) {
            kellect::stats::Bump(kellect::stats::imageRundown);
            return;
        }
    }

    // DiskIo events are pulled in by the FileIO name mapping
    // (EVENT_TRACE_FLAG_DISK_IO) but are not part of the behaviour model.
    // Reject them before allocation/parse and count them separately.
    const ULONG64 providerId = pEvent->EventHeader.ProviderId.Data1;
    if (providerId == DiskIoGuid.Data1 &&
        Filter::listenedEventsProviders.count(DiskIoGuid.Data1) == 0) {
        kellect::stats::Bump(kellect::stats::diskSideEvents);
        return;
    }

    // Reject providers we do not decode before touching the PID filter: CSwitch
    // / PerfInfo events can arrive at hundreds of thousands per second, and the
    // filter would take a mutex for every one of them.
    BaseEvent* event = getEventWithIdentifier(pEvent);
    if (event == nullptr) {
        // No per-event RecordFailure here: under diagnostic profiles (CSwitch)
        // this branch runs at 10^5-10^6 events/s and must stay lock-free.
        kellect::stats::Bump(kellect::stats::eventsUnknown);
        return;
    }

    if (Filter::firstFilter(pEvent)) {
        kellect::stats::Bump(kellect::stats::eventsFiltered);
        delete event;
        return;
    }

    event->setRawSequence(rawSeq);
    event->setRawProperty(pEvent->UserDataLength, pEvent->UserData);

    if (parsePools == nullptr) {
        eventParseThreadFunc(event);
        return;
    }
    while (!parsePools->enqueueTask(eventParseThreadFunc, event)) {
        if (kellect::evidence::Active()) {
            kellect::stats::Bump(kellect::stats::decodeQueueDropped);
            delete event;
            return;
        }
        // A legacy run applies backpressure. Never run the ordered decoder
        // concurrently with its worker, even when the queue is full.
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

VOID WINAPI EventParser::ConsumeUserEvent(PEVENT_RECORD pEvent) {
    const auto rawSeq = kellect::evidence::Capture(kellect::evidence::Source::User, *pEvent);
    if (evidenceOnly)
        return;
    DWORD status = ERROR_SUCCESS;
    PTRACE_EVENT_INFO pInfo = NULL;
    status = GetEventInformation4GetProperties(pEvent, pInfo);
    std::unique_ptr<TRACE_EVENT_INFO, decltype(&free)> infoOwner(pInfo, free);
    if (status != ERROR_SUCCESS || !pInfo || !pInfo->ProviderNameOffset) {
        kellect::stats::Bump(kellect::stats::eventsDroppedParse);
        return;
    }
    BaseEvent* event = getUserEventWithIdentifier(pEvent);
    std::wstring wstr(reinterpret_cast<wchar_t*>(reinterpret_cast<PBYTE>(pInfo) + pInfo->ProviderNameOffset));
    std::string providerName(wstr.begin(), wstr.end());

    for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; i++)
    {
        std::string* sJson = new std::string();
        bool flag = false;
        status = PrintProperties4GetProperties(event, pEvent, pInfo, i, nullptr, 0);
        if (ERROR_SUCCESS != status)
        {
            wprintf(L"Printing top level properties failed.\n");
        }
        event->parse();


        sJson->append(
                "{\"Event\":\"" + Tools::jsonEscape(providerName) + "\",\"Event_ID\":" + std::to_string(pInfo->EventDescriptor.Id) +
                ",\"PID\":" + std::to_string(event->getProcessID()) +
                ",\"PName\":\"" + Tools::jsonEscape(event->getProcessName()) +
                "\",\"PPID\":" + std::to_string(event->getParentProcessID()) +
                ",\"PPName\":\"" + Tools::jsonEscape(event->getParentProcessName()) +
                "\",\"TID\":" + std::to_string(event->getThreadID()) +
                ",\"TimeStamp\":" + std::to_string(event->getTimeStamp()) +
                ",\"Host-UUID\":\"" + Initializer::getUUID() + "\"");
        if (rawSeq) {
            sJson->append(",\"raw_ref\":{\"run_id\":\"" + kellect::evidence::RunId() +
                          "\",\"source\":\"user_etw\",\"raw_seq\":" + std::to_string(rawSeq) + "}");
        }
        sJson->append(",\"args\":{");
        for (auto pty : event->getProperties()) {

            if (pty.second) {

                if (flag) {
                    sJson->append(",");
                }

                flag = true;
                if (pty.second->getIsString()) {
                    std::string argValue = pty.second->getString();
                    sJson->append("\"" + pty.first + "\":\"" +
                                  Tools::jsonEscape(argValue) + "\"");
                }
                else {
                    sJson->append("\"" + pty.first + "\":" +
                                  std::to_string(pty.second->getULONG64()));
                }
            }
        }

        sJson->append("}}");
//        std::cout<<*sJson<<std::endl;

        op->pushOutputQueue(sJson);
//
    }
    delete event;
}
