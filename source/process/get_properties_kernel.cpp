//Turns the DEFINE_GUID for EventTraceGuid into a const.
#include "process/event_parse.h"
#include <windows.h>
#include <stdio.h>
#include <strsafe.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <evntrace.h>
#include <tdh.h>
#include <in6addr.h>
#include <cstdint>
#include "process/event.h"
#include <cstring>
#include "tools/tools.h"
#include "tools/stats.h"
#include "tools/providerInfo.h"
#include "schema/schema.h"
#include "process/stack_capture.h"
#include "runtime/evidence.h"

BaseEvent* WINAPI EventParser::getEventWithIdentifier(PEVENT_RECORD pEvent) {

    BaseEvent* event = nullptr;

    switch (pEvent->EventHeader.ProviderId.Data1) // init by event type ,data1 is providerid
    {
        case FileProvider:
            event = new EventFile;
            break;
        case ThreadProvider:
            event = new EventThread;
            break;
        case ProcessProvider:
            event = new EventProcess;
            break;
        case ImageProvider:
            event = new EventImage;
            break;
        case RegistryProvider:
            event = new EventRegistry;
            break;
        case DiskProvider:
            event = new EventDisk;
            break;
        case SystemCallProvider:
            event = new EventPerfInfo;
            break;
        case TcpIpProvider:
            event = new EventTCPIP;
            break;
        case CallStackProvider:
            if (!kellect::IsClassicStackWalk(pEvent->EventHeader))
                return nullptr;
            event = new EventCallstack;
            break;
        default:
            event = nullptr;
            return event;
    };

    event->setProcessorID(pEvent->BufferContext.ProcessorIndex);
    event->setProcessID(pEvent->EventHeader.ProcessId);     //TCPIP的pEvent中processID ThreadID
    event->setThreadID(pEvent->EventHeader.ThreadId);
    event->setTimeStamp(pEvent->EventHeader.TimeStamp.QuadPart);
    event->setPointerBytes(kellect::EventPointerBytes(pEvent->EventHeader.Flags,
        kellect::evidence::Status(kellect::evidence::Source::Kernel).pointerBytes));
//    event->setSTimeStamp(Tools::convertTimestamp(pEvent->EventHeader.TimeStamp.QuadPart));
    event->setEventIdentifier(
            new EventIdentifier(pEvent->EventHeader.ProviderId.Data1,pEvent->EventHeader.EventDescriptor.Opcode)
    );


    return event;
}

// --- helpers for bounds-checked variable-width fields ---------------------
namespace {

size_t BoundedAnsiLen(const char* p, size_t maxBytes) {
    size_t n = 0;
    while (n < maxBytes && p[n] != '\0') ++n;
    return n;
}

size_t BoundedWideLen(const wchar_t* p, size_t maxChars) {
    size_t n = 0;
    while (n < maxChars && p[n] != L'\0') ++n;
    return n;
}

} // namespace

// Decode the raw UserData frame of a kernel (classic) ETW event using the
// field layout declared in config/eventStruct_*.xml.
//
// Kernel events carry no instrumentation manifest, so TDH cannot decode them;
// the layout is a per-OS-build contract (see schema/schema.h). Two things are
// new versus the original implementation:
//
//   1. Every read is bounds-checked against userDataLen. The old code walked a
//      raw pointer and read past the frame whenever the layout did not match
//      the OS - exactly what happens on an unlisted Windows build.
//   2. The outcome (layout consumed N of M bytes) is fed to the schema drift
//      tracker, so a build that changed a frame is reported instead of silently
//      producing garbage. --schema-probe turns that into a report.
//
// On a layout/frame mismatch the longest valid prefix is kept (fields before
// the mismatch are still correct); --schema-strict drops such events instead.
BaseEvent* EventParser::getPropertiesByParsingOffset(BaseEvent* event, int userDataLen, void* userDataBeginAddress) {

    if (!event) return nullptr;

    EventIdentifier* identifier = event->getEventIdentifier();
    if (!identifier) return event;

    const ULONG64 providerId = identifier->getProviderID();
    const int opCode = identifier->getOpCode();

    const uint8_t* base = static_cast<const uint8_t*>(userDataBeginAddress);
    const size_t total = userDataLen > 0 ? static_cast<size_t>(userDataLen) : 0;

    // ------------------------------------------------------------------
    // Stack-walk frames have their own binary layout (timestamp, pid/tid,
    // then addresses) and are not described by the event XML.
    //   [0]   Timestamp
    //   [1]   ProcessId (low DWORD) | ThreadId (high DWORD)
    //   [2..] stack addresses
    // ------------------------------------------------------------------
    if (providerId == CallStackProvider) {

        auto* callStackEvent = static_cast<EventCallstack*>(event);
        auto stack = kellect::DecodeClassicStack(base, total, event->getPointerBytes());
        identifier->setEventName("CallStack");
        event->setTimeStamp(stack.timestamp);
        event->setProcessID(stack.pid);
        event->setThreadID(stack.tid);
        if (!stack.complete || Filter::secondFilter(event)) {
            event->setValueableEvent(false);
            kellect::stats::Bump(kellect::stats::eventsStackIncomplete);
            kellect::stats::RecordFailure(providerId, opCode, 0, "stack_incomplete");
        }
        else
            callStackEvent->stackAddresses = std::move(stack.frames);
        return event;
    }

    // ------------------------------------------------------------------
    // Regular kernel event: apply the declared layout.
    // ------------------------------------------------------------------
    auto layout = BaseEvent::eventStructMap.find(identifier);
    if (layout == BaseEvent::eventStructMap.end()) {
        // No XML layout for this (provider, opcode): keep the event with a
        // synthetic name instead of dropping it. The common JSON fields
        // (PID/TID/TimeStamp/Host-UUID) stay valid; args is empty.
        char synthetic[64];
        snprintf(synthetic, sizeof(synthetic), "Unknown_%08llx_%d",
                 static_cast<unsigned long long>(providerId), opCode);
        identifier->setEventName(synthetic);
        kellect::stats::Bump(kellect::stats::eventsSchemaUnknown);
        kellect::stats::RecordFailure(providerId, opCode, 0, "schema_unknown");
        return event;
    }
    identifier->setEventName(layout->first->getEventName());

    size_t off = 0;
    bool shortFrame = false;   // a declared field did not fit into the frame

    for (const BaseEvent::PropertyInfo& field : layout->second) {

        const size_t remaining = off <= total ? total - off : 0;
        dataType* dt = nullptr;

        switch (field.type) {

            case PULONG4_: {
                if (remaining < 4) { shortFrame = true; break; }
                dt = new dataType(*(reinterpret_cast<const ULONG*>(base + off)));
                off += 4;
                break;
            }
            case PULONG8_:
            case PULONGLONG_: {
                if (remaining < 8) { shortFrame = true; break; }
                // Was reading only 4 bytes while advancing 8: high halves of
                // pointers/64-bit counters were lost.
                dt = new dataType(*(reinterpret_cast<const ULONG64*>(base + off)));
                off += 8;
                break;
            }
            case PBYTE_: {
                if (remaining < 1) { shortFrame = true; break; }
                dt = new dataType(static_cast<ULONG64>(*(base + off)));
                off += 1;
                break;
            }
            case PUSHORT_: {
                if (remaining < 2) { shortFrame = true; break; }
                dt = new dataType(static_cast<ULONG64>(*(reinterpret_cast<const USHORT*>(base + off))));
                off += 2;
                break;
            }
            case PSTRING_: {
                // NUL-terminated ANSI string, bounded by the frame.
                const size_t chars = BoundedAnsiLen(
                    reinterpret_cast<const char*>(base + off), remaining);
                dt = new dataType(std::string(reinterpret_cast<const char*>(base + off), chars));
                off += chars + 1;
                if (off > total) { shortFrame = true; off = total; }
                break;
            }
            case PWSTRING_: {
                // NUL-terminated UTF-16 string, bounded by the frame.
                const size_t maxChars = remaining / sizeof(wchar_t);
                const size_t chars = BoundedWideLen(
                    reinterpret_cast<const wchar_t*>(base + off), maxChars);
                if (chars == maxChars) {
                    // No terminator inside the frame: the layout does not fit.
                    shortFrame = true;
                    break;
                }
                std::wstring wide(reinterpret_cast<const wchar_t*>(base + off), chars);
                std::string sVal = Tools::WString2String(wide.c_str());

                if (providerId == FileProvider || providerId == ImageProvider)
                    Tools::convertFileNameInDiskFormat(sVal);

                dt = new dataType(sVal);
                // Advance by the encoded width. The original advanced by the
                // UTF-8 byte count, which is only correct for pure-ASCII when
                // the string happens to be the last field.
                off += (chars + 1) * sizeof(wchar_t);
                if (off > total) { shortFrame = true; off = total; }
                break;
            }
            case SID_: {
                // Legacy layout assumption: two pointer-sized fields precede
                // the SID, which is stored inline. Keep that contract but make
                // the length computation safe (GetLengthSid on a bad pointer
                // reads arbitrary memory).
                const size_t kSidSkip = 8 * 2;
                if (remaining < kSidSkip) { shortFrame = true; break; }
                off += kSidSkip;

                const size_t sidRemaining = total - off;
                if (sidRemaining < 8) { shortFrame = true; off = total; break; }

                const uint8_t* sidBytes = base + off;
                const size_t subAuthorities = sidBytes[1];
                size_t sidLen = 8 + 4 * subAuthorities;
                if (sidLen > sidRemaining) {
                    shortFrame = true;
                    off = total;
                    break;
                }

                CHAR userName[256] = { 0 };
                CHAR domainName[256] = { 0 };
                DWORD cchUser = 256;
                DWORD cchDomain = 256;
                SID_NAME_USE use = SidTypeUnknown;

                LookupAccountSidA(NULL, (PSID)sidBytes, userName, &cchUser,
                                  domainName, &cchDomain, &use);

                std::string sidText = domainName;
                sidText.append("\\");
                sidText.append(userName);
                dt = new dataType(sidText);
                off += sidLen;
                break;
            }
            default: {
                // Unknown type code: skip the field rather than reusing the
                // previous dataType (the old code fell through and inserted a
                // stale pointer, then double-freed it).
                continue;
            }
        }

        if (!dt) {
            if (shortFrame) break;          // frame ended: keep parsed prefix
            if (field.optional) break;      // optional field absent as expected
            continue;
        }

        event->setProperty(field.name, dt);

        if (shortFrame) break;
    }

    const std::string eventName = identifier->getEventName();
    kellect::schema::DriftKey key;
    key.providerId = providerId;
    key.opCode = opCode;
    kellect::schema::DriftTracker::Instance().Record(
        key, eventName.c_str(),
        static_cast<uint32_t>(total), static_cast<uint32_t>(off), shortFrame);

    if (shortFrame) {
        kellect::stats::Bump(kellect::stats::schemaDrift);
        if (kellect::schema::StrictMode()) {
            event->setValueableEvent(false);
            kellect::stats::RecordFailure(providerId, opCode, 0, "short_frame_strict");
        }
    }

    return event;
}
