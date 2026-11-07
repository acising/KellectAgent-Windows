#pragma once

#include "output/output.h"
#include "process/sub_event.h"
#include "tools/filter.h"
#include "tools/threadpool.h"
#include <tdh.h>

class EventParser {
public:
    static void WINAPI ConsumeEventMain(PEVENT_RECORD event);
    static void WINAPI ConsumeUserEvent(PEVENT_RECORD event);
    static void shutdownOutput();
    // Backlog snapshot: parse queue, serializer queue, output queue.
    static void PipelineDepth(size_t& parseDepth, size_t& serializeDepth,
                              size_t& outputDepth);
    static void SetSerializerTarget(size_t count);
    static size_t GetSerializerTarget();

private:
    friend class Initializer;

    static void eventParseThreadFunc(BaseEvent* event);
    static void serializeThreadFunc(BaseEvent* event);
    static BaseEvent* WINAPI getEventWithIdentifier(PEVENT_RECORD event);
    static BaseEvent* WINAPI getUserEventWithIdentifier(PEVENT_RECORD event);
    static BaseEvent* getPropertiesByParsingOffset(BaseEvent* event, int length, void* data);

    static DWORD GetEventInformation4GetProperties(PEVENT_RECORD event, PTRACE_EVENT_INFO& info);
    static DWORD PrintProperties4GetProperties(BaseEvent* event, PEVENT_RECORD record,
        PTRACE_EVENT_INFO info, USHORT index, LPWSTR structureName, USHORT structureIndex);
    static DWORD FormatAndPrintData(BaseEvent* event, PEVENT_RECORD record, USHORT inType,
        USHORT outType, PBYTE data, DWORD dataSize, PEVENT_MAP_INFO map);
    static DWORD GetArraySize4GetProperties(PEVENT_RECORD event, PTRACE_EVENT_INFO info,
        USHORT index, PUSHORT arraySize);
    static DWORD GetMapInfo4GetProperties(PEVENT_RECORD event, LPWSTR mapName,
        DWORD decodingSource, PEVENT_MAP_INFO& map);
    static void PrintMapString(PEVENT_MAP_INFO map, PBYTE data);
    static void RemoveTrailingSpace4GetProperties(PEVENT_MAP_INFO map);

    enum PropertyType { PBYTE_ = 1, PUSHORT_ = 2, PULONG4_ = 4, PULONG8_ = 8,
                        PULONGLONG_ = 13, PWSTRING_ = 10, SID_ = 12, PSTRING_ = 11 };
    static Output* op;
    static std::thread outputThread;
    static bool evidenceOnly;
    static bool isWdm;
    static ThreadPool* parsePools;
    static ThreadPool* serializePool;
    static std::atomic<ULONG64> successParse;
};
