#pragma once
#include "tools/filter.h"
#include "output/output.h"
#include "tools/threadpool.h"
#include "sub_event.h"
#include "tools/json.hpp"
#include <tdh.h>
using json = nlohmann::json;

class EventParser {

public:
    static void eventParseThreadFunc(BaseEvent* event);
    void eventParseFunc(BaseEvent* event, PEVENT_RECORD pEvent);
    //static void eventParseThreadFunc(PEVENT_RECORD pEvent);
    static VOID WINAPI ConsumeEventSub(PEVENT_RECORD p_event);
    static VOID WINAPI ConsumeEventMain(PEVENT_RECORD p_event);
    static VOID WINAPI ConsumeUserEvent(PEVENT_RECORD p_event);
    VOID WINAPI GetFormattedPropertiesByTdh(PEVENT_RECORD pEvent);
    BaseEvent* WINAPI getEventWithIdentifier(PEVENT_RECORD pEvent);

     BaseEvent* WINAPI getUserEventWithIdentifier(PEVENT_RECORD pEvent) ;
    BaseEvent*  getPropertiesByParsingOffset(BaseEvent* event, int userDataLen, void* userDataBeginAddress);
    //BaseEvent*  getPropertiesByParsingOffset(BaseEvent* event, PEVENT_RECORD pEvent);
    DWORD PrintProperties4GetProperties(BaseEvent* event,PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, LPWSTR pStructureName, USHORT StructIndex);
    BaseEvent* WINAPI GetPropertiesByTdh(PEVENT_RECORD pEvent);
    BaseEvent*  getRawEvent(PEVENT_RECORD pEvent);
    DWORD FormatAndPrintData(BaseEvent* event,PEVENT_RECORD pEvent, USHORT InType, USHORT OutType, PBYTE pData, DWORD DataSize, PEVENT_MAP_INFO pMapInfo);
    void PrintMapString(PEVENT_MAP_INFO pMapInfo, PBYTE pData);
    DWORD GetArraySize4GetProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize);
    DWORD GetMapInfo4GetProperties(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO& pMapInfo);
    void RemoveTrailingSpace4GetProperties(PEVENT_MAP_INFO pMapInfo);
    DWORD GetEventInformation4GetProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO& pInfo);
    PBYTE ansiStr2wStr(PBYTE str);
    static void beginThreadParse() {
        threadParseFlag = true;
    }
    static void endThreadParse() {
        threadParseFlag = false;
    }
    void addThreadParseProviders(ULONG64 proid) {
        threadParseProviders.insert(proid);
    }
    void removeThreadParseProviders(ULONG64 proid) {
        threadParseProviders.erase(proid);
    }
    static bool inThreadParseProviders(ULONG64 proid) {
        return threadParseProviders.count(proid) != 0;
    }
    //static void initOutPut(int type, std::string option);

    //following functions are provided by TDH‘ library
    BaseEvent* WINAPI getPropertiesByTdh(PEVENT_RECORD pEvent);
    //static VOID WINAPI GetFormattedPropertiesByTdh(PEVENT_RECORD pEvent,std::ofstream fout);
    DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize);
    //DWORD GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO& pInfo);
    DWORD FormatAndPrintData(PEVENT_RECORD pEvent, USHORT InType, USHORT OutType, PBYTE pData, DWORD DataSize,
                             PEVENT_MAP_INFO pMapInfo, std::string paramName);

    void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo);
    DWORD GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO& pInfo);
    DWORD GetPropertyLength(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT PropertyLength);
    DWORD PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, LPWSTR pStructureName, USHORT StructIndex);
    DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO& pMapInfo);
    DWORD PrintPropertyMetadata(TRACE_EVENT_INFO* pinfo, DWORD i, USHORT indent);
    VOID WINAPI GetEventMetaData(PEVENT_RECORD pEvent);

    void SetargsJson(std::string name ,std::string value){
        argsJson[name]=value;
    }
    void SetargsJson(std::string name ,ULONG64 value){
        argsJson[name]=value;
    }
public:
    friend class Initializer;
    friend class EventProcess;
    static json j;
    static json argsJson;

private:
    static Filter filter;
    static Output* op;
    static ThreadPool* parsePools;	//thread pool, each thread in pool used to parse event.
    enum PropertyType { PBYTE_ = 1, PUSHORT_ = 2, PULONG4_ = 4, PULONG8_ = 8, PULONGLONG_ = 13, PWSTRING_ = 10, SID_ = 12, PSTRING_ = 11 };
    static PropertyType propertyType;
    static bool isWdm;
    static std::atomic<ULONG64> successParse;
    static std::set<ULONG64> threadParseProviders;
    static std::atomic<bool> threadParseFlag;
};
