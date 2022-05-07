#pragma once
#include "output/output.h"
#include "etw_configuration.h"
#include <tdh.h>
#include "tools/json.hpp"
#include "sub_event.h"
#include "tools/filter.h"
#include "tools/threadpool.h"

typedef VOID(WINAPI* consume_event_func_ptr) (PEVENT_RECORD);

//以下是providerID
#define ProviderFileIo		0x90cbdc39
#define ProviderThread		0x3d6fa8d1
#define ProviderProcess		0x3d6fa8d0
#define ProviderImage		0x2cb15d1d
#define ProviderRegistry	0xae53722e
#define ProviderALPC		0x45d8cccd
#define ProviderDiskIo		0x3d6fa8d4
#define ProviderPerfInfo	0xce1dbfb4
#define ProviderTcpIp		0x9a280ac0
#define ProviderUdpIp		0xbf3a50c5
#define ProviderSysConfig   0x01853a65
#define ProviderStackWalk	0xdef2fe46
#define ProviderPageFault   0x3D6FA8D3

class EventParser {

public:
	friend class Initializer;
	friend class EventProcess;
	static void eventParseThreadFunc(Event* event);
	static void eventParseFunc(Event* event, PEVENT_RECORD pEvent);
	//static void eventParseThreadFunc(PEVENT_RECORD pEvent);
	static VOID WINAPI ConsumeEventSub(PEVENT_RECORD p_event);
	static VOID WINAPI ConsumeEventMain(PEVENT_RECORD p_event);
	//static VOID WINAPI GetFormattedPropertiesByTdh(PEVENT_RECORD pEvent,std::ofstream fout);
	static VOID WINAPI GetFormattedPropertiesByTdh(PEVENT_RECORD pEvent);
	static Event* WINAPI getEventWithIdentifier(PEVENT_RECORD pEvent);
	
	//static EventRecord WINAPI GetThreadFormattedProperties(PEVENT_RECORD pEvent);
	//static VOID WINAPI GetPropertiesByTdh(PEVENT_RECORD pEvent, nlohmann::json& res_json);
	Event*  getPropertiesByParsingOffset(Event* event, int userDataLen, void* userDataBeginAddress);
	//Event*  getPropertiesByParsingOffset(Event* event, PEVENT_RECORD pEvent);
	Event*  getRawEvent(PEVENT_RECORD pEvent);
	
	Event* WINAPI getPropertiesByTdh(PEVENT_RECORD pEvent);
	DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize);
	//DWORD GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO& pInfo);
	DWORD FormatAndPrintData(PEVENT_RECORD pEvent, USHORT InType, USHORT OutType, PBYTE pData, DWORD DataSize,
		PEVENT_MAP_INFO pMapInfo, std::string paramName);
	void PrintMapString(PEVENT_MAP_INFO pMapInfo, PBYTE pData);
	void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo);
	DWORD GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO& pInfo);
	DWORD GetPropertyLength(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT PropertyLength);
	DWORD PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, LPWSTR pStructureName, USHORT StructIndex);
	DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO& pMapInfo);
	DWORD PrintPropertyMetadata(TRACE_EVENT_INFO* pinfo, DWORD i, USHORT indent);
	VOID WINAPI GetEventMetaData(PEVENT_RECORD pEvent);
	//static void initOutPut(int type, std::string option);

	static void beginThreadParse() {

		//EventParser::threadParseProviders.insert(ProviderTcpIp);
		//EventParser::threadParseProviders.insert(ProviderThread);
		//EventParser::threadParseProviders.insert(ProviderDiskIo);
		//EventParser::threadParseProviders.insert(ProviderStackWalk);

		threadParseFlag = true;
	}

	static void endThreadParse() {

		threadParseFlag = false;
		//EventParser::threadParseProviders.clear();
		//EventParser::threadParseProviders.erase(ProviderStackWalk);
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

private:
	static Filter filter;
	static OutPut* op;
	static ThreadPool* parsePools;	//创建一个线程池
	static enum propertyType { PBYTE_ = 1, PUSHORT_ = 2, PULONG4_ = 4, PULONG8_ = 8, PULONGLONG_ = 13, PWSTRING_ = 10, SID_ = 12, PSTRING_ = 11 };

	static std::atomic<ULONG64> successParse;
	static std::set<ULONG64> threadParseProviders;
	static std::atomic<bool> threadParseFlag;

};
