//#pragma once
//
//// Prototypes for get_properties
//
////void WINAPI ProcessEvent(PEVENT_RECORD pEvent);
//DWORD GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO& pInfo);
//DWORD PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, LPWSTR pStructureName, USHORT StructIndex);
//DWORD FormatAndPrintData(PEVENT_RECORD pEvent, USHORT InType, USHORT OutType, PBYTE pData, DWORD DataSize, PEVENT_MAP_INFO pMapInfo , std::wstring paramName);
//void PrintMapString(PEVENT_MAP_INFO pMapInfo, PBYTE pData);
//DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize);
//DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO& pMapInfo);
//void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo);
//
////// Prototypes for get_formatted_properties
////void WINAPI ProcessEvent(PEVENT_RECORD pEvent);
//DWORD GetEventInformation4GetFormattedProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO& pInfo);
//PBYTE PrintProperties4GetFormattedProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, DWORD PointerSize, USHORT i, PBYTE pUserData, PBYTE pEndOfUserData);
//DWORD GetPropertyLength(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT PropertyLength);
//DWORD GetArraySize4GetFormattedProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize);
//DWORD GetMapInfo4GetFormattedProperties(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO& pMapInfo);
//void RemoveTrailingSpace4GetFormattedProperties(PEVENT_MAP_INFO pMapInfo);
//
//// Prototypes for get_event_metadata
//
////void WINAPI ProcessEvent(PEVENT_RECORD pEvent);
//DWORD GetEventInformation4GetEventMetadata(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO& pInfo);
//DWORD PrintPropertyMetadata(TRACE_EVENT_INFO* pInfo, DWORD i, USHORT indent);
//
//
//
