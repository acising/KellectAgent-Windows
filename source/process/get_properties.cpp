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
#include "process/customer_parse.h"
#include "process/event.h"
#include "process/etw_config.h"
#include "tools/json.hpp"
#include "tools/tools.h"
#include "tools/logger.h"
#include "tools/providerInfo.h"

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "ws2_32.lib")  // For ntohs function

#define LOGFILE_PATH L"C:\\mylogfile.etl"

#define MAX_NAME 256

using namespace std;
//using json = nlohmann::json;

//typedef LPTSTR(NTAPI* PIPV6ADDRTOSTRING)(
//    const IN6_ADDR* Addr,
//    LPTSTR S
//    );
// Pointer value. The value will be 4 or 8.
USHORT g_PointerSize = 8;

BaseEvent* event = nullptr;

BaseEvent* WINAPI EventParser::getEventWithIdentifier(PEVENT_RECORD pEvent) {

    BaseEvent* event = nullptr;

    switch (pEvent->EventHeader.ProviderId.Data1) // init by event type
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
        event = new EventCallstack;
        break;
    default:
        event = nullptr;
        return event;
    };

    event->setProcessorID(pEvent->BufferContext.ProcessorIndex);
    event->setProcessID(pEvent->EventHeader.ProcessId);
    event->setThreadID(pEvent->EventHeader.ThreadId);
    event->setTimeStamp(pEvent->EventHeader.TimeStamp.QuadPart);
    event->setEventIdentifier(
        new EventIdentifier(pEvent->EventHeader.ProviderId.Data1,pEvent->EventHeader.EventDescriptor.Opcode)
    );

    return event;
}

BaseEvent* EventParser::getPropertiesByParsingOffset(BaseEvent* event, int userDataLen, void* userDataBeginAddress) {

    //BaseEvent* event = getEventWithIdentifier(pEvent);

    if (event->getEventIdentifier()->getProviderID() != CallStackProvider) { //fill events' properties according to property offsets
        
        auto iter = BaseEvent::eventStructMap.find(event->getEventIdentifier());

        if (iter != BaseEvent::eventStructMap.end()) {

            dataType* dt = nullptr;
            ULONG64 dataAddress = (ULONG64)userDataBeginAddress;
            std::wstring wsVal;
            std::string sVal;

            //modify the eventName
            event->getEventIdentifier()->setEventName(iter->first->getEventName());

            for (auto it : iter->second) {

                switch (it.second) {
                case PULONG4_:
                    //std::wcout << *(PULONG)(dataAddress) << std::endl;
                    dt = new dataType(*(PULONG)(dataAddress));
                    dataAddress += 4;
                    break;
                case PULONG8_:
                    dt = new dataType(*(PULONG)(dataAddress));
                    //std::wcout << dt->getULONG64() << std::endl;
                    dataAddress += 8;
                    break;
                case PULONGLONG_:
                    dt = new dataType(*(PULONGLONG)(dataAddress));
                    //std::wcout << dt->getULONG64() << std::endl;
                    dataAddress += 8;
                    break;
                case PBYTE_:

                    dt = new dataType(*(PBYTE)(dataAddress));
                    //std::wcout << dt->getULONG64() << std::endl;
                    dataAddress += 1;
                    break;
                case PSTRING_:

                    sVal = (LPSTR)dataAddress;
 
                    dt = new dataType(sVal);
                    dataAddress += sVal.size() + 1;
                    //std::wcout << dt->getWString() << std::endl;
                    break;
                case PWSTRING_:

                    sVal = Tools::WString2String((LPWSTR)dataAddress);
                    dataAddress += sVal.size() + 1;

                    if (event->getEventIdentifier()->getProviderID() == FileProvider ||
                        event->getEventIdentifier()->getProviderID() == ImageProvider)
                        Tools::convertFileNameInDiskFormat(sVal);

                    dt = new dataType(sVal);
                    break;
                case PUSHORT_:
                    dt = new dataType(*(PUSHORT)(dataAddress));
                    //std::wcout << dt->getULONG64() << std::endl;
                    dataAddress += 2;
                    break;
                case SID_:

                    CHAR UserName[256];
                    CHAR DomainName[256];
                    DWORD cchUserSize = 256;
                    DWORD cchDomainSize = 256;
                    SID_NAME_USE eNameUse;
                    STATUS status = ERROR_SUCCESS;

                    dataAddress += 8 * 2;

                    if (!LookupAccountSidA(NULL, (PSID)dataAddress, UserName, &cchUserSize, DomainName, &cchDomainSize, &eNameUse))
                    {
                        if (ERROR_NONE_MAPPED == status)
                        {
                            //wprintf(L"Unable to locate account for the specified SID\n");
                            status = ERROR_SUCCESS;
                        }
                        else
                        {
                            //wprintf(L"LookupAccountSid failed with %lu\n", status = GetLastError());
                        }
                    }
                    sVal = DomainName;
                    sVal.append("\\");
                    sVal.append(UserName);
                    dt = new dataType(sVal);

                    dataAddress += GetLengthSid((PVOID)(dataAddress));
                    break;
                }
                event->setProperty(it.first, dt);
            }
            
            //event->deleteRawProperty(); //delete userdata
        }
    }
    else {
        int stacksNum;
        ULONG64 processID;
        ULONG64 stackAddress;
        EventIdentifier* ei;
        EventCallstack* callStackEvent = new EventCallstack();  // get stack address and return 
        ULONG64* p_data = (ULONG64*)userDataBeginAddress;
        size_t data_size = userDataLen;
        int processorId = event->getProcessorID();
        ULONG64 minAddr = 0xffffffff;
        ULONG64 maxAddr = 0;

        ei = new EventIdentifier(event->getEventIdentifier()->getProviderID(), event->getEventIdentifier()->getOpCode(), "CallStack");
        //callStackEvent->setEventIdentifier(ei);
        callStackEvent->setEventIdentifier(ei);
        callStackEvent->setProcessorID(processorId);
        callStackEvent->setTimeStamp(*p_data);
        callStackEvent->setProcessID(*(DWORD*)(++p_data));
        callStackEvent->setThreadID(*((DWORD*)p_data + 1));
        //event->setProcessName(EventProcess::processID2Name[*(DWORD*)p_data]);
        ++p_data;

        //second filter, filter according to revise processID
        if (Filter::secondFilter(callStackEvent)) {
            callStackEvent->setValueableEvent(false);
            //return callStackEvent;
        }
        else {

            //get call address number, -2 because of the callStack addresses begin from third property
            stacksNum = (data_size / 8 - 2);
            processID = callStackEvent->getProcessID();
            //auto it = EventProcess::processID2ModuleAddressPair.find(callStackEvent->getProcessID());
            if (EventProcess::processID2ModuleAddressPair.count(processID)!=0) {
                auto minmaxAddrPair = EventProcess::processID2ModuleAddressPair[processID];
                minAddr = minmaxAddrPair.first;
                maxAddr = minmaxAddrPair.second;
            }

            for (int i = 0; i < stacksNum; ++i) {

                stackAddress = *(p_data + i) & (0xffffffff);   //extract low32 bits of the address
                if (stackAddress<minAddr || stackAddress>maxAddr)  continue;

//                std::cout<<stackAddress<<";";

                callStackEvent->stackAddresses.push_back(stackAddress);
            }

        }
//        std::cout<<std::endl;
        //return callStackEvent;
        delete event;   //avoid memory leak
        event = callStackEvent;
    }

    return event;
}


BaseEvent* WINAPI EventParser::getPropertiesByTdh(PEVENT_RECORD pEvent)
{
    // Callback that receives the events. 
    // Used to determine the data size of property values that contain a
    // Used to calculate CPU usage
    ULONG g_TimerResolution = 0;

    // Used to determine if the session is a private session or kernel session.
    // You need to know this when accessing some members of the EVENT_TRACE.Header
    // member (for example, KernelTime or UserTime).
    BOOL g_bUserMode = FALSE;

    // Handle to the trace file that you opened.
    TRACEHANDLE g_hTrace = 0;

    DWORD status = ERROR_SUCCESS;
    PTRACE_EVENT_INFO pInfo = nullptr;
    LPWSTR pwsEventGuid = nullptr;

    //filter process 0 and 4
    if (pEvent->EventHeader.ProcessId == GetCurrentProcessId()) {
        //event->setValueableEvent(false);
        event = nullptr;
        goto cleanup;
    }

    // Skips the event if it is the event trace header. Log files contain this event
    // but real-time sessions do not. The event contains the same information as 
    // the EVENT_TRACE_LOGFILE.LogfileHeader member that you can access when you open 
    // the trace. 

    if (IsEqualGUID(pEvent->EventHeader.ProviderId, EventTraceGuid) &&
        pEvent->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_INFO)
    {
        ; // Skip this event.
    }
    else
    {
        // Process the event. The pEvent->UserData member is a pointer to 
        // the event specific data, if it exists.

        //pinfo contain some meta info
        status = this->GetEventInformation(pEvent, pInfo);
        if (pInfo == nullptr ||status == 0x490) {
            //MyLogger::writeLog("事件信息获取失败，opcode=" + pEvent->EventHeader.EventDescriptor.Opcode);
            event = nullptr;
            goto cleanup;
        }

        //init event type

        event = this->getEventWithIdentifier(pEvent);
        if (event->getEventIdentifier()->getProviderID() == CallStackProvider)  goto cleanup;

        // If the event contains event-specific data use TDH to extract
        // the event data. For this example, to extract the data, the event 
        // must be defined by a MOF class or an instrumentation manifest.

        // Need to get the PointerSize for each event to cover the case where you are
        // consuming events from multiple log files that could have been generated on 
        // different architectures. Otherwise, you could have accessed the pointer
        // size when you opened the trace above (see pHeader->PointerSize).

        if (EVENT_HEADER_FLAG_32_BIT_HEADER == (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER))
        {
            g_PointerSize = 4;
        }
        else
        {
            g_PointerSize = 8;
        }

        for (USHORT i = 0; i < pInfo->TopLevelPropertyCount; ++i)
        {
            status = this->PrintProperties(pEvent, pInfo, i, NULL, 0);
            //status = PrintProperties(pEvent, pInfo, i, (LPWSTR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset), 0);
            if (ERROR_SUCCESS != status)
            {
                MyLogger::writeLog("Printing top level properties failed.\n");
                goto cleanup;
            }
        }
    }

cleanup:

    if (pInfo)
    {
        free(pInfo);
    }

    //if (pEvent) 
    //{
    //    delete pEvent;
    //}
    if (ERROR_SUCCESS != status)
    {
        CloseTrace(g_hTrace);
    }

    return event;
}


// Print the property.
DWORD EventParser::PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, LPWSTR pStructureName, USHORT StructIndex)
{
    DWORD status = ERROR_SUCCESS;
    DWORD LastMember = 0;  // Last member of a structure
    USHORT ArraySize = 0;
    PEVENT_MAP_INFO pMapInfo = nullptr;
    PROPERTY_DATA_DESCRIPTOR DataDescriptors[2];
    ULONG DescriptorsCount = 0;
    DWORD PropertySize = 0;
    PBYTE pData = nullptr;

    // Get the size of the array if the property is an array.

    status = GetArraySize(pEvent, pInfo, i, &ArraySize);

    for (USHORT k = 0; k < ArraySize; ++k)
    {
        std::string paramName = Tools::WString2String((LPWSTR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));

        // If the property is a structure, print the members of the structure.
        if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
        {
            //the last index of struct
            LastMember = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex +
                pInfo->EventPropertyInfoArray[i].structType.NumOfStructMembers;

            for (USHORT j = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex; j < LastMember; ++j)
            {
                status = PrintProperties(pEvent, pInfo, j, (LPWSTR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset), k);
                if (ERROR_SUCCESS != status)
                {
                    wprintf(L"Printing the members of the structure failed.\n");
                    goto cleanup;
                }
            }
        }
        else
        {
            ZeroMemory(&DataDescriptors, sizeof(DataDescriptors));

            // To retrieve a member of a structure, you need to specify an array of descriptors. 
            // The first descriptor in the array identifies the name of the structure and the second 
            // descriptor defines the member of the structure whose data you want to retrieve. 

            if (pStructureName)
            {
                DataDescriptors[0].PropertyName = (ULONGLONG)pStructureName;
                DataDescriptors[0].ArrayIndex = StructIndex;
                DataDescriptors[1].PropertyName = (ULONGLONG)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset);
                DataDescriptors[1].ArrayIndex = k;
                DescriptorsCount = 2;
            }
            else
            {
                DataDescriptors[0].PropertyName = (ULONGLONG)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset);
                std::wstring name = (LPCWSTR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset);
                //DataDescriptors[0].ArrayIndex = k;
                DataDescriptors[0].ArrayIndex = ULONG_MAX;
                DescriptorsCount = 1;
            }

            // The TDH API does not support IPv6 addresses. If the output type is TDH_OUTTYPE_IPV6,
            // you will not be able to consume the rest of the event. If you try to consume the
            // remainder of the event, you will get ERROR_EVT_INVALID_EVENT_DATA.

            if (TDH_INTYPE_BINARY == pInfo->EventPropertyInfoArray[i].nonStructType.InType &&
                TDH_OUTTYPE_IPV6 == pInfo->EventPropertyInfoArray[i].nonStructType.OutType){

                //wprintf(L"The event contains an IPv6 address. Skipping event.\n");
                status = ERROR_EVT_INVALID_EVENT_DATA;
                event->setValueableEvent(false);
                break;
            }
            else{
                status = TdhGetPropertySize(
                    pEvent,
                    0,  
                    NULL, 
                    DescriptorsCount,
                    &DataDescriptors[0],
                    &PropertySize);

                if (ERROR_SUCCESS != status){

                    //wprintf(L"TdhGetPropertySize failed with %lu , %s\n", status, paramName);
                    if (strcmp("connid", paramName.c_str()) == 0) {
                        auto connid = *(PULONG64)((ULONG64)pEvent->UserData + pEvent->UserDataLength - 8);
                        event->setProperty(BaseEvent::connid, new dataType(connid));

                        auto port1 = *(PSHORT)((ULONG64)pEvent->UserData + pEvent->UserDataLength - 14);
                        auto port2 = *(PSHORT)((ULONG64)pEvent->UserData + pEvent->UserDataLength - 16);

                        status = NO_ERROR;
                    }
                    goto cleanup;
                }

                pData = (PBYTE)malloc(PropertySize);

                if (nullptr == pData){
                    wprintf(L"Failed to allocate memory for property data\n");
                    status = ERROR_OUTOFMEMORY;
                    goto cleanup;
                }


                status = TdhGetProperty(pEvent, 0, NULL, DescriptorsCount, &DataDescriptors[0], PropertySize, pData);

                // Get the name/value mapping if the property specifies a value map.

                /*status = GetMapInfo(pEvent,
                    (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].nonStructType.MapNameOffset),
                    pInfo->DecodingSource,
                    pMapInfo);

                if (ERROR_SUCCESS != status){
                    wprintf(L"GetMapInfo failed\n");
                    goto cleanup;
                }*/


                status = FormatAndPrintData(pEvent,
                    pInfo->EventPropertyInfoArray[i].nonStructType.InType,
                    pInfo->EventPropertyInfoArray[i].nonStructType.OutType,
                    pData,
                    PropertySize,
                    pMapInfo,
                    paramName       //属性名
                );

                if (ERROR_SUCCESS != status)    wprintf(L"GetMapInfo failed\n");

                goto cleanup;
            }
        }
    }

cleanup:

    if (pData)
    {
        free(pData);
        pData = nullptr;
    }

    if (pMapInfo)
    {
        free(pMapInfo);
        pMapInfo = nullptr;
    }

    return status;
}

DWORD EventParser::FormatAndPrintData(PEVENT_RECORD pEvent, USHORT InType, USHORT OutType, PBYTE pData, DWORD DataSize, PEVENT_MAP_INFO pMapInfo, std::string paramName)
{
    UNREFERENCED_PARAMETER(pEvent);
   
    DWORD status = ERROR_SUCCESS;
    dataType* paramValue = nullptr;
    //ULONG64 addr = (ULONG64)pData;

    //if (pEvent->EventHeader.ProviderId.Data1 == 1030727888)   //process
    //    int a = 0;
    //if (pEvent->EventHeader.ProviderId.Data1 == 1030727889)   //thread
    //    int a = 0;
    //if (pEvent->EventHeader.ProviderId.Data1 == 749821213)     //image
    //    int a = 0;
    //if (pEvent->EventHeader.ProviderId.Data1 == 2586315456)     //TCP
    //    int a = 0;
    //if (pEvent->EventHeader.ProviderId.Data1 == 2924704302)     //Registry
    //    int a = 0;
    if (pEvent->EventHeader.ProviderId.Data1 == 2429279289 && pEvent->EventHeader.EventDescriptor.Opcode == 80)     //File
        int a = 0;
    switch (InType)
    {
    case TDH_INTYPE_UNICODESTRING:
    case TDH_INTYPE_COUNTEDSTRING:
    case TDH_INTYPE_REVERSEDCOUNTEDSTRING:
    case TDH_INTYPE_NONNULLTERMINATEDSTRING:
    {
        paramValue =new dataType(Tools::WString2String((LPWSTR)pData));
        break;
    }

    case TDH_INTYPE_ANSISTRING:
    case TDH_INTYPE_COUNTEDANSISTRING:
    case TDH_INTYPE_REVERSEDCOUNTEDANSISTRING:
    case TDH_INTYPE_NONNULLTERMINATEDANSISTRING:
    {
        paramValue = new dataType((LPSTR)pData);
        break;
    }

    case TDH_INTYPE_INT8:
    case TDH_INTYPE_UINT8:
    {
        paramValue = new dataType(*(PBYTE)pData);
        break;
    }

    case TDH_INTYPE_INT16:
    case TDH_INTYPE_UINT16:
    {
        paramValue = new dataType(*(PUSHORT)pData);
        break;
    }

    case TDH_INTYPE_INT32:
    {
        paramValue = new dataType(*(PLONG)pData);
        break;
    }

    case TDH_INTYPE_UINT32:
    {
        if (TDH_OUTTYPE_HRESULT == OutType ||
            TDH_OUTTYPE_WIN32ERROR == OutType ||
            TDH_OUTTYPE_NTSTATUS == OutType ||
            TDH_OUTTYPE_HEXINT32 == OutType)
        {
            paramValue = new dataType(*(PULONG)pData);
        }
        else if (TDH_OUTTYPE_IPV4 == OutType)
        {
            CHAR temp[36] = { 0 };

            sprintf_s(temp, 36, "%d.%d.%d.%d", (*(PLONG)pData >> 0) & 0xff,
                (*(PLONG)pData >> 8) & 0xff,
                (*(PLONG)pData >> 16) & 0xff,
                (*(PLONG)pData >> 24) & 0xff);

            paramValue = new dataType(temp);
        }
        else
        {
            //if (pMapInfo)
            //{
            //    PrintMapString(pMapInfo, pData);
            //}
            //else
            //{
            //    paramValue = dataType(*(PULONG)pData);
            //}
            paramValue = new dataType(*(PULONG)pData);
        }
        break;
    }

    case TDH_INTYPE_INT64:
    case TDH_INTYPE_UINT64:
    {
        paramValue = new dataType(*(PULONGLONG)pData);
        break;
    }
    case TDH_INTYPE_FLOAT:
    {
        paramValue = new dataType(*(PFLOAT)pData);
        break;
    }
    case TDH_INTYPE_DOUBLE:
    {
        paramValue = new dataType(*(DOUBLE*)pData);
        break;
    }
    case TDH_INTYPE_BOOLEAN:
    {
        paramValue = new dataType(*(PBOOL)pData);
        break;
    }
    //case TDH_INTYPE_BINARY:
    //{
    //    if (TDH_OUTTYPE_IPV6 == OutType)
    //    {
    //        WCHAR IPv6AddressAsString[46];
    //        PIPV6ADDRTOSTRING fnRtlIpv6AddressToString;

    //        fnRtlIpv6AddressToString = (PIPV6ADDRTOSTRING)GetProcAddress(
    //            GetModuleHandle(L"ntdll"), "RtlIpv6AddressToStringW");

    //        if (NULL == fnRtlIpv6AddressToString)
    //        {
    //            wprintf(L"GetProcAddress failed with %lu.\n", status = GetLastError());
    //            goto cleanup;
    //        }

    //        fnRtlIpv6AddressToString((IN6_ADDR*)pData, IPv6AddressAsString);

    //        //wprintf(L"%s\n", IPv6AddressAsString);
    //    }
    //    else
    //    {
    //        for (DWORD i = 0; i < DataSize; i++)
    //        {
    //            wprintf(L"%.2x", pData[i]);
    //        }

    //        //wprintf(L"\n");
    //    }

    //    break;
    //}
    case TDH_INTYPE_GUID:
    {
        WCHAR szGuid[50];
        StringFromGUID2(*(GUID*)pData, szGuid, sizeof(szGuid) - 1);

        paramValue = new dataType(Tools::WString2String(szGuid));
        break;
    }

    case TDH_INTYPE_POINTER:
    case TDH_INTYPE_SIZET:
    {
        paramValue = new dataType(*(PULONG)pData);
        break;
    }
    case TDH_INTYPE_SID:
    {
        WCHAR UserName[MAX_NAME];
        WCHAR DomainName[MAX_NAME];
        DWORD cchUserSize = MAX_NAME;
        DWORD cchDomainSize = MAX_NAME;
        SID_NAME_USE eNameUse;

        if (!LookupAccountSid(NULL, (PSID)pData, reinterpret_cast<LPSTR>(UserName), &cchUserSize,
                              reinterpret_cast<LPSTR>(DomainName), &cchDomainSize, &eNameUse))
        {
            if (ERROR_NONE_MAPPED == status)
            {
                //wprintf(L"Unable to locate account for the specified SID\n");
                status = ERROR_SUCCESS;
            }
            else
            {
                //wprintf(L"LookupAccountSid failed with %lu\n", status = GetLastError());
            }
            goto cleanup;
        }
        else
        {
            //wprintf(L"%s\\%s\n", DomainName, UserName);
        }
        break;
    }

    case TDH_INTYPE_HEXINT32:
    {
        paramValue = new dataType(*(PULONGLONG)pData);
        break;
    }

    case TDH_INTYPE_HEXINT64:
    {
        paramValue = new dataType(*(PULONGLONG)pData);
        break;
    }

    case TDH_INTYPE_UNICODECHAR:
    {
        paramValue = new dataType(*(PWCHAR)pData);
        break;
    }
    case TDH_INTYPE_ANSICHAR:
    {
        string tempValue((PCHAR)pData);
        paramValue = new dataType(tempValue);
        break;
    }
    case TDH_INTYPE_WBEMSID:
    {
        WCHAR UserName[MAX_NAME];
        WCHAR DomainName[MAX_NAME];
        DWORD cchUserSize = MAX_NAME;
        DWORD cchDomainSize = MAX_NAME;
        SID_NAME_USE eNameUse;

        if ((PULONG)pData > 0)
        {
            // A WBEM SID is actually a TOKEN_USER structure followed 
            // by the SID. The size of the TOKEN_USER structure differs 
            // depending on whether the events were generated on a 32-bit 
            // or 64-bit architecture. Also the structure is aligned
            // on an 8-byte boundary, so its size is 8 bytes on a
            // 32-bit computer and 16 bytes on a 64-bit computer.
            // Doubling the pointer size handles both cases.

            pData += g_PointerSize * 2;

            if (!LookupAccountSid(NULL, (PSID)pData, reinterpret_cast<LPSTR>(UserName), &cchUserSize,
                                  reinterpret_cast<LPSTR>(DomainName), &cchDomainSize, &eNameUse))
            {
                if (ERROR_NONE_MAPPED == status)
                {
                    wprintf(L"Unable to locate account for the specified SID\n");
                    status = ERROR_SUCCESS;
                }
                goto cleanup;
            }
            else
            {
                //wprintf(L"%s\\%s\n", DomainName, UserName);
            }
        }

        break;
    }

    default:
        status = ERROR_NOT_FOUND;
    }

cleanup:

    if (pEvent->EventHeader.ProviderId.Data1 == 1030727888)
        int a = 0;
    event->setProperty(paramName,paramValue);
    //delete paramValue;
    return status;
}


// Get the size of the array. For MOF-based events, the size is specified in the declaration or using 
// the MAX qualifier. For manifest-based events, the property can specify the size of the array
// using the count attribute. The count attribue can specify the size directly or specify the name 
// of another property in the event data that contains the size.

DWORD EventParser::GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize)
{
    DWORD status = ERROR_SUCCESS;

    if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamCount) == PropertyParamCount)
    {
        DWORD PropertySize = 0;
        PROPERTY_DATA_DESCRIPTOR DataDescriptor;
        DWORD Count = 0;  // Expects the count to be defined by a UINT16 or UINT32
        DWORD j = pInfo->EventPropertyInfoArray[i].countPropertyIndex;
        ZeroMemory(&DataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));

        DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[j].NameOffset);
        DataDescriptor.ArrayIndex = ULONG_MAX;
        status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
        status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Count);
        *ArraySize = (USHORT)Count;
    }
    else *ArraySize = pInfo->EventPropertyInfoArray[i].count;

    return status;
}

// Both MOF-based events and manifest-based events can specify name/value maps. The
// map values can be integer values or bit values. If the property specifies a value
// map, get the map.

//DWORD EventParser::GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO& pMapInfo)
//{
//    DWORD status = ERROR_SUCCESS;
//    DWORD MapSize = 0;
//
//    // Retrieve the required buffer size for the map info.
//
//    status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);
//
//    if (ERROR_INSUFFICIENT_BUFFER == status){
//        pMapInfo = (PEVENT_MAP_INFO)malloc(MapSize);
//        if (pMapInfo == NULL){
//            wprintf(L"Failed to allocate memory for map info (size=%lu).\n", MapSize);
//            status = ERROR_OUTOFMEMORY;
//            goto cleanup;
//        }
//
//        // Retrieve the map info.
//        status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);
//    }
//
//    if (ERROR_SUCCESS == status){
//        if (DecodingSourceXMLFile == DecodingSource)    RemoveTrailingSpace(pMapInfo);
//    }else{
//        if (ERROR_NOT_FOUND == status){
//            status = ERROR_SUCCESS; // This case is okay.
//        }
//        else  wprintf(L"TdhGetEventMapInformation failed with 0x%x.\n", status);
//    }
//
//cleanup:
//
//    return status;
//}

// The mapped string values defined in a manifest will contain a trailing space
// in the EVENT_MAP_ENTRY structure. Replace the trailing space with a null-
// terminating character, so that the bit mapped strings are correctly formatted.

//void EventParser::RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo)
//{
//    SIZE_T ByteLength = 0;
//
//    for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
//    {
//        ByteLength = (wcslen((LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset)) - 1) * 2;
//        *((LPWSTR)((PBYTE)pMapInfo + (pMapInfo->MapEntryArray[i].OutputOffset + ByteLength))) = L'\0';
//    }
//}

// Get the metadata for the event.
DWORD EventParser::GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO& pInfo)
{
    DWORD status = ERROR_SUCCESS;
    DWORD BufferSize = 0;

    // Retrieve the required buffer size for the event metadata.

    status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);

    if (ERROR_INSUFFICIENT_BUFFER == status)
    {
        pInfo = (TRACE_EVENT_INFO*)malloc(BufferSize);
        if (pInfo == nullptr)
        {
            wprintf(L"Failed to allocate memory for event info (size=%lu).\n", BufferSize);
            status = ERROR_OUTOFMEMORY;
            goto cleanup;
        }

        // Retrieve the event metadata.

        status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);
    }

    if (ERROR_SUCCESS != status)
    {
        //wprintf(L"TdhGetEventInformation failed with 0x%x.\n", status);
    }

cleanup:

    return status;
}


