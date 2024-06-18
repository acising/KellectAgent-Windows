//Turns the DEFINE_GUID for EventTraceGuid into a const.
#define _CRT_SECURE_NO_WARNINGS
#pragma once
#include <atlstr.h>     //CString��ͷ�ļ�

#define INITGUID
#include <string>
#include <windows.h>
#include <stdio.h>
#include <strsafe.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <evntrace.h>
#include <tdh.h>
#include <in6addr.h>
#include<iostream>
#include <ws2ipdef.h>
#include <WS2tcpip.h>
#include "tools/json.hpp"
#include "process/event.h"
#include "output/output.h"
#include "process/event_parse.h"

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "ws2_32.lib")  // For ntohs function

#define LOGFILE_PATH L"C:\\mylogfile.etl"

#define MAX_NAME 256
 USHORT g_PointerSize1 = 0;
using namespace std;
string argName;                 //����arguments�����еĲ�����
BaseEvent* userEvent;
bool isChineseCharacter(std::string str) {
    int i = 0;
    for (; i < str.length(); i++)
    {
        //不是全角字符
        if (str[i] >= 0 && str[i] <= 127)
        {

        }
        else
        {
            return true;
        }
    }
    return false;
}
json EventParser:: argsJson;
std::string WString2String(LPCWSTR ws) {
    int nLen = WideCharToMultiByte(CP_UTF8, 0, ws, -1, NULL, 0, NULL, NULL);
    if (nLen == 0)	return nullptr;
    char* pResult = new char[nLen];
    WideCharToMultiByte(CP_ACP, 0, ws, -1, pResult, nLen, NULL, NULL);
    std::string res = pResult;
    delete pResult;
    return res;
}
typedef LPTSTR(NTAPI* PIPV6ADDRTOSTRING)(
        const IN6_ADDR* Addr,
        LPTSTR S
);
// Pointer value. The value will be 4 or 8.


class StyledWriter;

//�����ַ�תΪstring
string Unicode2AnsiString(LPCWSTR ws) {

    CString str(ws);
    string s(CW2A(reinterpret_cast<LPCWSTR>(str.GetString())));

    return s;
}




BaseEvent* WINAPI EventParser::getUserEventWithIdentifier(PEVENT_RECORD pEvent) {
    BaseEvent* event = new EventUSer;

    event->setProcessorID(pEvent->BufferContext.ProcessorIndex);
    event->setProcessID(pEvent->EventHeader.ProcessId);     //TCPIP的pEvent中processID ThreadID
    event->setThreadID(pEvent->EventHeader.ThreadId);
    event->setTimeStamp(pEvent->EventHeader.TimeStamp.QuadPart);
//    event->setSTimeStamp(Tools::convertTimestamp(pEvent->EventHeader.TimeStamp.QuadPart));
    event->setEventIdentifier(
            new EventIdentifier(pEvent->EventHeader.ProviderId.Data1,pEvent->EventHeader.EventDescriptor.Opcode)
    );
    return event;
}



//
//BaseEvent*WINAPI EventParser:: GetPropertiesByTdh(PEVENT_RECORD pEvent)
//{
//    ULONG g_TimerResolution = 0;
//    json();
//    BOOL g_bUserMode = FALSE;
//
//    TRACEHANDLE g_hTrace = 0;
//
//    DWORD status = ERROR_SUCCESS;
//    PTRACE_EVENT_INFO pInfo = NULL;
//    LPWSTR pwsEventGuid = NULL;
//    status = GetEventInformation4GetProperties(pEvent, pInfo);
////    if (IsEqualGUID(pEvent->EventHeader.ProviderId, EventTraceGuid) &&
////        pEvent->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_INFO)
////    {
////        ; // Skip this event.
////    }
////    else
////    {
////        status = GetEventInformation4GetProperties(pEvent, pInfo);
////
////        if (ERROR_SUCCESS != status)
////        {
////            wprintf(L"GetEventInformation failed with %lu\n", status);
////            goto cleanup;
////        }
////        if (DecodingSourceWbem == pInfo->DecodingSource)  // MOF class
////        {
////            HRESULT hr = StringFromCLSID(pInfo->EventGuid, &pwsEventGuid);
////
////            if (FAILED(hr))
////            {
////                wprintf(L"StringFromCLSID failed with 0x%x\n", hr);
////                status = hr;
////                goto cleanup;
////            }
////            std::wstring wstr(pwsEventGuid);
////            std::string eventGuid(wstr.begin(), wstr.end());
////            j["Event_GUID"]= eventGuid;
////            CoTaskMemFree(pwsEventGuid);
////            pwsEventGuid = NULL;
////            j["Event_version"]= pEvent->EventHeader.EventDescriptor.Version;
////            j["Event_opCode"]= pEvent->EventHeader.EventDescriptor.Opcode;
////
////        }
////        else if (DecodingSourceXMLFile == pInfo->DecodingSource) // Instrumentation manifest
////        {
////
////            j["Event_ProviderId"]= pEvent->EventHeader.ProviderId.Data1;
////
////        }
////        else // Not handling the WPP case
////        {
////            goto cleanup;
////        }
////        std::wstring wstr(reinterpret_cast<wchar_t*>(reinterpret_cast<PBYTE>(pInfo) + pInfo->ProviderNameOffset));
////        std::string providerName(wstr.begin(), wstr.end());
////        j["Provider_name"]= providerName;
////        j["Event_ID"]= pInfo->EventDescriptor.Id;
////        j["Thread_ID"]=pEvent->EventHeader.ThreadId;
////        j["Process_ID"]=pEvent->EventHeader.ProcessId;
////        j["TimeStamp"]=pEvent->EventHeader.TimeStamp.QuadPart;
////        if (EVENT_HEADER_FLAG_32_BIT_HEADER == (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER))
////        {
////            g_PointerSize = 4;
////        }
////        else
////        {
////            g_PointerSize = 8;
////        }
////
////        if (EVENT_HEADER_FLAG_STRING_ONLY == (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY))
////        {
////            wprintf(L"userdata：%s\n", (LPWSTR)pEvent->UserData);
////        }
////        else
////        {
//            status = GetEventInformation4GetProperties(pEvent, pInfo);
//            for (USHORT i = 0; i < pInfo->TopLevelPropertyCount; i++)
//            {
//                status = PrintProperties4GetProperties(pEvent, pInfo, i, NULL, 0);
//                if (ERROR_SUCCESS != status)
//                {
//                    wprintf(L"Printing top level properties failed.\n");
//                    goto cleanup;
//                }
//                j["args"]=argsJson;
//                std::string* sJson = new std::string(j.dump());
////                std::cout<<j.dump()<<std::endl;
////                std::cout<<""<<std::endl;
//               op->output(j.dump());
//                delete sJson;
////            }
////        }
//    }
//
//    cleanup:
//
//    if (pInfo)
//    {
//        free(pInfo);
//    }
//
//    if (ERROR_SUCCESS != status)
//    {
//        CloseTrace(g_hTrace);
//    }
//
//}


// Print the property.

DWORD EventParser:: PrintProperties4GetProperties(BaseEvent* event,PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, LPWSTR pStructureName, USHORT StructIndex)
{
    userEvent=event;
    DWORD status = ERROR_SUCCESS;
    DWORD LastMember = 0;  // Last member of a structure
    USHORT ArraySize = 0;
    PEVENT_MAP_INFO pMapInfo = NULL;
    PROPERTY_DATA_DESCRIPTOR DataDescriptors[2];
    ULONG DescriptorsCount = 0;
    DWORD PropertySize = 0;
    PBYTE pData = NULL;

    // Get the size of the array if the property is an array.

    status = GetArraySize4GetProperties(pEvent, pInfo, i, &ArraySize);

    for (USHORT k = 0; k < ArraySize; k++)
    {
//        wprintf(L"%*s%s: ", (pStructureName) ? 4 : 0, L"", (LPWSTR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
        argName = WString2String((LPWSTR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
        if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
        {
            LastMember = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex +
                         pInfo->EventPropertyInfoArray[i].structType.NumOfStructMembers;
            for (USHORT j = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex; j < LastMember; j++)
            {
                status = PrintProperties4GetProperties(event,pEvent, pInfo, j, (LPWSTR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset), k);
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

            if (pStructureName)     //���Ҫ������Ϊ�ṹ��Ա�����ԵĴ�С����ָ��������������������������
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
                //DataDescriptors[0].ArrayIndex = k;
                DataDescriptors[0].ArrayIndex = ULONG_MAX;
                DescriptorsCount = 1;
            }

            if (TDH_INTYPE_BINARY == pInfo->EventPropertyInfoArray[i].nonStructType.InType &&
                TDH_OUTTYPE_IPV6 == pInfo->EventPropertyInfoArray[i].nonStructType.OutType)
            {
                wprintf(L"The event contains an IPv6 address. Skipping event.\n");
                status = ERROR_EVT_INVALID_EVENT_DATA;
                break;
            }
            else
            {

                status = TdhGetPropertySize(
                        pEvent,                 //���ݸ�EventRecordCallback�ص����¼���¼��event record��
                        0,
                        NULL,
                        DescriptorsCount,       //pPropertyData�������������ṹ��������
                        &DataDescriptors[0],    //PROPERTY_DATA_DESCRIPTOR�ṹ���飬���ڶ���Ҫ�������С�����ԡ�
                        &PropertySize);         //���ԵĴ�С�����ֽ�Ϊ��λ

                //cout << "status:" << status << endl;



                if (ERROR_SUCCESS != status)
                {
                    wprintf(L"TdhGetPropertySize failed with %lu\n", status);

                    //TODO
                    //connid�޷���ȷ��ȡ���ԡ���������Ϊ������ִ�У������ظ�statusΪ0�������
                    if (wcscmp((LPWSTR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset), L"connid") == 0) {
                        status = 0;
                    }
                    goto cleanup;
                }

                pData = (PBYTE)malloc(PropertySize);

                if (NULL == pData)
                {
                    wprintf(L"Failed to allocate memory for property data\n");
                    status = ERROR_OUTOFMEMORY;
                    goto cleanup;
                }

                status = TdhGetProperty(pEvent, 0, NULL, DescriptorsCount, &DataDescriptors[0], PropertySize, pData);

                // Get the name/value mapping if the property specifies a value map.
                if (ERROR_SUCCESS != status)
                {
                    wprintf(L"GetMapInfo failed\n");
                    goto cleanup;
                }

                status = FormatAndPrintData(event,pEvent,
                                            pInfo->EventPropertyInfoArray[i].nonStructType.InType,
                                            pInfo->EventPropertyInfoArray[i].nonStructType.OutType,
                                            pData,
                                            PropertySize,
                                            pMapInfo
                );

                if (ERROR_SUCCESS != status)
                {
                    wprintf(L"GetMapInfo failed\n");
                    goto cleanup;
                }

                if (pData)
                {
                    free(pData); C:
                    pData = NULL;
                }

                if (pMapInfo)
                {
                    free(pMapInfo);
                    pMapInfo = NULL;
                }
            }
        }
    }

    cleanup:

    if (pData)
    {
        free(pData);
        pData = NULL;
    }

    if (pMapInfo)
    {
        free(pMapInfo);
        pMapInfo = NULL;
    }

    return status;
}

DWORD EventParser:: FormatAndPrintData(BaseEvent* event,PEVENT_RECORD pEvent, USHORT InType, USHORT OutType, PBYTE pData, DWORD DataSize, PEVENT_MAP_INFO pMapInfo)
{
    UNREFERENCED_PARAMETER(pEvent);
    dataType* paramValue = nullptr;
    DWORD status = ERROR_SUCCESS;

    if (pEvent->EventHeader.ProviderId.Data1 == 2429279289 && pEvent->EventHeader.EventDescriptor.Opcode == 64) {
        int a = 0;
    }
    switch (InType)
    {
        case TDH_INTYPE_UNICODESTRING:
        case TDH_INTYPE_COUNTEDSTRING:
        case TDH_INTYPE_REVERSEDCOUNTEDSTRING:
        case TDH_INTYPE_NONNULLTERMINATEDSTRING:
        {
            size_t StringLength = 0;

            if (TDH_INTYPE_COUNTEDSTRING == InType)
            {
                StringLength = *(PUSHORT)pData;
            }
            else if (TDH_INTYPE_REVERSEDCOUNTEDSTRING == InType)
            {
                StringLength = MAKEWORD(HIBYTE((PUSHORT)pData), LOBYTE((PUSHORT)pData));
            }
            else if (TDH_INTYPE_NONNULLTERMINATEDSTRING == InType)
            {
                StringLength = DataSize;
            }
            else
            {
                StringLength = wcslen((LPWSTR)pData);
            }
            paramValue = new dataType(WString2String((LPWSTR) pData));
//            string  w =  paramValue->getString();
//            string r=w;
//            if( isChineseCharacter(w)){
//                std::cout<<argName<<r<<std::endl;
//            }else{
//                std::cout<<argName<<w<<std::endl;
//                j[argName]=w;
//            }
//            paramValue=nullptr;
//            std::cout <<argName<< ": " << paramValue->getString() << std::endl;
//            paramValue=nullptr;
//            wprintf(L"%.*s\n", StringLength, (LPWSTR)pData);
            break;
        }

        case TDH_INTYPE_ANSISTRING:
        case TDH_INTYPE_COUNTEDANSISTRING:
        case TDH_INTYPE_REVERSEDCOUNTEDANSISTRING:
        case TDH_INTYPE_NONNULLTERMINATEDANSISTRING:
        {
            size_t StringLength = 0;

            if (TDH_INTYPE_COUNTEDANSISTRING == InType)
            {
                StringLength = *(PUSHORT)pData;
            }
            else if (TDH_INTYPE_REVERSEDCOUNTEDANSISTRING == InType)
            {
                StringLength = MAKEWORD(HIBYTE((PUSHORT)pData), LOBYTE((PUSHORT)pData));
            }
            else if (TDH_INTYPE_NONNULLTERMINATEDANSISTRING == InType)
            {
                StringLength = DataSize;
            }
            else
            {
                StringLength = strlen((LPSTR)pData);
            }
            paramValue = new dataType(WString2String((LPWSTR) pData));
//            wprintf(L"%.*S\n", StringLength, (LPSTR)pData);
            break;
        }

        case TDH_INTYPE_INT8:
        {
            paramValue = new dataType(*(PCHAR) pData);
//            wprintf(L"%hd\n", *(PCHAR)pData);
            break;
        }

        case TDH_INTYPE_UINT8:
        {
            if (TDH_OUTTYPE_HEXINT8 == OutType)
            {
                paramValue = new dataType(*(PBYTE) pData);
//                wprintf(L"0x%x\n", *(PBYTE)pData);
            }
            else
            {
                paramValue = new dataType(*(PBYTE) pData);
//                wprintf(L"%hu\n", *(PBYTE)pData);
            }

            break;
        }

        case TDH_INTYPE_INT16:
        {
            paramValue = new dataType(*(PUSHORT) pData);
//            wprintf(L"%hd\n", *(PSHORT)pData);
            break;
        }

        case TDH_INTYPE_UINT16:
        {
            if (TDH_OUTTYPE_HEXINT16 == OutType)
            {
                paramValue = new dataType(*(PUSHORT) pData);
//                wprintf(L"0x%x\n", *(PUSHORT)pData);
            }
            else if (TDH_OUTTYPE_PORT == OutType)
            {
                paramValue = new dataType(*(PUSHORT) pData);
//                wprintf(L"%hu\n", ntohs(*(PUSHORT)pData));
            }
            else
            {
                paramValue = new dataType(*(PUSHORT) pData);
//                wprintf(L"%hu\n", *(PUSHORT)pData);
            }

            break;
        }

        case TDH_INTYPE_INT32:
        {
            paramValue = new dataType(*(PLONG) pData);
//            if (TDH_OUTTYPE_HRESULT == OutType)
//            {
//                wprintf(L"0x%x\n", *(PLONG)pData);
//            }
//            else
//            {
//                wprintf(L"%d\n", *(PLONG)pData);
//            }

            break;
        }

        case TDH_INTYPE_UINT32:
        {
            if (TDH_OUTTYPE_HRESULT == OutType ||
                TDH_OUTTYPE_WIN32ERROR == OutType ||
                TDH_OUTTYPE_NTSTATUS == OutType ||
                TDH_OUTTYPE_HEXINT32 == OutType)
            {
                paramValue = new dataType(*(PULONG) pData);
//                wprintf(L"0x%x\n", *(PULONG)pData);
            }
            else if (TDH_OUTTYPE_IPV4 == OutType)
            {
                CHAR temp[36] = {0};

                sprintf_s(temp, 36, "%d.%d.%d.%d", (*(PLONG) pData >> 0) & 0xff,
                          (*(PLONG) pData >> 8) & 0xff,
                          (*(PLONG) pData >> 16) & 0xff,
                          (*(PLONG) pData >> 24) & 0xff);
                paramValue = new dataType(temp);
//                wprintf(L"%d.%d.%d.%d\n", (*(PLONG)pData >> 0) & 0xff,
//                        (*(PLONG)pData >> 8) & 0xff,
//                        (*(PLONG)pData >> 16) & 0xff,
//                        (*(PLONG)pData >> 24) & 0xff);
            }
            else
            {
                if (pMapInfo)
                {
                    PrintMapString(pMapInfo, pData);
                }
                else
                {
                    paramValue = new dataType(*(PULONG) pData);
//                    wprintf(L"%lu\n", *(PULONG)pData);
                }
            }

            break;
        }

        case TDH_INTYPE_INT64:
        {
            paramValue = new dataType(*(PULONGLONG) pData);
//            wprintf(L"%I64d\n", *(PLONGLONG)pData);

            break;
        }

        case TDH_INTYPE_UINT64:
        {
            paramValue = new dataType(*(PULONGLONG) pData);
//            if (TDH_OUTTYPE_HEXINT64 == OutType)
//            {
//                wprintf(L"0x%x\n", *(PULONGLONG)pData);
//            }
//            else
//            {
//                wprintf(L"%I64u\n", *(PULONGLONG)pData);
//            }

            break;
        }

        case TDH_INTYPE_FLOAT:
        {
            paramValue = new dataType(*(PFLOAT) pData);
//            wprintf(L"%f\n", *(PFLOAT)pData);

            break;
        }

        case TDH_INTYPE_DOUBLE:
        {
            paramValue = new dataType(*(DOUBLE *) pData);
//            wprintf(L"%I64f\n", *(DOUBLE*)pData);

            break;
        }

        case TDH_INTYPE_BOOLEAN:
        {
            paramValue = new dataType(*(PBOOL) pData);
//            wprintf(L"%s\n", (0 == (PBOOL)pData) ? L"false" : L"true");

            break;
        }

        case TDH_INTYPE_BINARY:
        {
            if (TDH_OUTTYPE_IPV6 == OutType)
            {
                WCHAR IPv6AddressAsString[46];
                PIPV6ADDRTOSTRING fnRtlIpv6AddressToString;

                fnRtlIpv6AddressToString = (PIPV6ADDRTOSTRING)GetProcAddress(
                        GetModuleHandle(reinterpret_cast<LPCSTR>(L"ntdll")), "RtlIpv6AddressToStringW");

                if (NULL == fnRtlIpv6AddressToString)
                {
                    wprintf(L"GetProcAddress failed with %lu.\n", status = GetLastError());
                    goto cleanup;
                }

                fnRtlIpv6AddressToString((IN6_ADDR*)pData, reinterpret_cast<LPTSTR>(IPv6AddressAsString));
                paramValue = new dataType(reinterpret_cast<ULONG64>(IPv6AddressAsString));
//                wprintf(L"%s\n", IPv6AddressAsString);
            }
            else if(TDH_OUTTYPE_SOCKETADDRESS == OutType) {

                sockaddr_in *pSockAddr = reinterpret_cast<sockaddr_in *>(pData);


                char IPv4AddressAsString[INET_ADDRSTRLEN];
                const char *result = inet_ntop(AF_INET, &(pSockAddr->sin_addr), IPv4AddressAsString, INET_ADDRSTRLEN);

                if (result == nullptr) {
                    wprintf(L"inet_ntop failed with error: %d\n", WSAGetLastError());
                }
                paramValue = new dataType(reinterpret_cast<ULONG64>(IPv4AddressAsString));
//                wprintf(L"%S\n", IPv4AddressAsString);
            }
            else
            {
//                for (DWORD i = 0; i < DataSize; i++)
//                {
//                    wprintf(L"%.2x", pData[i]);
//                }
                std::stringstream ss;
                for (DWORD i = 0; i < DataSize; i++) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pData[i]);
                }
                std::string output = ss.str();
                paramValue = new dataType(output);
//                wprintf(L"\n");
            }

            break;
        }

        case TDH_INTYPE_GUID:
        {
            WCHAR szGuid[50];

            StringFromGUID2(*(GUID*)pData, szGuid, sizeof(szGuid) - 1);
//            wprintf(L"%s\n", szGuid);
            paramValue = new dataType(WString2String(szGuid));

            break;
        }

        case TDH_INTYPE_POINTER:
        case TDH_INTYPE_SIZET:
        {
//            if (4 == g_PointerSize)
//            {
//                wprintf(L"0x%x\n", *(PULONG)pData);
//            }
//            else
//            {
//                wprintf(L"0x%x\n", *(PULONGLONG)pData);
//            }
            paramValue = new dataType(*(PULONG) pData);
            break;
        }

        case TDH_INTYPE_FILETIME:
        {
            break;
        }

        case TDH_INTYPE_SYSTEMTIME:
        {
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
                    wprintf(L"Unable to locate account for the specified SID\n");
                    status = ERROR_SUCCESS;
                }
                else
                {
                    wprintf(L"LookupAccountSid failed with %lu\n", status = GetLastError());
                }

                goto cleanup;
            }
            else
            {
//                wprintf(L"%s\\%s\n", DomainName, UserName);
            }

            break;
        }

        case TDH_INTYPE_HEXINT32:
        {
            paramValue = new dataType(*(PULONGLONG) pData);
//            wprintf(L"0x%x\n", (PULONG)pData);
            break;
        }

        case TDH_INTYPE_HEXINT64:
        {
            paramValue = new dataType(*(PULONGLONG) pData);
//            wprintf(L"0x%x\n", (PULONGLONG)pData);
            break;
        }

        case TDH_INTYPE_UNICODECHAR:
        {
            paramValue = new dataType(*(PWCHAR) pData);
//            wprintf(L"%c\n", *(PWCHAR)pData);
            break;
        }

        case TDH_INTYPE_ANSICHAR:
        {
            std::string tempValue((PCHAR) pData);
            paramValue = new dataType(tempValue);
//            wprintf(L"%C\n", *(PCHAR)pData);
            break;
        }

        case TDH_INTYPE_WBEMSID:
        {
            WCHAR UserName[MAX_NAME];
            WCHAR DomainName[MAX_NAME];
            DWORD cchUserSize = MAX_NAME;
            DWORD cchDomainSize = MAX_NAME;
            SID_NAME_USE eNameUse;

            if (reinterpret_cast<int>((PULONG) pData) > 0)
            {
                // A WBEM SID is actually a TOKEN_USER structure followed
                // by the SID. The size of the TOKEN_USER structure differs
                // depending on whether the events were generated on a 32-bit
                // or 64-bit architecture. Also the structure is aligned
                // on an 8-byte boundary, so its size is 8 bytes on a
                // 32-bit computer and 16 bytes on a 64-bit computer.
                // Doubling the pointer size handles both cases.

                pData += g_PointerSize1 * 2;

                if (!LookupAccountSid(NULL, (PSID)pData, reinterpret_cast<LPSTR>(UserName), &cchUserSize,
                                      reinterpret_cast<LPSTR>(DomainName), &cchDomainSize, &eNameUse))
                {
                    if (ERROR_NONE_MAPPED == status)
                    {
                        wprintf(L"Unable to locate account for the specified SID\n");
                        status = ERROR_SUCCESS;
                    }
                    else
                    {
                        wprintf(L"LookupAccountSid failed with %lu\n", status = GetLastError());
                    }

                    goto cleanup;
                }
                else
                {
//                    wprintf(L"%s\\%s\n", DomainName, UserName);
                }
            }

            break;
        }

        default:
            status = ERROR_NOT_FOUND;
    }

    cleanup:

    if(paramValue){
//        if(paramValue->getIsString()){
//            argsJson[argName]=paramValue->getString();
//
//        }else{
//            argsJson[argName]=paramValue->getULONG64();
//
//        }
        event->setProperty(argName,paramValue);
    }
    return status;
}
void EventParser::  PrintMapString(PEVENT_MAP_INFO pMapInfo, PBYTE pData)
{
    cout << "������printmapstring����" << endl;

    BOOL MatchFound = FALSE;

    if ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_MANIFEST_VALUEMAP) == EVENTMAP_INFO_FLAG_MANIFEST_VALUEMAP ||
        ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_VALUEMAP) == EVENTMAP_INFO_FLAG_WBEM_VALUEMAP &&
         (pMapInfo->Flag & (~EVENTMAP_INFO_FLAG_WBEM_VALUEMAP)) != EVENTMAP_INFO_FLAG_WBEM_FLAG))
    {
        if ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_NO_MAP) == EVENTMAP_INFO_FLAG_WBEM_NO_MAP)
        {
            //wprintf(L"%s\n", (LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[*(PULONG)pData].OutputOffset));
        }
        else
        {
            for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
            {
                if (pMapInfo->MapEntryArray[i].Value == *(PULONG)pData)
                {
                    //wprintf(L"%s\n", (LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset));
                    MatchFound = TRUE;
                    break;
                }
            }

            if (FALSE == MatchFound)
            {
                //wprintf(L"%lu\n", *(PULONG)pData);
            }
        }
    }
    else if ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_MANIFEST_BITMAP) == EVENTMAP_INFO_FLAG_MANIFEST_BITMAP ||
             (pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_BITMAP) == EVENTMAP_INFO_FLAG_WBEM_BITMAP ||
             ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_VALUEMAP) == EVENTMAP_INFO_FLAG_WBEM_VALUEMAP &&
              (pMapInfo->Flag & (~EVENTMAP_INFO_FLAG_WBEM_VALUEMAP)) == EVENTMAP_INFO_FLAG_WBEM_FLAG))
    {
        if ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_NO_MAP) == EVENTMAP_INFO_FLAG_WBEM_NO_MAP)
        {
            DWORD BitPosition = 0;

            for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
            {
                if ((*(PULONG)pData & (BitPosition = (1 << i))) == BitPosition)
                {
                    wprintf(L"%s%s",
                            (MatchFound) ? L" | " : L"",
                            (LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset));

                    MatchFound = TRUE;
                }
            }

        }
        else
        {
            for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
            {
                if ((pMapInfo->MapEntryArray[i].Value & *(PULONG)pData) == pMapInfo->MapEntryArray[i].Value)
                {
                    wprintf(L"%s%s",
                            (MatchFound) ? L" | " : L"",
                            (LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset));

                    MatchFound = TRUE;
                }
            }
        }

        if (MatchFound)
        {
            //wprintf(L"\n");
        }
        else
        {
            //wprintf(L"%lu\n", *(PULONG)pData);
        }
    }
}

// Get the size of the array. For MOF-based events, the size is specified in the declaration or using
// the MAX qualifier. For manifest-based events, the property can specify the size of the array
// using the count attribute. The count attribue can specify the size directly or specify the name
// of another property in the event data that contains the size.

DWORD EventParser:: GetArraySize4GetProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize)
{
    DWORD status = ERROR_SUCCESS;
    PROPERTY_DATA_DESCRIPTOR DataDescriptor;
    DWORD PropertySize = 0;

    if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamCount) == PropertyParamCount)
    {
        DWORD Count = 0;  // Expects the count to be defined by a UINT16 or UINT32
        DWORD j = pInfo->EventPropertyInfoArray[i].countPropertyIndex;
        ZeroMemory(&DataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));

        //������һ��DataDescriptor���������ǽṹ�����ݣ�����DataDescriptor���飨��СΪ2���������ṹ��ĳ�Ա
        DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[j].NameOffset);
        DataDescriptor.ArrayIndex = ULONG_MAX;
        status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
        status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Count);
        *ArraySize = (USHORT)Count;
    }
    else
    {
        *ArraySize = pInfo->EventPropertyInfoArray[i].count;
    }

    return status;
}

// Both MOF-based events and manifest-based events can specify name/value maps. The
// map values can be integer values or bit values. If the property specifies a value
// map, get the map.

DWORD EventParser::GetMapInfo4GetProperties(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO& pMapInfo)
{
    DWORD status = ERROR_SUCCESS;
    DWORD MapSize = 0;

    // Retrieve the required buffer size for the map info.

    status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);

    if (ERROR_INSUFFICIENT_BUFFER == status)
    {
        pMapInfo = (PEVENT_MAP_INFO)malloc(MapSize);
        if (pMapInfo == NULL)
        {
            wprintf(L"Failed to allocate memory for map info (size=%lu).\n", MapSize);
            status = ERROR_OUTOFMEMORY;
            goto cleanup;
        }

        // Retrieve the map info.

        status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);
    }

    if (ERROR_SUCCESS == status)
    {
        if (DecodingSourceXMLFile == DecodingSource)
        {
            RemoveTrailingSpace4GetProperties(pMapInfo);
        }
    }
    else
    {
        if (ERROR_NOT_FOUND == status)
        {
            status = ERROR_SUCCESS; // This case is okay.
        }
        else
        {
            wprintf(L"TdhGetEventMapInformation failed with 0x%x.\n", status);
        }
    }

    cleanup:

    return status;
}

// The mapped string values defined in a manifest will contain a trailing space
// in the EVENT_MAP_ENTRY structure. Replace the trailing space with a null-
// terminating character, so that the bit mapped strings are correctly formatted.

void EventParser:: RemoveTrailingSpace4GetProperties(PEVENT_MAP_INFO pMapInfo)
{
    SIZE_T ByteLength = 0;

    for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
    {
        ByteLength = (wcslen((LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset)) - 1) * 2;
        *((LPWSTR)((PBYTE)pMapInfo + (pMapInfo->MapEntryArray[i].OutputOffset + ByteLength))) = L'\0';
    }
}

// Get the metadata for the event.
DWORD EventParser:: GetEventInformation4GetProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO& pInfo)
{
    DWORD status = ERROR_SUCCESS;
    DWORD BufferSize = 0;

    // Retrieve the required buffer size for the event metadata.

    status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);

    if (ERROR_INSUFFICIENT_BUFFER == status)
    {
        pInfo = (TRACE_EVENT_INFO*)malloc(BufferSize);
        if (pInfo == NULL)
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

        char desc[256];
        sprintf(desc, "no schema found for the provider:%lld and opCode:%d",
                pEvent->EventHeader.ProviderId.Data1, pEvent->EventHeader.EventDescriptor.Opcode);


        wprintf(L"TdhGetEventInformation failed with 0x%x.\n", status);
    }

    cleanup:

    return status;
}

PBYTE EventParser:: ansiStr2wStr(PBYTE str) {

    size_t convertedChars = 0;
    size_t len = strlen((LPSTR)str) + 1;
    WCHAR Temp[1280] = { 0 };

    //_TRUNCATE��unsigned long�����ֵ��convertedChars��ת�����ַ���
    mbstowcs_s(&convertedChars, Temp, len, (LPSTR)str, _TRUNCATE);
    return (PBYTE)Temp;
}
