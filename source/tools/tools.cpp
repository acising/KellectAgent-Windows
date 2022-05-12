#include <Windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include "tools/tools.h"
#include "process/event_parse.h"
#include "tools/logger.h"
#include <locale>

std::map <std::string, std::string > EventImage::volume2Disk;

std::string Tools::WString2String(LPCWSTR ws) {

    int nLen = WideCharToMultiByte(CP_UTF8, 0, ws, -1, NULL, 0, NULL, NULL);
    if (nLen == 0)	return nullptr;

    char* pResult = new char[nLen];
    WideCharToMultiByte(CP_ACP, 0, ws, -1, pResult, nLen, NULL, NULL);

    std::string res = pResult;
    delete pResult;
    return res;
}

std::wstring Tools::StringToWString(LPCSTR cs)
{
    int nLen = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, cs, -1, NULL, 0);
    if (nLen == 0)	return nullptr;

    wchar_t* pResult = new wchar_t[nLen];
    MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, cs, -1, pResult, nLen);

    std::wstring res = pResult;
    delete pResult;
    return res;

}

int Tools::String2Int(const std::string& s) {

    int res = -1;
    std::stringstream stream(s);
    stream >> res;

    return res;
}

std::string Tools::DecInt2HexStr(ULONG64 num)
{
    CHAR tempres[255];
    sprintf_s(tempres,255, "%llx", num);

    return tempres;
}


std::wstring Tools::DecInt2HexWStr(ULONG64 num)
{
    wchar_t tempres[255];
    swprintf_s(tempres, L"%llx", num);

    return tempres;
}
ULONG64 Tools::HexStr2DecInt(std::string s) {

    const char* phexch = s.c_str();
    ULONG64 res = strtoull(phexch, NULL, 16);

    return res;
}

std::string Tools::UnicodeToUtf8(const LPCWSTR unicode)
{
    int len;
    len = WideCharToMultiByte(CP_UTF8, 0, unicode, -1, NULL, 0, NULL, NULL);
    char* szUtf8 = (char*)malloc(len + 1);
    memset(szUtf8, 0, len + 1);
    WideCharToMultiByte(CP_UTF8, 0, unicode, -1, szUtf8, len, NULL, NULL);

    return szUtf8;
}
std::string Tools::getTimeFromSystemTimeStamp(LARGE_INTEGER timeStamp) {

    // Print the time stamp for when the event occurred.
    FILETIME ft;
    SYSTEMTIME stUTC;

    ft.dwHighDateTime = timeStamp.HighPart;
    ft.dwLowDateTime = timeStamp.LowPart;

    //std::string formattedTime;
    char formattedTime[128];
    FileTimeToSystemTime(&ft, &stUTC);

    sprintf(formattedTime,"%d-%d-%d %d:%d:%d.%d", stUTC.wYear, stUTC.wMonth,
            stUTC.wDay, stUTC.wHour+8, stUTC.wMinute, stUTC.wSecond, stUTC.wMilliseconds);

    return std::string(formattedTime);
}

void Tools::initVolume2DiskMap() {

    TCHAR drv = 0;
    TCHAR cDiskSymbol[] = _T("C:");
    //printf("pathValue=%s\n", pathValue);
    std::string pathParamName = "SystemRoot";
    std::string pathValue = getenv(pathParamName.c_str());

    EventImage::volume2Disk.insert(
            std::map<std::string, std::string>::value_type("\\" + pathParamName, pathValue));

    for (drv = _T('C'); drv <= _T('Z'); ++drv)
    {
        cDiskSymbol[0] = drv;
        {
            CHAR szBuf[MAX_PATH] = { 0 };
            QueryDosDeviceA(cDiskSymbol, szBuf, MAX_PATH);

            EventImage::volume2Disk.insert(std::map<std::string, std::string>::value_type(
//                    Tools::WString2String(reinterpret_cast<LPCWSTR>(szBuf)),
                    szBuf,
//                    Tools::WString2String(reinterpret_cast<LPCWSTR>(cDiskSymbol))));
                    cDiskSymbol));
            //_tprintf(_T("==== %s === %s  ===\n"), cDiskSymbol, szBuf);
        }
    }
}

ULONG64 Tools::String2ULONG64(const std::string& s) {

    ULONG64 res = -1;
    std::stringstream stream(s);
    stream >> res;

    return res;
}

void Tools::convertFileNameInDiskFormat(std::string &fileName) {

    if (fileName.empty()) {
        MyLogger::writeLog("fileName is empty, skip it");
        return;
    }

    if (strcmp(fileName.substr(0,7).c_str(), "\\Device") == 0) {
        std::string pathType = fileName.substr(0,23);

        std::map<std::string,std::string>::iterator it =  EventImage::volume2Disk.find(pathType);
        if (it == EventImage::volume2Disk.end()) {
            MyLogger::writeLog("not find the mapping imageFileName2DiskNumber");
            return;
        }

        fileName = it->second + fileName.substr(23);
    }
    else if (strcmp(fileName.substr(0,11).c_str(), "\\SystemRoot") == 0) {
        std::string pathType = fileName.substr(0, 11);

        std::map<std::string, std::string>::iterator it = EventImage::volume2Disk.find(pathType);
        if (it == EventImage::volume2Disk.end()) {
            MyLogger::writeLog("not find the mapping imageFileName2DiskNumber");
            return;
        }

        fileName = it->second.append(fileName.substr(11));
    }
}

void initThreadProcessMap(ULONG64 pid) {

    THREADENTRY32 te32;
    te32.dwSize = sizeof(te32);
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);

    if (hThreadSnap == INVALID_HANDLE_VALUE){
        MyLogger::writeLog("CreateToolhelp32Snapshot of thread failed.\n");
        return;
    }
    BOOL tMore = Thread32First(hThreadSnap, &te32);
    while (tMore) {
        //ReadWriteMap will OverWrite the item if the key is exist.
        //EventThread::threadId2processId.insert(te32.th32ThreadID, pid);
        EventThread::threadId2processId[te32.th32ThreadID] = pid;
        EventThread::threadSet.insert(te32.th32ThreadID);
        tMore = Thread32Next(hThreadSnap, &te32);
    }

    CloseHandle(hThreadSnap);
}

int InitProcessMap() {

    std::cout << "------Begin to initialize datas of process and thread...------" << std::endl;

    PROCESSENTRY32 pe32;
    int i = 0;
    //????????????????????????С
    pe32.dwSize = sizeof(pe32);

    //get the snapshot current processes
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        printf("CreateToolhelp32Snapshot of process failed.\n");
        return -1;
    }

    //search first process infomation by snapshot got before
    BOOL bMore = Process32First(hProcessSnap, &pe32);
    while (bMore)
    {
        //printf("processName:%ls\n", pe32.szExeFile);
        //printf("processID:%u\n\n", pe32.th32ProcessID);
        if (pe32.th32ProcessID != 0) {		//skip pid=0, which is idle process
            EventProcess::processID2Name[pe32.th32ProcessID] = pe32.szExeFile;

            //EventProcess::processID2Name.insert(pe32.th32ProcessID,Tools::WString2String((LPCWSTR)pe32.szExeFile));
            //EventProcess::processIDSet.insert(pe32.th32ProcessID);

            //std::wcout << EventProcess::processID2Name[pe32.th32ProcessID] << std::endl;
            initThreadProcessMap(pe32.th32ProcessID);
        }

        //search next process infomation by snapshot got before
        bMore = Process32Next(hProcessSnap, &pe32);
        ++i;
    }
    //set idle process mapping
    EventProcess::processID2Name[0] = "idle";
    EventProcess::processID2Name[INIT_PROCESS_ID] =  "Unknown" ;
    //EventProcess::processID2Name.insert(EventProcess::UnknownProcess, "Unknown" );
    //EventProcess::processID2Name.insert(0, "idle" );

    std::cout << "------Initialize datas of process and thread end...------" << std::endl;

    //release snapshot
    CloseHandle(hProcessSnap);

    return 0;
}

ULONG64	Tools::getProcessIDByTID(ULONG64 tid){

    PROCESSENTRY32 pe32;

    pe32.dwSize = sizeof(pe32);
    HANDLE hThreadSnap;
    THREADENTRY32 te32;
    ULONG64 pid = -1;

    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        MyLogger::writeLog("CreateToolhelp32Snapshot for process failed.\n");
        return pid;
    }
    BOOL tMore = false;

    BOOL bMore = Process32First(hProcessSnap, &pe32);
    while (bMore) {
        /*	if (pid == pe32.th32ProcessID) {
                pName = (LPCWSTR)pe32.szExeFile;
                break;
            }*/
        te32.dwSize = sizeof(te32);
        hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);

        if (hThreadSnap == INVALID_HANDLE_VALUE) {
            MyLogger::writeLog("CreateToolhelp32Snapshot for thread failed.\n");
            return 0;
        }
        tMore = Thread32First(hThreadSnap, &te32);
        while (tMore) {

            if (tid == te32.th32ThreadID) {
                pid = pe32.th32ProcessID;
                break;
            }
            tMore = Thread32Next(hThreadSnap, &te32);
        }
        CloseHandle(hThreadSnap);

        if (pid != -1)	break;
        bMore = Process32Next(hProcessSnap, &pe32);
    }

    CloseHandle(hProcessSnap);

    return pid;
}

std::wstring Tools::getProcessNameByPID(ULONG64 pid) {

    PROCESSENTRY32 pe32;
    int i = 0;

    pe32.dwSize = sizeof(pe32);
    std::wstring pName = L"";

    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE){
        MyLogger::writeLog("CreateToolhelp32Snapshot for process failed.\n");
        return pName;
    }
    BOOL bMore = Process32First(hProcessSnap, &pe32);
    while (bMore){
        if (pid == pe32.th32ProcessID) {
            pName = (LPCWSTR)pe32.szExeFile;
            break;
        }
        bMore = Process32Next(hProcessSnap, &pe32);
    }
    CloseHandle(hProcessSnap);

    return pName;
}