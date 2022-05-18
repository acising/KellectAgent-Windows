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
    }else if(strcmp(fileName.substr(0,11).c_str(), "%SystemRoot") == 0){
        std::string pathType = fileName.substr(0, 11);

        std::map<std::string, std::string>::iterator it = EventImage::volume2Disk.find("\\SystemRoot");
        if (it == EventImage::volume2Disk.end()) {
            MyLogger::writeLog("not find the mapping imageFileName2DiskNumber");
            return;
        }
        fileName = it->second.append(fileName.substr(11));
    }
}
std::string Tools::getProcessNameByPID(ULONG64 pid){

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);

    //get the snapshot current processes
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        printf("CreateToolhelp32Snapshot of process failed.\n");
    }else{
        //search first process infomation by snapshot got before
        BOOL bMore = Process32First(hProcessSnap, &pe32);
        while (bMore)
        {
            if (pe32.th32ProcessID == pid) {		//skip pid=0, which is idle process
                std::string res = pe32.szExeFile;
                CloseHandle(hProcessSnap);

                return res;
            }

            //search next process infomation by snapshot got before
            bMore = Process32Next(hProcessSnap, &pe32);
        }
        //release snapshot
        CloseHandle(hProcessSnap);
    }

    return "";
}

int	Tools::getProcessIDByTID(ULONG64 tid){

    HANDLE hThreadSnap;
    THREADENTRY32 te32;
    int pid = -1;

    te32.dwSize = sizeof(te32);
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);

    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        MyLogger::writeLog("CreateToolhelp32Snapshot for thread failed.\n");
        return pid;
    }
    BOOL tMore = Thread32First(hThreadSnap, &te32);

    while (tMore) {

        if (tid == te32.th32ThreadID) {
            pid = te32.th32OwnerProcessID;
            break;
        }
        tMore = Thread32Next(hThreadSnap, &te32);
    }
    CloseHandle(hThreadSnap);

    return pid;
}
