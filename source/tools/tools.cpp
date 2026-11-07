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
    if (nLen == 0) return nullptr;

    char* pResult = new char[nLen];
    WideCharToMultiByte(CP_UTF8, 0, ws, -1, pResult, nLen, NULL, NULL);

    std::string res = pResult;
    delete[] pResult; // 使用 delete[] 来释放内存

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

// Create every missing component of the directory that holds `filePath`.
// FileOutPut uses this so `-f %ProgramData%\Kellect\events\x.jsonl` succeeds on
// a machine where nothing was ever written by Kellect (the service writes there
// by default, and a failed open used to abort the whole collector).
bool Tools::ensureParentDirectory(const std::string& filePath) {
    const size_t slash = filePath.find_last_of("\\/");
    if (slash == std::string::npos) return true;

    std::string dir = filePath.substr(0, slash);
    if (dir.empty()) return true;

    std::string current;
    size_t i = 0;
    if (dir.size() >= 2 && dir[1] == ':') {
        current = dir.substr(0, 2);   // "C:"
        i = 2;
    }
    for (; i <= dir.size(); ++i) {
        if (i == dir.size() || dir[i] == '\\' || dir[i] == '/') {
            if (!current.empty() && current.back() != ':') {
                if (!CreateDirectoryA(current.c_str(), nullptr)) {
                    const DWORD err = GetLastError();
                    // ERROR_ALREADY_EXISTS is the normal case after the first
                    // event; ERROR_ACCESS_DENIED must not stop the caller.
                    if (err != ERROR_ALREADY_EXISTS && err != ERROR_ACCESS_DENIED) {
                        MyLogger::writeLog("create directory failed: " + current);
                    }
                }
            }
        }
        if (i < dir.size()) current.push_back(dir[i]);
    }
    return true;
}

void Tools::convertFileNameInDiskFormat(std::string &fileName) {
    if (fileName.empty())
        return;   // common for FileIo_Name-less records; never log per event

    if (strcmp(fileName.substr(0,7).c_str(), "\\Device") == 0) {

        int idx = fileName.find('\\',9);
        if(idx != -1){
            std::string pathType = fileName.substr(0,idx);
            std::map<std::string,std::string>::iterator it =  EventImage::volume2Disk.find(pathType);
            if(it != EventImage::volume2Disk.end())
                fileName = it->second + fileName.substr(idx);
        }else{
            MyLogger::writeLog("not find the mapping imageFileName2DiskNumber");
        }
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

bool Tools::getOSVersion(DWORD& dwMajorVer, DWORD& dwMinorVer,DWORD& dwBuildNumber)
{
    BOOL bRet= FALSE;
    HMODULE hModNtdll= NULL;
    if (hModNtdll= ::LoadLibraryW(L"ntdll.dll"))
    {
        typedef void (WINAPI *pfRTLGETNTVERSIONNUMBERS)(DWORD*,DWORD*, DWORD*);
        pfRTLGETNTVERSIONNUMBERS pfRtlGetNtVersionNumbers;
        pfRtlGetNtVersionNumbers = (pfRTLGETNTVERSIONNUMBERS)::GetProcAddress(hModNtdll, "RtlGetNtVersionNumbers");
        if (pfRtlGetNtVersionNumbers)
        {
            pfRtlGetNtVersionNumbers(&dwMajorVer, &dwMinorVer,&dwBuildNumber);
            dwBuildNumber&= 0x0ffff;
            bRet = TRUE;
        }

        ::FreeLibrary(hModNtdll);
        hModNtdll = NULL;
    }

    return bRet;
}

std::string Tools::convertTimestamp(ULONG64 timestamp){

//    int hourNanoSecond = 60*60*1000*1000;
//    int minuteNanoSecond = 60*1000*1000;
//    int sec = 60*1000*1000;
    ULONG64 duration = 369;
//    duration *= 369;
    duration *= 365;
    duration *= 24;
    duration *= 60*60*1000;
    time_t tt = (timestamp/10000-duration)/1000;

    time_t current = time(NULL);
    struct tm *tmp_time_current = gmtime(&current);
    struct tm *tmp_time = gmtime(&tt);
    char s[100];


    strftime(s, sizeof(s)+1, "%04Y%02m%02d %H:%M:%S", tmp_time_current);
    printf("%I64d: %s\n", (ULONG64)tt, s);

    int a = 0;

    return s;
}

void Tools::appendUnsigned(std::string& out, unsigned long long v) {
    char buffer[24];
    int n = 0;
    do {
        buffer[n++] = static_cast<char>('0' + static_cast<int>(v % 10));
        v /= 10;
    } while (v != 0);
    while (n > 0)
        out.push_back(buffer[--n]);
}

void Tools::appendInt(std::string& out, long long v) {
    if (v < 0) {
        out.push_back('-');
        // Negate without overflow on LLONG_MIN.
        appendUnsigned(out, static_cast<unsigned long long>(-(v + 1)) + 1ull);
    } else {
        appendUnsigned(out, static_cast<unsigned long long>(v));
    }
}

// Appends `s` escaped per RFC 8259. Copies runs of plain bytes in bulk (most
// paths/command lines need no escaping at all) instead of pushing char by char.
void Tools::appendJsonEscaped(std::string& out, const std::string& s) {
    const size_t n = s.size();
    size_t i = 0;
    while (i < n) {
        const size_t runStart = i;
        while (i < n) {
            const unsigned char c = static_cast<unsigned char>(s[i]);
            if (c < 0x20 || c == '"' || c == '\\')
                break;
            ++i;
        }
        if (i > runStart)
            out.append(s, runStart, i - runStart);
        if (i >= n)
            break;

        const unsigned char c = static_cast<unsigned char>(s[i]);
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default: {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
                out += buf;
            }
        }
        ++i;
    }
}

// JSON string escape per RFC 8259: ", \, control chars; other chars (<0x20)
// as u00xx. Leaves multi-byte UTF-8 bytes untouched.
std::string Tools::jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    appendJsonEscaped(out, s);
    return out;
}
