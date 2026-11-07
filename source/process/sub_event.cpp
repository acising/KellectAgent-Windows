#include <windows.h>
#include <tlhelp32.h>
#include "tools/logger.h"
#include "tools/tools.h"
#include "process/sub_event.h"
#include <fstream>
#include <regex>
#include <algorithm>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include <codecvt>
#include "nlohmann/json.hpp"
#include "filter.h"
//#include "process/etw_config.h"
#include "process/event_parse.h"
#include "tools/providerInfo.h"
#include "runtime/evidence.h"
#include "process/pe_metadata.h"

ReadWriteMap<ULONG64,std::string> EventRegistry::keyHandle2KeyName;
std::map< ULONG64, std::string*> EventPerfInfo::systemCallMap;
std::map< ULONG64, std::string*> EventPerfInfo::systemCallMapUsed;
std::set<ULONG64> EventThread::threadSet;
std::mutex EventImage::modulesApiMutex;
std::map<int, int> EventProcess::processID2ParentProcessID;
std::map<std::string, std::string> processList;
std::map<std::string, std::string> fileList;
std::map<std::string, std::string> registryList;
std::map<std::string, std::string> socketList;
std::set<std::string> noEventList;
std::string Initializer::uuid;  //declare static property

namespace {

// ---- deferred export-table loader -----------------------------------------
// LoadLibrary + PE export walk costs hundreds of microseconds per image and
// used to run inside EventImage::parse (first on the ETW callback thread, then
// on the ordered parse thread). A burst of ImageLoad events (process start
// storms, WOW64 processes) would stall every other event behind it. The loader
// runs on its own thread; CallStack reads the tables under modulesApiMutex and
// simply resolves fewer API names until a table is published.
std::mutex g_apiQueueMutex;
std::condition_variable g_apiQueueCv;
std::deque<std::string> g_apiQueue;
bool g_apiLoaderStarted = false;
bool g_apiLoaderStop = false;
std::thread g_apiLoader;
const size_t kApiQueueLimit = 4096;
constexpr size_t kMaxCachedModules = 256;
constexpr size_t kMaxCachedExports = 128 * 1024;
size_t g_cachedExports = 0;
bool g_adaptiveExports = true;

std::wstring ImagePath(const std::string& utf8) {
    const int length = static_cast<int>(utf8.size());
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), length, nullptr, 0);
    if (!count)
        return {};
    std::wstring result(count, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), length, &result[0], count);
    return result;
}

void ApiLoaderLoop() {
    for (;;) {
        std::string imageFileName;
        {
            std::unique_lock<std::mutex> lock(g_apiQueueMutex);
            g_apiQueueCv.wait(lock, [] { return g_apiLoaderStop || !g_apiQueue.empty(); });
            if (g_apiLoaderStop)
                return;
            imageFileName = std::move(g_apiQueue.front());
            g_apiQueue.pop_front();
        }
        EventImage::loadModuleApis(imageFileName);
    }
}

} // namespace

void EventImage::PreEnumerateModules() {
    HANDLE procSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (procSnap == INVALID_HANDLE_VALUE)
        return;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(procSnap, &pe)) {
        do {
            const DWORD pid = pe.th32ProcessID;
            if (pid == 0)
                continue;
            HANDLE modSnap = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if (modSnap == INVALID_HANDLE_VALUE)
                continue;

            MODULEENTRY32W me{};
            me.dwSize = sizeof(me);
            if (Module32FirstW(modSnap, &me)) {
                auto& modules = processID2Modules[static_cast<int>(pid)];
                do {
                    const ULONG64 begin = reinterpret_cast<ULONG64>(me.modBaseAddr);
                    const ULONG64 end = begin + me.modBaseSize;
                    std::string path = Tools::WString2String(me.szExePath);
                    modules.erase(begin);
                    modules.emplace(begin, Module(begin, end, path));
                } while (Module32NextW(modSnap, &me));
            }
            CloseHandle(modSnap);
        } while (Process32NextW(procSnap, &pe));
    }
    CloseHandle(procSnap);
}

void EventImage::startApiLoader() {
    std::lock_guard<std::mutex> lock(g_apiQueueMutex);
    if (g_apiLoaderStarted)
        return;
    g_apiLoaderStarted = true;
    g_apiLoaderStop = false;
    g_apiLoader = std::thread(ApiLoaderLoop);
}

void EventImage::stopApiLoader() {
    {
        std::lock_guard<std::mutex> lock(g_apiQueueMutex);
        g_apiLoaderStop = true;
        g_apiLoaderStarted = false;
        g_apiQueue.clear();
    }
    g_apiQueueCv.notify_one();
    if (g_apiLoader.joinable())
        g_apiLoader.join();
}

bool EventImage::enqueueModuleApis(const std::string& imageFileName) {
    {
        std::lock_guard<std::mutex> lock(g_apiQueueMutex);
        if (!g_apiLoaderStarted || g_apiQueue.size() >= kApiQueueLimit)
            return false;
        g_apiQueue.push_back(imageFileName);
    }
    g_apiQueueCv.notify_one();
    return true;
}

void EventImage::loadModuleApis(const std::string& imageFileName) {
    auto path = ImagePath(imageFileName);
    kellect::PeMetadata metadata;
    if (path.empty() || !kellect::ReadPeMetadata(path, metadata) || metadata.exports.empty())
        return;

    std::lock_guard<std::mutex> lock(EventImage::modulesApiMutex);
    if (EventImage::modulesName2APIs.count(imageFileName) ||
        EventImage::modulesName2APIs.size() >= kMaxCachedModules ||
        metadata.exports.size() > kMaxCachedExports - g_cachedExports)
        return;
    auto& apis = EventImage::modulesName2APIs[imageFileName];
    for (auto& entry : metadata.exports)
        apis.insert(new MyAPI(entry.rva, std::move(entry.name)));
    g_cachedExports += apis.size();
}

void EventImage::setAdaptiveExports(bool enabled) {
    g_adaptiveExports = enabled;
}
using json = nlohmann::json;
std::string jsonString = R"({ "ProcessStart": "EVENT_EXECUTE", "ThreadStart": "EVENT_CREATE_THREAD", "RegistryDeleteValue": "EVENT_MODIFY_FILE_ATTRIBUTES", "FileIORead": "EVENT_READ",
"FileIOFileCreate": "EVENT_CREATE_OBJECT", "FileIOWrite": "EVENT_WRITE", "RegistrySetValue": "EVENT_MODIFY_FILE_ATTRIBUTES", "RegistryCreate": "EVENT_CREATE_OBJECT",
"RegistryKCBCreate": "EVENT_CREATE_OBJECT", "TcpIpSendIPV4": "EVENT_SENDMSG", "TcpIpRecvIPV4": "EVENT_RECVMSG", "TcpIpSendIPV6": "EVENT_SENDMSG",
"TcpIpRecvIPV6": "EVENT_RECVMSG", "FileIORename": "EVENT_RENAME", "FileIOCreate": "EVENT_OPEN", "RegistryOpen": "EVENT_OPEN", "FileIOCleanup": "EVENT_CLOSE",
"RegistryClose": "EVENT_CLOSE", "FileIOClose": "EVENT_CLOSE", "FileIOFlush": "EVENT_CLOSE", "RegistryFlush": "EVENT_CLOSE", "ProcessEnd": "EVENT_EXIT",
"ThreadEnd": "EVENT_EXIT", "FileIOFileDelete": "EVENT_DELETE_OBJECT", "ImageLoad": "EVENT_LOADLIBARY", "TcpIpRetransmitIPV4": "EVENT_SENDMSG", "TcpIpRetransmitIPV6": "EVENT_SENDMSG",
"TcpIpAcceptIPV4": "EVENT_ACCEPT", "TcpIpAcceptIPV6": "EVENT_ACCEPT", "TcpIpConnectIPV4": "EVENT_CONNECT", "TcpIpConnectIPV6": "EVENT_CONNECT", "TcpIpDisconnectIPV4": "EVENT_CLOSE",
"TcpIpDisconnectIPV6": "EVENT_CLOSE", "TcpIpReconnectIPV6": "EVENT_CONNECT", "TcpIpReconnectIPV4": "EVENT_CONNECT", "RegistryDelete": "EVENT_DELETE", "RegistryKCBDelete": "EVENT_DELETE",
"RegistrySetInformation": "EVENT_UPDATE", "FileIODelete": "EVENT_DELETE", "FileIODirEnum": "EVENT_ITERATE", "RegistryQuery": "EVENT_ITERATE", "RegistryQueryValue": "EVENT_ITERATE",
"RegistryEnumerateKey": "EVENT_ITERATE", "RegistryEnumerateValueKey": "EVENT_ITERATE", "RegistryQueryMultipleValue": "EVENT_ITERATE", "FileIOFileRundown": "EVENT_DC_STAET",
"ImageDCStart": "EVENT_DC_STAET", "ProcessDCStart": "EVENT_DC_STAET", "ThreadDCStart": "EVENT_DC_STAET", "RegistryKCBRundownBegin": "EVENT_DC_STAET", "RegistryDCStart": "EVENT_DC_STAET",
"ProcessDCEnd": "EVENT_DC_END", "ThreadDCEnd": "EVENT_DC_END", "RegistryKCBRundownEnd": "EVENT_DC_END"})";

std::vector<std::string> fileEntity = {"FileIOFileCreate", "FileIOWrite", "FileIOFileDelete","FileIODelete", "FileIOFileRundown", "FileIORename"};
std::vector<std::string> registryEntity = {"RegistryDeleteValue", "RegistrySetValue", "RegistryCreate", "RegistryKCBCreate", "RegistryDelete", "RegistryKCBDelete",
                                          "RegistrySetInformation"};
std::vector<std::string>ignoreEvent={"FileIOCreate", "RegistryOpen", "FileIOCleanup", "RegistryClose", "FileIOClose",
"FileIOFlush", "RegistryFlush", "TcpIpAcceptIPV4", "TcpIpAcceptIPV6", "TcpIpConnectIPV4",
"TcpIpConnectIPV6", "TcpIpDisconnectIPV4", "TcpIpDisconnectIPV6", "TcpIpReconnectIPV6",
"TcpIpReconnectIPV4", "FileIODirEnum", "RegistryQuery", "RegistryQueryValue", "RegistryEnumerateKey",
"RegistryEnumerateValueKey", "RegistryQueryMultipleValue"};

json eventType = json::parse(jsonString);
json argsObject;
std::string to_utf8(std::wstring& wide_string)
{
    static std::wstring_convert<std::codecvt_utf8<wchar_t>> utf8_conv;
    return utf8_conv.to_bytes(wide_string);
}
void setFileName(BaseEvent* ev) {

	ULONG64 fileObject = 0;
	ULONG64 fileKey = 0;

	dataType* dt = ev->getProperty(BaseEvent::FileObject);
	if (dt) {
		fileObject = dt->getULONG64();
	}

	dt = ev->getProperty(BaseEvent::FileKey);
	if (dt) {
		fileKey = dt->getULONG64();
	}

	dataType* tempDataType;
	if (fileKey !=0 && EventFile::fileKey2Name.count(fileKey) != 0) {

		//tempDataType = new dataType(EventFile::fileKey2Name.getValue(fileKey));		//to avoid undefined behavior, because mutex needs before iterator.
		tempDataType = new dataType(EventFile::fileKey2Name[fileKey]);		//to avoid undefined behavior, because mutex needs before iterator.
		ev->setProperty(BaseEvent::FileName, tempDataType);
	}
	else {
		if (fileObject != 0 && EventFile::fileObject2Name.count(fileObject) != 0) {

			//tempDataType = new dataType(EventFile::fileObject2Name.getValue(fileObject));	//to avoid undefined behavior, because mutexe needs before iterator.
			tempDataType = new dataType(EventFile::fileObject2Name[fileObject]);	//to avoid undefined behavior, because mutexe needs before iterator.
			ev->setProperty(BaseEvent::FileName, tempDataType);
		}
		else {
            // Handles opened before the capture started have no name in the
            // map. Dropping those Read/Write/Rename events loses most file
            // activity, so keep the event and mark the path as unknown.
            ev->setProperty(BaseEvent::FileName, new dataType(std::string("<unknown>")));
        }
	}
}
void EventFile::parse() {

    dataType* dt = getProperty(FileObject);
	ULONG64 fileObject = 1;

	if (dt) {
		fileObject = dt->getULONG64();
	}

    // Missing properties must never dereference a null dataType: a short or
    // drifting schema would otherwise crash the parser (seen as 0xc0000005 at
    // a dataType getter). Empty values simply skip the name-map update.
    auto stringProp = [this](int id) -> std::string {
        dataType* p = getProperty(id);
        return p ? p->getString() : std::string();
    };
    auto u64Prop = [this](int id) -> ULONG64 {
        dataType* p = getProperty(id);
        return p ? p->getULONG64() : 0;
    };

	switch (getEventIdentifier()->getOpCode()) {

	case NOTDEFINEDTYPE1:
	case NOTDEFINEDTYPE2:
		return;
	case RUNDOWN: {
        setTIDAndPID(this);
        removeQuotesFromProperty(FileName);
        {
            std::string name = stringProp(FileName);
            if (!name.empty())
                fileKey2Name[fileObject] = name;
        }
        setValueableEvent(false);
        break;
	}
	case NAME:
	case FILECREATE: {
        setTIDAndPID(this);
        removeQuotesFromProperty(FileName);
		//ReadWriteMap will OverWrite the item if the key is exist.
		//fileKey2Name.insertOverwirte(fileObject, fileName);
        {
            std::string name = stringProp(FileName);
            if (!name.empty())
                fileKey2Name[fileObject] = name;
        }
        break;
	}
	case FILEDELETE_: {
        setTIDAndPID(this);
		fileKey2Name.erase(fileObject);
        break;
	}
	case CREATE: {
		//ReadWriteMap will OverWrite the item if the key is exist.
		//fileObject2Name.insertOverwirte(fileObject, getProperty(OpenPath)->getString());
        removeQuotesFromProperty(OpenPath);
        {
            std::string name = stringProp(OpenPath);
            if (!name.empty())
                fileObject2Name[fileObject] = name;
        }
		break;
	}
	case DIRENUM:
	case NOTIFY: {
        // do nothing in directory enumeration and directory notification events
        removeQuotesFromProperty(FileName);
        {
            std::string fileName = stringProp(FileName);
            ULONG64 fileKey = u64Prop(FileKey);
            if (!fileName.empty()) {
                if (fileKey != 0)
                    fileKey2Name[fileKey] = fileName;
                if (fileObject != 1)
                    fileObject2Name[fileObject] = fileName;
            }
        }
		break;
	}
	case CLEANUP:{
        setFileName(this);
        break;
    }
    case RENAME:
    case DELETE_:
    case READ:
    case WRITE:
        setFileName(this);
        break;
	case CLOSE: {
		ULONG64 fileKey = u64Prop(FileKey);
		setFileName(this);
		fileObject2Name.erase(fileObject);
        if (fileKey != 0)
            fileKey2Name.erase(fileKey);
		break;
	}
	default:
        // Unhandled FileIo opcodes (Flush/QueryInfo/FSControl/OperationEnd)
        // still carry their decoded fields; keep them instead of dropping.
		break;
	}

	if (isValueableEvent()) {

        //set tid and pid according to 'EventThread::threadId2processId'
		dataType* tmp = getProperty(TTID);
		if(tmp){

            ULONG64 threadId = tmp->getULONG64();
			setThreadID(threadId);

			auto it = EventThread::threadId2processId.find(threadId);
			if (it != EventThread::threadId2processId.end() && it->second != -1) {

                int pid = it->second;
				setProcessID(pid);
			}
		}
        //fill parentProcess Information
        fillProcessInfo();
	}
}

//some events need to revise tid(线程id) and pid(进程id), return pid
int BaseEvent::setTIDAndPID(BaseEvent* ev) {

    int processorId = ev->getProcessorID();
    int threadId = EventThread::processorId2threadId[processorId];
    int processId = INIT_PROCESS_ID;

	if (threadId != INIT_THREAD_ID) {
        // Find threadId in the map, if not found, default to INIT_PROCESS_ID
        auto it = EventThread::threadId2processId.find(threadId);
        processId = (it != EventThread::threadId2processId.end()) ? it->second : INIT_PROCESS_ID;

        //if there is no mapping of tid to pid , then call CreateToolhelp32Snapshot to enumerate all pids
		if (processId == INIT_PROCESS_ID) {
			processId = Tools::getProcessIDByTID(threadId);
			EventThread::threadId2processId[threadId] = processId;
		}
	}

	ev->setProcessID(processId);
	ev->setThreadID(threadId);

//    std::cout<<threadId<< " :  "<< processId <<std::endl;

    return processId;
}

void EventThread::parse() {

	int pid, tid;

	switch (getEventIdentifier()->getOpCode())
	{
	case THREADSTART:
	case THREADDCSTART: {

		if (!getProperty(ProcessId) || !getProperty(TThreadId)) {
			setValueableEvent(false);
			break;
		}
		pid = getProperty(ProcessId)->getULONG64();
		tid = getProperty(TThreadId)->getULONG64();

		//threadId2processId.insert(tid, pid);
		threadId2processId[tid] = pid;

		break;
	}
	case THREADEND:
	case THREADDCEND: {

		if (!getProperty(ProcessId) || !getProperty(TThreadId)) {
			setValueableEvent(false);
			break;
		}
		pid = getProperty(ProcessId)->getULONG64();
		tid = getProperty(TThreadId)->getULONG64();

        //assume default id is 0
		threadId2processId[tid] = 0;
		break;
	}
	case CSWITCH: {
        // NewThreadId is absent in some builds / short frames. Never
        // dereference a missing property (0xc0000005 at dataType::getULONG64).
        dataType* newTid = getProperty(NewThreadId);
        if (newTid)
            processorId2threadId[getProcessorID()] = newTid->getULONG64();
		setValueableEvent(false);	// cswitch is scheduling noise
		break;
	}
	default: {
		setValueableEvent(false);
		break;
	}
	}

	if (isValueableEvent()) {

		setProcessID(pid);
		setThreadID(tid);

        fillProcessInfo(); //fill parentProcess and process Information
	}
}

void EventImage::parse() {
    auto* pidField = getProperty(ProcessId);
    auto* base = getProperty(ImageBase);
    auto* size = getProperty(ImageSize);
    auto* filename = getProperty(FileName);
    if (!pidField || !base || !size || !filename) {
        setValueableEvent(false);
        return;
    }

    const auto pid = static_cast<int>(pidField->getULONG64());
    const auto address = base->getULONG64();
    const auto length = size->getULONG64();
    auto path = filename->getString();
    setProcessID(pid);
    if (Filter::secondFilter(this))
        return;
    if (!Initializer::getListenCallStack() && Filter::filterImageFile(path)) {
        setValueableEvent(false);
        return;
    }
    fillProcessInfo();
    if (!Initializer::getListenCallStack())
        return;

    switch (getEventIdentifier()->getOpCode()) {
        case IMAGEUNLOAD: {
            auto process = processID2Modules.find(pid);
            if (process != processID2Modules.end())
                process->second.erase(address);
            break;
        }
        case IMAGELOAD:
        case IMAGEDCSTART: {
            if (!length || length > UINT64_MAX - address)
                break;
            auto& modules = processID2Modules[pid];
            modules.erase(address);
            modules.emplace(address, Module(address, address + length, path));
            break;
        }
    }
}


namespace {
// behaviour scope: keep stacks on lifecycle / create / write / delete / rename /
// connect events, but not on every Read/Write byte or Send/Recv packet.
bool g_behaviorStackScope = true;

bool StackWanted(const GUID& guid, UCHAR opcode) {
    if (!g_behaviorStackScope)
        return true;
    const DWORD provider = guid.Data1;
    // Measured on Windows 11 26200: classic stack walking for FileIO/Registry/
    // TCP events starves ETW itself (etw_lost hundreds of thousands) even at
    // moderate rates. The default scope therefore only stacks process/thread/
    // image lifecycle; --profile diagnostic restores the full set.
    if (provider == FileGuid.Data1 || provider == RegistryGuid.Data1 ||
        provider == TcpIpGuid.Data1 || provider == DiskIoGuid.Data1)
        return false;
    return true;   // process / thread / image
}
} // namespace

void EventCallstack::SetStackScope(bool behaviorScope) {
    g_behaviorStackScope = behaviorScope;
}

#define KELLECT_ADD_STACK(guid, op) \
    do { if (StackWanted(guid, (UCHAR)(op))) \
             callStackEvents[idx++] = { guid, (UCHAR)(op), { 0 } }; } while (0)

//start tracing callstack configuration
ULONG EventCallstack::initCallStackTracing(TRACEHANDLE SessionHandle) {

    int idx = 0;
    CLASSIC_EVENT_ID callStackEvents[100]={};

    if(Filter::listenedEventsProviders.count(ProcessProvider)){
        KELLECT_ADD_STACK(ProcessGuid, 1);   //start
        KELLECT_ADD_STACK(ProcessGuid, 2);   //end
        KELLECT_ADD_STACK(ProcessGuid, 3);   //dcstart
        KELLECT_ADD_STACK(ProcessGuid, 4);   //dcend
    }
    if(Filter::listenedEventsProviders.count(FileProvider)){
        KELLECT_ADD_STACK(FileGuid, 32); //filecreate
        KELLECT_ADD_STACK(FileGuid, 35); //filedelete
        KELLECT_ADD_STACK(FileGuid, 64); //create
        KELLECT_ADD_STACK(FileGuid, 67); //read
        KELLECT_ADD_STACK(FileGuid, 68); //write
        KELLECT_ADD_STACK(FileGuid, 70); //delete
        KELLECT_ADD_STACK(FileGuid, 72); //direnum
        KELLECT_ADD_STACK(FileGuid, 73); //flush
        KELLECT_ADD_STACK(FileGuid, 74); //Query
        KELLECT_ADD_STACK(FileGuid, 75); // control
        KELLECT_ADD_STACK(FileGuid, 71); //Rename
    }
    if(Filter::listenedEventsProviders.count(DiskProvider)){
        KELLECT_ADD_STACK(DiskIoGuid, 11); //write
        KELLECT_ADD_STACK(DiskIoGuid, 10); //read
    }
    if(Filter::listenedEventsProviders.count(ThreadProvider)){
        KELLECT_ADD_STACK(ThreadGuid, 1);    //  start
        KELLECT_ADD_STACK(ThreadGuid, 2);    //  end
        KELLECT_ADD_STACK(ThreadGuid, 3);    //  dcstart
        KELLECT_ADD_STACK(ThreadGuid, 4);    //  dcend
    }
    if(Filter::listenedEventsProviders.count(TcpIpProvider)){
        KELLECT_ADD_STACK(TcpIpGuid, 10);    //TcpIpSendIPV4
        KELLECT_ADD_STACK(TcpIpGuid, 11);    //TcpIpRecvIPV4
        KELLECT_ADD_STACK(TcpIpGuid, 12);    //TcpIpConnectIPV4
        KELLECT_ADD_STACK(TcpIpGuid, 13);    //TcpIpDisconnectIPV4
        KELLECT_ADD_STACK(TcpIpGuid, 14);    //TcpIpRetransmitIPV4
        KELLECT_ADD_STACK(TcpIpGuid, 15);    //TcpIpAcceptIPV4
        KELLECT_ADD_STACK(TcpIpGuid, 16);    //TcpIpReconnectIPV4
        KELLECT_ADD_STACK(TcpIpGuid, 18);    //TcpIpTCPCopyIPV4

        KELLECT_ADD_STACK(TcpIpGuid, 26);    //TcpIpSendIPV6
        KELLECT_ADD_STACK(TcpIpGuid, 27);    //TcpIpRecvIPV6
        KELLECT_ADD_STACK(TcpIpGuid, 28);    //TcpIpConnectIPV6
        KELLECT_ADD_STACK(TcpIpGuid, 29);    //TcpIpDisconnectIPV6
        KELLECT_ADD_STACK(TcpIpGuid, 30);    //TcpIpRetransmitIPV6
        KELLECT_ADD_STACK(TcpIpGuid, 31);    //TcpIpAcceptIPV6
        KELLECT_ADD_STACK(TcpIpGuid, 32);    //TcpIpReconnectIPV6
        KELLECT_ADD_STACK(TcpIpGuid, 34);    //TcpIpTCPCopyIPV6

    }
    if(Filter::listenedEventsProviders.count(ImageProvider)){
        KELLECT_ADD_STACK(ImageLoadGuid, 10);    //imagheload
        KELLECT_ADD_STACK(ImageLoadGuid, 2);    //imageunload
        KELLECT_ADD_STACK(ImageLoadGuid, 3);    //imagedcstart
        KELLECT_ADD_STACK(ImageLoadGuid, 4);    //imagedcend
    }
    if(Filter::listenedEventsProviders.count(RegistryProvider)){
        KELLECT_ADD_STACK(RegistryGuid, 10); //RegistryCreate
        KELLECT_ADD_STACK(RegistryGuid, 11); //RegistryOpen
        KELLECT_ADD_STACK(RegistryGuid, 12); //RegistryDelete
        KELLECT_ADD_STACK(RegistryGuid, 13); //RegistryQuery
        KELLECT_ADD_STACK(RegistryGuid, 14); //RegistrySetValue
        KELLECT_ADD_STACK(RegistryGuid, 15); //RegistryDeleteValue
        KELLECT_ADD_STACK(RegistryGuid, 16); //RegistryQueryValue
        KELLECT_ADD_STACK(RegistryGuid, 17); //RegistryEnumerateKey
        KELLECT_ADD_STACK(RegistryGuid, 22); //RegistryKCBCreate
        KELLECT_ADD_STACK(RegistryGuid, 23); //RegistryKCBDelete
        KELLECT_ADD_STACK(RegistryGuid, 27); //RegistryClose
    }

    if (!idx)
        return ERROR_NOT_SUPPORTED;
    return TraceSetInformation(SessionHandle, TraceStackTracingInfo, callStackEvents,
                               idx * sizeof(callStackEvents[0]));
}

void EventCallstack::parse() {
    fillProcessInfo();
    const auto process = EventImage::processID2Modules.find(getProcessID());
    std::string calls;
    char raw[64];

    auto append = [&](const std::string& text) {
        if (!calls.empty())
            calls += ',';
        calls += text;
    };

    if (process != EventImage::processID2Modules.end()) {
        const auto& modules = process->second;
        for (auto address : stackAddresses) {
            auto next = modules.upper_bound(address);
            if (next == modules.begin()) {
                snprintf(raw, sizeof(raw), "0x%llx",
                         static_cast<unsigned long long>(address));
                append(raw);
                continue;
            }
            const Module& module = std::prev(next)->second;
            if (address >= module.getAddressEnd()) {
                snprintf(raw, sizeof(raw), "0x%llx",
                         static_cast<unsigned long long>(address));
                append(raw);
                continue;
            }

            const auto moduleName = module.getModuleName();
            const ULONG64 rva = address - module.getAddressBegin();
            snprintf(raw, sizeof(raw), "+0x%llx",
                     static_cast<unsigned long long>(rva));

            // Behaviour scope = limited parsing: module + RVA only. No PE
            // export walk, no PDB, and never drop the stack when a symbol is
            // unavailable. diagnostic/full still resolves API names.
            if (g_behaviorStackScope) {
                append(moduleName + raw);
                continue;
            }

            std::unique_lock<std::mutex> lock(EventImage::modulesApiMutex);
            const auto exports = EventImage::modulesName2APIs.find(moduleName);
            if (exports == EventImage::modulesName2APIs.end()) {
                lock.unlock();
                if (g_adaptiveExports && Filter::parsedApiImage.size() < 4096 &&
                    !Filter::parsedApiImage.count(moduleName) &&
                    EventImage::enqueueModuleApis(moduleName))
                    Filter::parsedApiImage.insert(moduleName);
                append(moduleName + raw);
                continue;
            }
            const auto& apis = exports->second;
            MyAPI rvaKey(rva);
            auto after = apis.upper_bound(&rvaKey);
            if (after == apis.begin()) {
                append(moduleName + raw);
                continue;
            }
            append(moduleName + ":" + (*std::prev(after))->getAPIName());
        }
    }

    if (calls.empty()) {
        // Keep the event even if no frame resolved; raw addresses are evidence.
        for (auto address : stackAddresses) {
            snprintf(raw, sizeof(raw), "0x%llx",
                     static_cast<unsigned long long>(address));
            append(raw);
        }
    }
    if (!calls.empty())
        setProperty("stackInfo", new dataType(calls));
}

void  EventUnImportant::parse() {

	setValueableEvent(false);
	//MyLogger::writeLog("EventUnImportant parse successfully!");
}

void  EventProcess::parse() {

	dataType* pidProp = getProperty(ProcessId);
	if (!pidProp)
		return;
	ULONG64 pid = pidProp->getULONG64();
	setProcessID(pid);

	switch (getEventIdentifier()->getOpCode())
	{
	case PROCESSSTART:
	case PROCESSDCSTART: {

        removeQuotesFromProperty(ImageFileName);
		// for both update and add value
		processID2Name[pid] = getProperty(ImageFileName)->getString();

		//family process (GUI/service/another collector) started after this run:
		//blacklist its PID so its later file/registry/... events die at firstFilter,
		//and drop this ProcessStart event itself
		if (Filter::isKellectFamilyImage(processID2Name[pid].c_str())) {
            {
                std::lock_guard<std::mutex> lock(Filter::processIdMutex);
                Filter::filteredProcessID.insert(static_cast<int>(pid));
            }
			setValueableEvent(false);
			break;
		}

		// PID reuse cleanup (plan B): new process with a blacklisted PID but a
		// non-family image — release the stale entry (covers missed PROCESSEND).
		// Guard: permanent entries {0,4,128,self} are never released.
		if (pid != 0 && pid != 4 && pid != 128 &&
            pid != (ULONG64)GetCurrentProcessId()) {
            std::lock_guard<std::mutex> lock(Filter::processIdMutex);
            Filter::filteredProcessID.erase(static_cast<int>(pid));
        }

        if (getEventIdentifier()->getOpCode() == PROCESSSTART)
            EventImage::processID2Modules.erase(static_cast<int>(pid));

		break;
	}
	case PROCESSEND:
	case PROCESSDCEND: {

		// do not erase , for thread safe
		//processID2Name.erase(processID);

		//process end ,clear correlate modules set
        if (getEventIdentifier()->getOpCode() == PROCESSEND)
            EventImage::processID2Modules.erase(static_cast<int>(pid));

		// PID reuse cleanup (plan A): release this PID from the dynamic filter
		// blacklist so a future process reusing the PID isn't silently dropped.
		// Guard: permanent entries {0,4,128,self} are never released.
		if (pid != 0 && pid != 4 && pid != 128 &&
            pid != (ULONG64)GetCurrentProcessId()) {
            std::lock_guard<std::mutex> lock(Filter::processIdMutex);
            Filter::filteredProcessID.erase(static_cast<int>(pid));
        }

		break;
	}
	case PROCESSDEFUNCT: 
	default:
		setValueableEvent(false);
		break;
	}

    replaceCharacterFromProperty(UserSID,'\\',"-");
	if (isValueableEvent()) {

        //change the format of commandLine property.
        removeQuotesFromProperty(CommandLine);
        replaceCharacterFromProperty(CommandLine,'\n'," ");

        //insert the mapping of pid and ppid
		dataType* parentProp = getProperty(ParentId);
		ULONG64 ppid = parentProp ? parentProp->getULONG64() : 0;
        EventProcess::processID2ParentProcessID[pid] = ppid;    //set ppid to each pid
        setParentProcessID(ppid);

		//second filter, filter according to revised processID
		if (!Filter::secondFilter(this)) {

			//std::wstring parentProcessName;
            fillProcessInfo(); //fill parentProcess and process Information
        }
		else {
			setValueableEvent(false);
		}
	}
}

void  EventRegistry::parse() {

    fillProcessInfo(); //fill parentProcess and process Information

    switch (getEventIdentifier()->getOpCode()) {
        case REG_OPEN:
        case REG_CREATE:
        case REG_QUERYVALUE:
        case REG_KCBCREATE:{

            removeQuotesFromProperty(KeyName);
            dataType* nameProp = getProperty(KeyName);
            dataType* handleProp = getProperty(KeyHandle);
            if (!nameProp || !handleProp)
                break;
            std::string keyName = nameProp->getString();
            ULONG64 keyHandle = handleProp->getULONG64();
            keyHandle2KeyName.insertOverwirte(keyHandle,keyName);
            break;
        }
        case REG_KCBRUNDOWNBEGIN:{
            // Session-start registry-state dump: feeds the keyHandle->name map.
            removeQuotesFromProperty(KeyName);
            dataType* nameProp = getProperty(KeyName);
            dataType* handleProp = getProperty(KeyHandle);
            if (nameProp && handleProp)
                keyHandle2KeyName.insertOverwirte(handleProp->getULONG64(),
                                                  nameProp->getString());
            setValueableEvent(false);
            break;
        }
        case REG_KCBRUNDOWNEND:{
            setValueableEvent(false);
            break;
        }
        default:{
            auto d = getProperty(KeyHandle);

            if(d){
                ULONG64 keyHandle = d->getULONG64();
    //            auto item = keyHandle2KeyName.find(keyHandle);
                auto keyName = keyHandle2KeyName.getValue(keyHandle);

                if(keyName.size()>0){
                    delete getProperty(KeyName);
                    setProperty(KeyName,new dataType(keyName));
                }
            }
        }
    }
}

void  EventDisk::parse() {


    switch (getEventIdentifier()->getOpCode()) {
        case DISKFLUSHBUFFERS:
        case DISKWRITE:
        case DISKREAD: {

//            setTIDAndPID(this);
//            Filter::secondFilter(this);
            auto d = getProperty(IssuingThreadId);
            if (d != nullptr) {

                int issuingThreadId = d->getULONG64();
                int processId = INIT_PROCESS_ID;
                
                // Find issuingThreadId in the map, if not found, default to INIT_PROCESS_ID
                auto it = EventThread::threadId2processId.find(issuingThreadId);
                if (it != EventThread::threadId2processId.end()) {
                    processId = it->second;
                }

                if (processId == INIT_PROCESS_ID) {
                    processId = Tools::getProcessIDByTID(issuingThreadId);
                    EventThread::threadId2processId[issuingThreadId] = processId;
//                  std::cout<<"issuingThread:"<<issuingThreadId<<"   ,processId:" << processId<<std::endl;
                }
                setThreadID(issuingThreadId);
                setProcessID(processId);

                EventThread::threadId2processId[issuingThreadId] = processId;
            }
        }
    }

    fillProcessInfo(); //fill parentProcess and process Information
}

void  EventPerfInfo::parse() {
	
	//int a = 0;
	
	setTIDAndPID(this);

    fillProcessInfo(); //fill parentProcess and process Information
	//std::cout << Tools::DecInt2HexStr(getProperty(BaseEvent::SysCallAddress).getULONG64());
	if (ei->getOpCode() == 51) {
		dataType* sysProp = getProperty(SysCallAddress);
		if (!sysProp)
			return;
		ULONG64 sysCallAddress = sysProp->getULONG64();
		std::string* sysCallName = nullptr;
		std::map<ULONG64, std::string*>::iterator it = systemCallMapUsed.find(sysCallAddress);

		if (it == systemCallMapUsed.end()) {

			it = systemCallMap.find(sysCallAddress);
			if (it == systemCallMap.end()) {
				setValueableEvent(false);
			}
			else {
				sysCallName = it->second;
				systemCallMapUsed.insert(std::map<ULONG64, std::string*>::value_type(it->first, sysCallName));
				systemCallMap.erase(it);
				//addr2FuncNameUsed.insert(it);
			}

		}
		else
			sysCallName = it->second;
	
		setSysCallName(sysCallName);
	}
}
void EventUSer::parse() {
    fillProcessInfo();
}
void  EventTCPIP::parse() {

	int pid;
	switch (this->getEventIdentifier()->getOpCode()) {
        case TCPIPFAILED:
            break;
        case SENDIPV4:
        case RECVIPV4:
        case DISCONNECTIPV4:
        case RETRANSMITIPV4:
        case RECONNECTIPV4:
        case TCPCOPYIPV4:
        case CONNECTIPV4:
        case ACCEPTIPV4: {

            dataType* dAddr = getProperty(daddr);
            dataType* sAddr = getProperty(saddr);
            if(dAddr&&sAddr){

                ULONG64 lSAddr =  sAddr->getULONG64();
                ULONG64 lDAddr =  dAddr->getULONG64();

                delete sAddr;
                delete dAddr;

                setProperty(daddr,new dataType(transferULONG2IPAddr(lDAddr)));
                setProperty(saddr,new dataType(transferULONG2IPAddr(lSAddr)));
            }
        }
        default:
            {
                dataType* pidProp = getProperty(PID);
                if (!pidProp)
                    break;
                pid = pidProp->getULONG64();
            }
            setProcessID(pid);
            break;
    }

	//second filter, filter according to revise processID
	if (Filter::secondFilter(this)) {
		
		setValueableEvent(false);
		return;
	}

	fillProcessInfo();
}
std::string getNewGuid() {
    GUID guid;
    char tempUUID[1024];
    std::string buf;
    HRESULT res = CoCreateGuid(&guid);
    if (res == S_OK) {
        sprintf(tempUUID, "%08X-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X", guid.Data1, guid.Data2, guid.Data3,
                guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6],
                guid.Data4[7]);
        buf = std::string(tempUUID);
    }
    return buf;
}

json Getargs(BaseEvent* event){
    nlohmann::json argsObject1;
    for (auto pty : event->getProperties()) {
        if (pty.second) {
            if (pty.second->getIsString()) {
                std::string argValue = pty.second->getString();
                argsObject1[pty.first] = argValue;

            } else {

                argsObject1[pty.first] = pty.second->getULONG64();
            }
        }
    }
    for (auto pty : event->getProperties()) {
        delete pty.second;
    }
    return argsObject1;
}


json Entity_Declare(BaseEvent* event,std::string eventname){
    std::string uuid=getNewGuid();
    json j;
    nlohmann::json entityObject;
    nlohmann::json dataObject;
//    std::cout<<"test ThreadStart1"<<std::endl;
//    nlohmann::json argsObject= Getargs(event);
//


 // delete properties
    if(eventname=="process"){
        nlohmann::json subjectObject;
        subjectObject["uuid"]=uuid;
        subjectObject["Type"] = "SUBJECT_PROCESS";
        subjectObject["PID"] = event->getProcessID();
        subjectObject["PName"] = event->getProcessName();
        subjectObject["NodeType"] = "process";
        subjectObject["ParentSubject"] ;
        subjectObject["TimeStamp"] = event->getTimeStamp();
        dataObject["Subject"] = subjectObject;
        dataObject["args"]=argsObject;
        dataObject["weights"]=1;
        entityObject["data"]=dataObject;
        //额外数据格式，用到再删除注解
        /*
        entityObject["WDMVersion"]="1.0";
        entityObject["source"]="";
        entityObject["@type"]="com.tags.Process";*/

    }else if(eventname=="thread"){
        nlohmann::json subjectObject;
        subjectObject["uuid"]=uuid;
        subjectObject["Type"] = "SUBJECT_PROCESS";
        subjectObject["TID"] = event->getThreadID();
        subjectObject["NodeType"] = "thread";
        subjectObject["ParentSubject"] ;
        subjectObject["TimeStamp"] = event->getTimeStamp();
        dataObject["Subject"] = subjectObject;
        dataObject["args"]=argsObject;
        dataObject["weights"]=1;
        entityObject["data"]=dataObject;
        //额外数据格式，用到再删除注解
        /*
        entityObject["WDMVersion"]="1.0";
        entityObject["source"]="";
        entityObject["@type"]="com.tags.Process";*/
    }
    else if(eventname=="file"){
        nlohmann::json ObjectObject;
        ObjectObject["uuid"]=uuid;
        ObjectObject["Type"] = "FILE_OBJECT_FILE";
        ObjectObject["Path"] ;
        ObjectObject["NodeType"] = "file";
        ObjectObject["TimeStamp"] = event->getTimeStamp();
        dataObject["Object"] = ObjectObject;
        dataObject["args"]=argsObject;
        dataObject["weights"]=1;
        entityObject["data"]=dataObject;
        //额外数据格式，用到再删除注解
        /*
        entityObject["WDMVersion"]="1.0";
        entityObject["source"]="";
        entityObject["@type"]="com.tags.File";*/
    }
    else if(eventname=="registry"){
        nlohmann::json ObjectObject;
        ObjectObject["uuid"]=uuid;
        ObjectObject["Type"] = "FILE_OBJECT_FILE";
        ObjectObject["Path"]=argsObject["KeyName"];
        ObjectObject["NodeType"] = "register";
        ObjectObject["TimeStamp"] = event->getTimeStamp();
        dataObject["Object"] = ObjectObject;
        dataObject["args"]=argsObject;
        dataObject["weights"]=1;
        entityObject["data"]=dataObject;
        //额外数据格式，用到再删除注解
        /*
        entityObject["WDMVersion"]="1.0";
        entityObject["source"]="";
        entityObject["@type"]="com.tags.File";*/
    }
    else if(eventname=="socket"){
        nlohmann::json ObjectObject;
        ObjectObject["uuid"]=uuid;
        ObjectObject["Type"] = "FILE_OBJECT_UNIX_SOCKET";
        ObjectObject["NodeType"] = "socket";
        ObjectObject["saddr"]=argsObject["saddr"];
        ObjectObject["sport"]=argsObject["sport"];
        ObjectObject["daddr"]=argsObject["daddr"];
        ObjectObject["dport"]=argsObject["dport"];
        ObjectObject["TimeStamp"] = event->getTimeStamp();
        dataObject["Object"] = ObjectObject;
        dataObject["args"]=argsObject;
        dataObject["weights"]=1;
        entityObject["data"]=dataObject;
        //额外数据格式，用到再删除注解
        /*
        entityObject["WDMVersion"]="1.0";
        entityObject["source"]="";
        entityObject["@type"]="com.tags.Socket";*/
    }
    return entityObject;
}
json Event_Declare(BaseEvent* event){
    std::string uuid=getNewGuid();
    nlohmann::json entityObject;
    nlohmann::json eventObject;
    nlohmann::json dataObject;
    argsObject= Getargs(event);
    eventObject["uuid"]=uuid;
    eventObject["Type"] ;
    eventObject["subject"];
    eventObject["object"];
    eventObject["object2"];
    eventObject["CommandLine"] ;
    eventObject["TimeStamp"] = event->getTimeStamp();
    dataObject["Event"] = eventObject;
    dataObject["args"]=argsObject;
    dataObject["weights"]=1;
    entityObject["data"]=dataObject;
    //额外数据格式，用到再删除注解
    /*
entityObject["WDMVersion"]="1.0";

entityObject["source"]="";
entityObject["@type"]="com.tags.Event";*/
return entityObject;
}
STATUS getCommonJsonNoLib(BaseEvent* event, std::string* sJson) {
    if (!event || sJson == nullptr) return STATUS_FAIL;

    // Append-only serialisation: no temporary std::string per field
    // (std::to_string / jsonEscape used to allocate several times per event).
    sJson->reserve(sJson->size() + 256);

    sJson->append("{\"Event\":\"");
    Tools::appendJsonEscaped(*sJson, event->getEventIdentifier()->getEventName());

    sJson->append("\",\"PID\":");
    Tools::appendInt(*sJson, event->getProcessID());

    sJson->append(",\"PName\":\"");
    Tools::appendJsonEscaped(*sJson, event->getProcessName());

    sJson->append("\",\"PPID\":");
    Tools::appendInt(*sJson, event->getParentProcessID());

    sJson->append(",\"PPName\":\"");
    Tools::appendJsonEscaped(*sJson, event->getParentProcessName());

    sJson->append("\",\"TID\":");
    Tools::appendInt(*sJson, event->getThreadID());

    sJson->append(",\"TimeStamp\":");
    Tools::appendUnsigned(*sJson, static_cast<unsigned long long>(event->getTimeStamp()));

    sJson->append(",\"Host-UUID\":\"");
    Tools::appendJsonEscaped(*sJson, Initializer::getUUID());

    sJson->push_back('"');
    if (event->getRawSequence()) {
        sJson->append(",\"raw_ref\":{\"run_id\":\"");
        sJson->append(kellect::evidence::RunId());
        sJson->append("\",\"source\":\"kernel_etw\",\"raw_seq\":");
        Tools::appendUnsigned(*sJson, event->getRawSequence());
        sJson->push_back('}');
    }
    sJson->append(",\"args\":{");

    bool first = true;
    for (auto& pty : event->getProperties()) {
        if (pty.second == nullptr) continue;

        if (!first) sJson->push_back(',');
        first = false;

        sJson->push_back('"');
        sJson->append(pty.first);
        sJson->append("\":");

        if (pty.second->getIsString()) {
            sJson->push_back('"');
            Tools::appendJsonEscaped(*sJson, pty.second->getString());
            sJson->push_back('"');
        }
        else {
            Tools::appendUnsigned(*sJson,
                                  static_cast<unsigned long long>(pty.second->getULONG64()));
        }

        delete pty.second;   // the event owns its property values
    }

    sJson->append("}}");
    event->setPropertiesDeleted(true);   // values freed above
    return STATUS_SUCCESS;
}

STATUS TranstoWdm(BaseEvent* event, std::string* sJson){
if (!event||!sJson){
    return STATUS_FAIL;
}
std::string eventName = event->getEventIdentifier()->getEventName().c_str();
std::string pKey= event->getProcessName() + std::to_string(event->getProcessID());
//    nlohmann::json argsObject= wdmEvent["data"]["args"];
auto it = std::find(ignoreEvent.begin(), ignoreEvent.end(), eventName);

if(eventName.find("DiskIO")==0){
    return STATUS_FAIL;
}
if(it!=ignoreEvent.end()){
    return  STATUS_FAIL;
}

if (eventType.count(eventName)==0){
//        noEventList.insert(eventName);
    return  STATUS_FAIL;
}
json wdmEvent=Event_Declare(event);
if(eventName.find("Registry")==0){
    auto it = std::find(registryEntity.begin(), registryEntity.end(), eventName);
    if (it != registryEntity.end()){
        if(processList.count(pKey)==0){
            json entityObject=Entity_Declare(event,"process");
            processList[pKey]=entityObject["data"]["Subject"]["uuid"];
            entityObject["data"]["Subject"]["ParentSubject"]=processList.at(pKey);
            sJson->append(entityObject.dump());
            sJson->append("\n");
        }
        if(argsObject.contains("KeyName")) {
            if (registryList.count(argsObject["KeyName"]) == 0) {
                json entityObject = Entity_Declare(event, "registry");
                registryList[argsObject["KeyName"]] = entityObject["data"]["Object"]["uuid"];
                sJson->append(entityObject.dump());
                sJson->append("\n");
            }
        }
    }
//    if(argsObject["keyName"]!=NULL&&registryList.count(argsObject["keyName"])==0){
//            std::cout<<"Registry 8 "<<std::endl;
//            std::cout<<"come in"<<std::endl;
//            return STATUS_FAIL;
//        }
    if ((processList.count(pKey) == 0 || registryList.count(argsObject["KeyName"]) == 0)) {
        // 键不存在，进行相应处理
        return STATUS_FAIL;
    }
    wdmEvent["data"]["Event"]["subject"]=processList[pKey];
    wdmEvent["data"]["Event"]["object"]=registryList.at(argsObject["KeyName"]);
    wdmEvent["data"]["Event"]["Type"]=eventType[eventName];
    sJson->append(wdmEvent.dump());
    sJson->append("\n");
}
else if(eventName.find("Process")==0){
    std::string ppKey=event->getParentProcessName()+std::to_string(event->getParentProcessID());
    if(processList.count(ppKey)==0){
        nlohmann::json entityObject;
        nlohmann::json dataObject;
        nlohmann::json subjectObject;
        subjectObject["uuid"]=getNewGuid();
        subjectObject["Type"]="SUBJECT_PROCESS";
        subjectObject["PID"]=event->getProcessID();
        subjectObject["PName"]=event->getProcessName();
        subjectObject["NodeType"]="process";
        subjectObject["ParentSubject"];
        subjectObject["TimeStamp"]=std::to_string(event->getTimeStamp());
        dataObject["Subject"]=subjectObject;
        dataObject["args"]=argsObject;
        dataObject["weights"]=1;
        entityObject["data"]=dataObject;
        entityObject["WDMVersion"]="1.0";
        entityObject["source"]="";
//            processList.insert(std::map<std::string,std::string>::value_type(ppKey,subjectObject["uuid"]));
        processList[ppKey]=subjectObject["uuid"];
        sJson->append(entityObject.dump());
        sJson->append("\n");
    }
    if(processList.count(pKey)==0){
        json entityObject=Entity_Declare(event,"process");
//            processList.insert(std::map<std::string,std::string>::value_type(pKey,entityObject["data"]["Subject"]["uuid"]));
        processList[pKey]=entityObject["data"]["Subject"]["uuid"];
        entityObject["data"]["Subject"]["ParentSubject"]=processList.at(ppKey);
        sJson->append(entityObject.dump());
        sJson->append("\n");
    }

    wdmEvent["data"]["Event"]["subject"] = processList.at(ppKey);
    wdmEvent["data"]["Event"]["object"] = processList.at(pKey);
    wdmEvent["data"]["Event"]["Type"] = eventType[eventName];
    wdmEvent["data"]["Event"]["CommandLine"] = argsObject["CommandLine"];
    std::cout<<" Process out"<<std::endl;
    sJson->append(wdmEvent.dump());
}
else if(eventName.find("ThreadStart")==0){
    if(processList.count(pKey)==0){
        json entityObject=Entity_Declare(event,"process");

//            processList.insert(std::map<std::string,std::string>::value_type(pKey,entityObject["data"]["Subject"]["uuid"]));
        processList[pKey]=entityObject["data"]["Subject"]["uuid"];
        entityObject["data"]["Subject"]["ParentSubject"]=processList.at(pKey);
       sJson->append(entityObject.dump());
       sJson->append("\n");
    }
    json entityObject=Entity_Declare(event,"thread");
    entityObject["data"]["Subject"]["ParentSubject"]=processList.at(pKey);
    sJson->append(entityObject.dump());
    sJson->append("\n");
    wdmEvent["data"]["Event"]["subject"] = processList.at(pKey);
    wdmEvent["data"]["Event"]["object"] = processList.at(pKey);
    wdmEvent["data"]["Event"]["Type"] = eventType[eventName];
    sJson->append(wdmEvent.dump());

}
else if(eventName.find("FileIO")==0){
    auto it = std::find(fileEntity.begin(), fileEntity.end(), eventName);
    if (it != fileEntity.end()){
        if(processList.count(pKey)==0){
            json entityObject=Entity_Declare(event,"process");
//                processList.insert(std::map<std::string,std::string>::value_type(pKey,entityObject["data"]["Subject"]["uuid"]));
            processList[pKey]=entityObject["data"]["Subject"]["uuid"];
            entityObject["data"]["Subject"]["ParentSubject"]=processList.at(pKey);
            sJson->append(entityObject.dump());
            sJson->append("\n");
        }
        if(argsObject.contains("FileName")&&fileList.count(argsObject["FileName"])==0){
            json entityObject=Entity_Declare(event,"file");
            fileList[argsObject["FileName"]]=entityObject["data"]["Object"]["uuid"];
//                entityObject["data"]["Object"]["Path"] = argsObject["FileName"];
            entityObject["data"]["Object"]["Path"] =argsObject["FileName"];
           std:: string length=argsObject["FileName"];
            sJson->append(entityObject.dump());
            sJson->append("\n");
        }
        else if(argsObject.contains("OpenPath")&&fileList.count(argsObject["OpenPath"])==0){
            json entityObject=Entity_Declare(event,"file");
            fileList[argsObject["OpenPath"]]=entityObject["data"]["Object"]["uuid"];
            entityObject["data"]["Object"]["Path"]=argsObject["OpenPath"];
            sJson->append(entityObject.dump());
            sJson->append("\n");
        }
    }
   if(argsObject.contains("FileName")&&fileList.count(argsObject["FileName"])==0){
       return STATUS_FAIL;
  }
    if(argsObject.contains("OpenPath")&&fileList.count(argsObject["FileName"])==0){

       return STATUS_FAIL;
   }
    wdmEvent["data"]["Event"]["subject"]=processList[pKey];
    if(argsObject.contains("FileName")){
        wdmEvent["data"]["Event"]["object"]=fileList[argsObject["FileName"]];
    }else if(argsObject.contains("OpenPath")){
        wdmEvent["data"]["Event"]["object"] = fileList[argsObject["OpenPath"]];
    }
    wdmEvent["data"]["Event"]["Type"] = eventType[eventName];
    sJson->append(wdmEvent.dump());
    sJson->append("\n");
}
else if(eventName.find("Tcp")==0){
    if(processList.count(pKey)==0){
        json entityObject=Entity_Declare(event,"process");
        processList[pKey]=entityObject["data"]["Subject"]["uuid"];
        entityObject["data"]["Subject"]["ParentSubject"]=processList[pKey];
        sJson->append(entityObject.dump());
        sJson->append("\n");
    }
    std::stringstream ss;
    std::string daddr_str = argsObject["daddr"];
    std::string saddr_str = argsObject["saddr"];
    ss << argsObject["dport"];
    std::string dport_str = ss.str();
    ss.str("");
    ss << argsObject["sport"];
    std::string sport_str = ss.str();
    ss.str("");
    std::string socket = daddr_str + ":" + dport_str + " => " + saddr_str + ":" + sport_str;
    ss.str("");
    if(socketList.count(socket)==0){
        json entityObject=Entity_Declare(event,"socket");
        socketList[socket]=entityObject["data"]["Object"]["uuid"];
        sJson->append(entityObject.dump());
        sJson->append("\n");
    }
    wdmEvent["data"]["Event"]["subject"] = processList.at(pKey);
    wdmEvent["data"]["Event"]["object"] = socketList[socket];
    wdmEvent["data"]["Event"]["Type"] = eventType[eventName];

    sJson->append(wdmEvent.dump());
}
else{
    return STATUS_FAIL;
}
return STATUS_SUCCESS;
}

//parse jsonString


STATUS BaseEvent::toJsonString(std::string* sJson) {

return getCommonJsonNoLib(this, sJson);
}

STATUS BaseEvent::toWdmJsonString(std::string* sJson) {
STATUS status = TranstoWdm(this, sJson);

this->setPropertiesDeleted(true);
return status;
}
