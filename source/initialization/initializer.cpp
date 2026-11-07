

#include "initialization/initializer.h"
#include "process/event_parse.h"
#include "process/etw_config.h"
#include "tools/tools.h"
#include "tools/logger.h"
#include <regex>
#include <sstream>
#include <memory>
#include <TlHelp32.h>
#include "nlohmann/json.hpp"
#include "filter.h"
#include "tools/providerInfo.h"
#include "tools/tinyxml2.h"
#include "schema/schema.h"
#include "channel/probe_channel.h"
#include "output/tee_output.h"
#include "secargus/config.h"
#include "secargus/mqtt_output.h"
#include "secargus/util.h"
#include "runtime/collector.h"
#include <thread>

namespace {

// Starting an ETW session (kernel logger or a private session) requires
// SeSystemProfilePrivilege / an elevated token. Failing later with a bare
// "StartTrace failed with 5" is unhelpful, so check up front.
bool IsProcessElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;

    TOKEN_ELEVATION elevation;
    ZeroMemory(&elevation, sizeof(elevation));
    DWORD returned = 0;
    const BOOL ok = GetTokenInformation(token, TokenElevation, &elevation,
                                        sizeof(elevation), &returned);
    CloseHandle(token);
    return ok != FALSE && elevation.TokenIsElevated != 0;
}

} // namespace

INITIALIZE_EASYLOGGINGPP
using namespace std;
using namespace tinyxml2;

//use to classify events by providerID and opcodes.
std::map<EventIdentifier*, std::list<BaseEvent::PropertyInfo>, EventIdentifierSortCriterion>  BaseEvent::eventStructMap;

std::set<EventIdentifier*, EventIdentifierSortCriterion> Filter::filteredEventIdentifiers;
std::set<EventIdentifier*, EventIdentifierSortCriterion> Filter::droppedEventIdentifiers;
std::set<int> Filter::filteredProcessID;
std::mutex Filter::processIdMutex;
std::set<std::string> Filter::filteredImageFile;
std::set<std::string> Filter::parsedApiImage;
std::set<std::string> Initializer::userDroppedEventNames;
std::set<ULONG64> Filter::listenedEventsProviders;
bool Filter::listenAllEvents(false);
bool Initializer::listenCallStack(false);
int Initializer::statsInterval = 0;
bool Initializer::adaptiveEnabled = true;
std::map <std::string, std::set<MyAPI*, MyAPISortCriterion> > EventImage::modulesName2APIs;
ThreadPool* EventParser::parsePools;
ThreadPool* EventParser::serializePool;
int EventThread::processorId2threadId[MAX_PROCESSOR_NUM];
std::map<ULONG64, int> EventThread::threadId2processId;

STATUS Initializer::initEnabledEvent(ULONG64 eventType) {

    if(!enbaleFlagsInited ) return STATUS_SUCCESS;

    enabledFlags = EVENT_TRACE_FLAG_PROCESS;   // thread family is opt-in (--enable-thread-events)
    //callstack initialize in
    if (eventType & CALLSTACKEVENT){
        setListenCallStack(true);   // set listenCallStack true;
        enabledFlags |= EVENT_TRACE_FLAG_IMAGE_LOAD;
        Filter::listenedEventsProviders.insert(CallStackGuid.Data1);
    }
    if (eventType & PROCESSEVENT){
        enabledFlags |= EVENT_TRACE_FLAG_PROCESS;
        Filter::listenedEventsProviders.insert(ProcessGuid.Data1);
    }
    if (eventType & THREADEVENT){
        enabledFlags |= EVENT_TRACE_FLAG_THREAD;
        Filter::listenedEventsProviders.insert(ThreadGuid.Data1);
    }
    if (eventType & REGISTEREVENT){
        enabledFlags |= EVENT_TRACE_FLAG_REGISTRY;
        Filter::listenedEventsProviders.insert(RegistryGuid.Data1);
    }
    if (eventType & FILEEVENT){

        //DISK_FILE_IO "requires disk IO"(evntrace.h): without DISK_IO the kernel
        //emits no FileIo_Name-family events(opcodes 0/36), so fileKey2Name only
        //covers files opened during the capture and most Read/Write events fail
        //setFileName() and get dropped. DISK_IO is therefore enabled here too;
        //DiskIo's own events stay out of the output because DiskIoGuid is not
        //in listenedEventsProviders under a FILE-only mask (thirdFilter drops them).
        // DISK_FILE_IO is what makes the FileIo_Name family available; DISK_IO
        // is required for that mapping. DISK_IO_INIT is *not* needed and its
        // Init/Complete records are pure overhead for behaviour collection.
        enabledFlags |= EVENT_TRACE_FLAG_FILE_IO_INIT | EVENT_TRACE_FLAG_DISK_FILE_IO |
                        EVENT_TRACE_FLAG_FILE_IO | EVENT_TRACE_FLAG_DISK_IO;
        // No EVENT_TRACE_FLAG_CSWITCH: it emits a PerfInfo CSwitch event for
        // every context switch, which Kellect does not decode (unknown
        // provider) and which floods the kernel buffers - that showed up as
        // etw_lost on busy systems. Stacks do not need it either.
        Filter::listenedEventsProviders.insert(FileGuid.Data1);
    }
    if (eventType & DISKEVENT){
        enabledFlags |= EVENT_TRACE_FLAG_DISK_IO | EVENT_TRACE_FLAG_DISK_IO_INIT;
        Filter::listenedEventsProviders.insert(DiskIoGuid.Data1);
    }
//    if (eventType & SYSTEMCALLEVENT){
//        enabledFlags |= EVENT_TRACE_FLAG_SYSTEMCALL;
//        Filter::listenedEventsProviders.insert(SystemCallGuid.Data1);
//    }
    if (eventType & IMAGEEVENT){
        enabledFlags |= EVENT_TRACE_FLAG_IMAGE_LOAD;
        Filter::listenedEventsProviders.insert(ImageLoadGuid.Data1);
    }
    if (eventType & TCPIPEVENT){
        enabledFlags |= EVENT_TRACE_FLAG_NETWORK_TCPIP;
        // CSWITCH intentionally off here as well (see the FILE block above).
        Filter::listenedEventsProviders.insert(TcpIpGuid.Data1);
    }

    if(Filter::listenedEventsProviders.size() >= 7) Filter::listenAllEvents=true;

    return STATUS_SUCCESS;
}
/*
    initialize kernel provider trace event types.
*/
inline void Initializer::initDefaultEnabledEvents() {

    Filter::listenAllEvents=true;
    // Callstack is opt-in (--callstack): by default only kernel events are
    // collected, which keeps the volume and CPU cost down.
    setListenCallStack(callstackRequested);
    userEnabledFlags = 0xab;   // behaviour: no Thread/Image rundown by default
    if (!callstackRequested)
        userEnabledFlags &= ~CALLSTACKEVENT;
}

/*
    initialize tracing filter:
    - static PID blacklist (built-in + config/filter.txt)
    - dropped event names (config/filter.txt + CLI -x), resolved to identifiers
    - image file blacklist (config/filter.txt)
    The former hardcoded ~80-pair event whitelist is disabled below; unknown
    event types are now handled by thirdFilter's provider-level check.
*/
void Initializer::applyDesiredConfig() {
    std::ifstream in("config\\remote\\desired.json");
    if (!in.is_open())
        return;

    nlohmann::json doc;
    try {
        in >> doc;
    } catch (const std::exception&) {
        std::cerr << "Warning: config\\remote\\desired.json is not valid JSON; ignored"
                  << std::endl;
        return;
    }
    if (!doc.is_object())
        return;

    if (doc.contains("event_mask") && doc["event_mask"].is_number_integer()) {
        const long long mask = doc["event_mask"].get<long long>();
        if (mask >= 0 && mask <= 0x3ff) {
            userEnabledFlags = static_cast<ULONG64>(mask);
            enbaleFlagsInited = true;   // keep the default path from overwriting it
            std::cout << "remote desired config: event mask = 0x" << std::hex << mask
                      << std::dec << " (" << doc.value("desired_version", std::string("?"))
                      << ")" << std::endl;
        } else {
            std::cerr << "Warning: desired.json event_mask out of range; ignored" << std::endl;
        }
    }
}

void Initializer::initFilter() {    // --- built-in PID blacklist (always present, cannot be removed via config) ---
    Filter::filteredProcessID.insert(0);
    Filter::filteredProcessID.insert(4);
    Filter::filteredProcessID.insert(128);
    Filter::filteredProcessID.insert(GetCurrentProcessId());

    //blacklist the whole kellect toolchain (GUI host / any sibling collector):
    //the session-start process dump would otherwise surface our own processes'
    //events in the stream
    {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W entry;
            entry.dwSize = sizeof(entry);
            if (Process32FirstW(snapshot, &entry)) {
                do {
                    if (Filter::isKellectFamilyImage(entry.szExeFile))
                        Filter::filteredProcessID.insert(static_cast<int>(entry.th32ProcessID));
                } while (Process32NextW(snapshot, &entry));
            }
            CloseHandle(snapshot);
        }
    }

    // --- read config/filter.txt for user-configurable entries ---
    //  sections: filteredProcessID / droppedEventName / filteredImageFile
    //  missing file or parse failure falls back to the defaults above
    {
        std::ifstream f(filterFileName);
        if (f.is_open()) {
            std::string section, line;
            int lineNo = 0;
            bool warnedOldFormat = false;

            while (std::getline(f, line)) {
                ++lineNo;
                size_t b = line.find_first_not_of(" \t\r\n");
                if (b == std::string::npos) continue;
                size_t e = line.find_last_not_of(" \t\r\n");
                line = line.substr(b, e - b + 1);
                if (line.empty() || line[0] == '#') continue;

                // Only the known section names switch sections; everything else
                // is a value for the current one (event names such as
                // "FileIODirNotify" are bare identifiers too).
                if (line == "filteredProcessID" || line == "droppedEventName" ||
                    line == "filteredImageFile" || line == "parsedApiImage") {
                    section = line;
                    continue;
                }
                if (line == "filteredEventIdentifier") {
                    // v1 release format: an 80-pair (provider, opcode) whitelist
                    // the current pipeline no longer uses. Skipping the section
                    // (instead of feeding "3740466758 32" to std::stoi, which
                    // throws std::out_of_range) is what keeps an old
                    // release/config/filter.txt from crashing startup.
                    if (!warnedOldFormat) {
                        std::cerr << "Warning: " << filterFileName
                                  << " contains the deprecated 'filteredEventIdentifier' section;"
                                     " it is ignored (use 'droppedEventName')." << std::endl;
                        warnedOldFormat = true;
                    }
                    section = "ignored";
                    continue;
                }

                if (section == "filteredProcessID") {
                    // accept "0 4 128" as well as one PID per line
                    std::istringstream pids(line);
                    std::string token;
                    while (pids >> token) {
                        try {
                            int pid = std::stoi(token);
                            if (pid >= 0) Filter::filteredProcessID.insert(pid);
                        } catch (const std::exception&) {
                            std::cerr << "Warning: " << filterFileName << ":" << lineNo
                                      << " invalid PID '" << token << "' (ignored)" << std::endl;
                        }
                    }
                } else if (section == "droppedEventName") {
                    userDroppedEventNames.insert(line);
                } else if (section == "filteredImageFile") {
                    Filter::filteredImageFile.insert(line);
                } else if (section == "parsedApiImage") {
                    Filter::parsedApiImage.insert(line);
                }
            }
        } else {
            std::cerr << "Warning: could not open " << filterFileName
                      << "; using built-in defaults." << std::endl;
        }
    }

    // --- resolve dropped event names (from -x CLI and filter.txt) to identifiers ---
    // requires eventStruct loaded (initEventPropertiesMap runs before initFilter)
    if (!userDroppedEventNames.empty()) {
        for (EventIdentifier* ei : BaseEvent::eventIdentifierSet) {
            if (userDroppedEventNames.count(ei->getEventName())) {
                Filter::droppedEventIdentifiers.insert(
                    new EventIdentifier(ei->getProviderID(), ei->getOpCode()));
            }
        }
    }

    // === Former hardcoded event identifier whitelist (~80 pairs), disabled ===
    // These correspond 1:1 to the event types defined in eventStruct xml.
    // The whitelist check (filterEventIdentifier) has been removed from
    // firstFilter; unknown event types are now handled by thirdFilter's
    // provider-level check. Preserved below as reference for provider/opcode
    // values in case the whitelist needs to be restored.
    //
    // std::vector<std::pair<ULONG64, int>> filteredEventIdentifiers = {
    //         {3740466758, 32}, {1030727888, 1}, {1030727888, 2}, {1030727889, 1},
    //         {1030727889, 2}, {1030727889, 36}, {2924704302, 10}, {2924704302, 11},
    //         {2924704302, 12}, {2924704302, 13}, {2924704302, 14}, {2924704302, 15},
    //         {2924704302, 16}, {2924704302, 17}, {2924704302, 18}, {2924704302, 19},
    //         {2924704302, 20}, {2924704302, 21}, {2924704302, 22}, {2924704302, 23},
    //         {2924704302, 24}, {2924704302, 25}, {2924704302, 26}, {2924704302, 27},
    //         {2586315456, 10}, {2586315456, 26}, {2586315456, 11}, {2586315456, 13},
    //         {2586315456, 14}, {2586315456, 16}, {2586315456, 18}, {2586315456, 27},
    //         {2586315456, 29}, {2586315456, 30}, {2586315456, 32}, {2586315456, 34},
    //         {2586315456, 12}, {2586315456, 15}, {2586315456, 28}, {2586315456, 31},
    //         {2586315456, 17}, {2429279289, 64}, {2429279289, 72}, {2429279289, 77},
    //         {2429279289, 69}, {2429279289, 70}, {2429279289, 71}, {2429279289, 74},
    //         {2429279289, 75}, {2429279289, 0}, {2429279289, 32}, {2429279289, 35},
    //         {2429279289, 36}, {2429279289, 67}, {2429279289, 68}, {2429279289, 65},
    //         {2429279289, 66}, {2429279289, 73}, {1030727892, 11}, {1030727892, 10},
    //         {1030727892, 12}, {1030727892, 13}, {1030727892, 15}, {1030727892, 14},
    //         {1030727892, 52}, {1030727892, 53}, {1030727892, 37}, {1030727892, 34},
    //         {1030727892, 35}, {1171836109, 34}, {1171836109, 33}, {1171836109, 37},
    //         {1171836109, 36}, {1171836109, 35}, {3458056116, 66}, {3458056116, 68},
    //         {3458056116, 69}, {3458056116, 67}, {3458056116, 69}, {3458056116, 52},
    //         {749821213, 10}, {749821213, 2}
    // };
    // for (const auto& pair : filteredEventIdentifiers) {
    //     EventIdentifier* ei = new EventIdentifier(pair.first, pair.second);
    //     Filter::filteredEventIdentifiers.insert(ei);
    // }

    MyLogger::writeLog("initFilter succeed!");
}


void Initializer::initImages(bool background) {
    std::ifstream list(initImagesFile);
    if (!list) {
        std::cerr << "Warning: Could not open image prewarm list: " << initImagesFile << '\n';
        return;
    }
    std::string path;
    size_t accepted = 0;
    while (accepted < 256 && std::getline(list, path)) {
        if (path.compare(0, 3, "\xef\xbb\xbf") == 0)
            path.erase(0, 3);
        const auto begin = path.find_first_not_of(" \t\r");
        if (begin == std::string::npos || path[begin] == '#')
            continue;
        path = path.substr(begin, path.find_last_not_of(" \t\r") - begin + 1);
        if (path.size() >= 4096 || Filter::parsedApiImage.count(path))
            continue;
        if (background && !EventImage::enqueueModuleApis(path))
            break;
        Filter::parsedApiImage.insert(path);
        Filter::filteredImageFile.insert(path);
        if (!background)
            EventImage::loadModuleApis(path);
        ++accepted;
    }
    std::cout << "Image prewarm candidates: " << accepted << '\n';
}

/*
    initialize EventIdentiier map with correlated properties.

    The layout file is chosen from the OS build number (schema module): every
    eventStruct_*.xml declares MinBuild/MaxBuild on its root element, so a new
    Windows release only needs a new XML + drift verification, not a code
    change. Previously this was a hard-coded `6.1 ? win7 : win10`, which is why
    Win11 was not supported.
*/
void Initializer::initEventPropertiesMap(std::string confFile) {

    std::set <EventIdentifier*> tempEventIdentifierSet;
    std::list<BaseEvent::PropertyInfo> tempList;
    BaseEvent::PropertyInfo propertyInfo;
    tinyxml2::XMLDocument doc;

    kellect::schema::OsInfo os = kellect::schema::DetectOs();
    std::string detected = kellect::schema::SelectSchemaFile("config", os.build);
    if (!detected.empty())
        confFile = detected;
    os.schemaFile = confFile;

    std::cout << "------ETW event schema------" << std::endl;
    std::cout << "  os      : " << os.displayName << " ("
              << kellect::schema::ProfileName(os.profile) << ")" << std::endl;
    std::cout << "  profile : " << confFile << std::endl;

    int res = doc.LoadFile(confFile.c_str()); //load xml file
    if(res!=0){
        // Without a schema every kernel event is dropped at parse time, so a
        // missing/invalid config directory must fail loudly instead of
        // producing an empty stream (this is fatal for a service too).
        std::cerr << "FATAL: cannot load event schema '" << confFile
                  << "'. Run kellect from its installation folder (config\\ must"
                     " sit next to the executable)." << std::endl;
        exit(4);
    }

    //load file to get the EventIdentifier, which used to parse the event stream
    EventIdentifier* ei;
    XMLElement* root = doc.RootElement();
    XMLElement* evnt = root->FirstChildElement("Event");
    while(evnt!= nullptr){
        //load single event type identifier
        XMLElement* opCodeElement = evnt->FirstChildElement("OpCode");
        XMLElement* providerIDElement = evnt->FirstChildElement("ProviderID");
        XMLElement* eventNameElement = evnt->FirstChildElement("EventName");
        XMLElement* attributesElement = evnt->FirstChildElement("Attributes");
        int opCode = opCodeElement->Int64Text();
        ULONG64 providerID = Tools::String2ULONG64(providerIDElement->GetText());
        const char *eventName = eventNameElement->GetText();
        ei = new EventIdentifier(providerID , opCode, eventName);

        //load single event type properties pairs
        XMLElement * attrElement = attributesElement->FirstChildElement("Attribute");
        while(attrElement!=nullptr){        //get attributes of current event

            const char *attrName = attrElement->GetText();
            int type = attrElement->Int64Attribute("type");
            bool optional = attrElement->IntAttribute("optional", 0) != 0;

            propertyInfo = BaseEvent::PropertyInfo(attrName ? attrName : "", type, optional);
            tempList.push_back(propertyInfo);
            attrElement = attrElement->NextSiblingElement();
        }

        //store the eventIdentifier and properties
        BaseEvent::eventIdentifierSet.insert(ei);
        BaseEvent::eventStructMap.insert(
                    std::map<EventIdentifier*, std::list<BaseEvent::PropertyInfo>, EventIdentifierSortCriterion>::value_type(ei, tempList));
        tempList.clear();

        evnt = evnt->NextSiblingElement();  //next event type sibling node
    }

    //store the propertyIndex to propertyName
    std::string tempString = "UniqueProcessKey,ProcessId,ParentId,SessionId,ExitStatus,DirectoryTableBase,Flags,UserSID,ImageFileName,CommandLine,PackageFullName,ApplicationId,TThreadId,StackBase,StackLimit,UserStackBase,UserStackLimit,Affinity,Win32StartAddr,TebBase,SubProcessTag,BasePriority,PagePriority,IoPriority,ThreadFlags,NewThreadId,OldThreadId,NewThreadPriority,OldThreadPriority,PreviousCState,SpareByte,OldThreadWaitReason,OldThreadState,OldThreadWaitIdealProcessor,NewThreadWaitTime,Reserved,PageFaultCount,HandleCount,PeakVirtualSize,PeakWorkingSetSize,PeakPagefileUsage,QuotaPeakPagedPoolUsage,QuotaPeakNonPagedPoolUsage,VirtualSize,WorkingSetSize,PagefileUsage,QuotaPagedPoolUsage,QuotaNonPagedPoolUsage,PrivatePageCount,InitialTime,Status,Index,KeyHandle,KeyName,PID,size,daddr,saddr,dport,sport,startime,endtime,seqnum,connid,mss,sackopt,tsopt,wsopt,rcvwin,rcvwinscale,sndwinscale,Proto,FailureCode,IrpPtr,FileObject,TTID,CreateOptions,FileAttributes,ShareAccess,OpenPath,FileKey,Length,InfoClass,FileIndex,FileName,ExtraInfo,NtStatus,Offset,IoSize,IoFlags,DiskNumber,IrpFlags,TransferSize,ByteOffset,Irp,HighResResponseTime,IssuingThreadId,RoutineAddr,UniqMatchId,Routine,MajorFunction,MinorFunction,MessageID,IsServerPort,PortName,ReturnValue,Vector,SysCallAddress,SysCallNtStatus,ImageBase,ImageSize,ImageChecksum,TimeDateStamp,SignatureLevel,SignatureType,Reserved0,DefaultBase,Reserved1,Reserved2,Reserved3,Reserved4";

    //ifstream infile("config/propertyName.txt",ios::in);
    std::regex re(",");
    std::sregex_token_iterator p(tempString.begin(), tempString.end(), re, -1);
    std::sregex_token_iterator end;
    //std::string tempString;
    // 分割字符串并存入向量
    while (p != end) {
        BaseEvent::propertyNameVector.push_back(*p);
        ++p;
    }


//    if (!infile.is_open())
//    {
//        cout << "read file 'config/propertyName.txt' failed..." << endl;
//        return;
//    }
//    if (getline(infile, tempString) && tempString != "") {
//
//        p = std::sregex_token_iterator(tempString.begin(), tempString.end(), re, -1);
//
//        while (p != end) {
//            BaseEvent::propertyNameVector.push_back(*p);
//            ++p;
//        }
//    }
//    infile.close();

////    for debug: get propertyIndex
//    for (auto item : BaseEvent::propertyNameVector) {
//        std::cout << item << ",";
//    }
//    int a = 0;
}

/*
    Pipeline workers. The ETW callback only filters, allocates the event shell,
    copies the raw frame and pushes it here.

      * parsePools     - exactly ONE thread. Decode + semantic parse must stay in
                         ETW order because they update shared maps
                         (tid->pid, fileObject->path, keyHandle->key).
      * serializePool  - JSON building only; 1 thread keeps the output order,
                         more threads raise throughput (--serialize-threads).
      * API loader     - export-table parsing for ImageLoad, on its own thread.

    Both pools are bounded: when a backlog is full the caller runs the task
    inline, which slows the producer instead of dropping the event.
*/
void Initializer::initPrasePool() {

    EventParser::parsePools = new ThreadPool(1, 200000);

    size_t serializerCount = serializeThreads;
    if (serializerCount < 1) serializerCount = 1;
    if (serializerCount > 8) serializerCount = 8;
    // Start the maximum number of serializers; the dynamic target starts at the
    // configured value and can grow 1..8 without creating threads on the hot path.
    EventParser::serializePool = new ThreadPool(8, 200000, 8);
    EventParser::serializePool->SetTargetWorkers(serializerCount);

    // LoadLibrary/PE export parsing (hundreds of microseconds per new image)
    // must not stall the ordered parse thread.
    if (callstackRequested)
        EventImage::startApiLoader();

    if (serializerCount > 1) {
        std::cout << "note: " << serializerCount
                  << " serializer threads -> event JSON lines may interleave in time order"
                  << std::endl;
    }
}
void Initializer::initOutputThread() {
    if (EventParser::op != nullptr)
        EventParser::outputThread = std::thread(&Output::outputStrings, EventParser::op);
}

void Initializer::initProcessor2ThreadAndThread2Process(){

    for(int i = 0 ; i<MAX_PROCESSOR_NUM; i++)
        EventThread::processorId2threadId[i] = INIT_THREAD_ID;

    // threadId2processId is now a std::map, no need to initialize all elements
    // for(int i = 0 ; i<MAX_THREAD_NUM; i++)
    //     EventThread::threadId2processId[i] = INIT_PROCESS_ID;

    // processID2ParentProcessID is now a std::map, no need to initialize all elements
    // The map will be populated as processes are enumerated
}

STATUS Initializer::initThreadProcessMap() {

    // Seed threadId -> processId from a live snapshot. Later ThreadStart /
    // ThreadEnd events keep it current; the snapshot only removes the
    // "unknown PID" window at startup. Failures degrade gracefully: the map is
    // filled by events anyway.
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Warning: thread snapshot failed (" << GetLastError()
                  << "); thread->process mapping will be learned from events." << std::endl;
        return STATUS_SUCCESS;
    }

    THREADENTRY32 entry;
    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);

    int count = 0;
    if (Thread32First(snapshot, &entry)) {
        do {
            EventThread::threadId2processId[(ULONG64)entry.th32ThreadID] =
                (int)entry.th32OwnerProcessID;
            ++count;
        } while (Thread32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);

    std::cout << "  threads  : " << count << std::endl;
    return STATUS_SUCCESS;
}

// Helper function to enable debug privilege
BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed. Error: " << GetLastError() << std::endl;
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        std::cerr << "LookupPrivilegeValue failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        std::cerr << "AdjustTokenPrivileges failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

STATUS Initializer:: InitProcessMap() {

    // Seed pid -> image name / ppid from a live snapshot so events that arrive
    // before their own ProcessStart/ProcessDCStart carry a usable PName and
    // PPID. A failed snapshot is not fatal: events fill the maps as they come.
    std::cout << "------Begin to initialize datas of process and thread...------" << std::endl;

    EventProcess::processID2Name[0] = "idle";
    EventProcess::processID2Name[INIT_PROCESS_ID] = "Unknown";

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Warning: process snapshot failed (" << GetLastError()
                  << "); process names will be learned from events." << std::endl;
        return STATUS_SUCCESS;
    }

    PROCESSENTRY32W entry;
    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);

    int count = 0;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            const int pid = (int)entry.th32ProcessID;
            std::wstring wideName(entry.szExeFile);
            std::string name = Tools::WString2String(wideName.c_str());

            EventProcess::processID2Name[pid] = name;
            if (!name.empty()) EventProcess::processName2ID[name] = pid;
            EventProcess::processID2ParentProcessID[pid] = (int)entry.th32ParentProcessID;
            ++count;
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);

    std::cout << "  processes: " << count << std::endl;
    std::cout << "------Initialize datas of process and thread end...------" << std::endl;
    return STATUS_SUCCESS;
}

void Initializer::initHostUUID() {
    // 1) 从 config/uuid 读上次生成的 UUID(跨重启保持一致)
    {
        std::ifstream f("config/uuid");
        if (f.is_open()) {
            std::string saved;
            std::getline(f, saved);
            // standard UUID string length = 36 (8-4-4-4-12)
            if (saved.size() == 36) {
                setUUID(saved);
                return;
            }
        }
    }

    // 2) 生成新 UUID 并持久化,下次启动复用
    GUID guid;
    if (CoCreateGuid(&guid) == S_OK) {
        char buf[64];
        sprintf(buf, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                guid.Data1, guid.Data2, guid.Data3,
                guid.Data4[0], guid.Data4[1],
                guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5],
                guid.Data4[6], guid.Data4[7]);
        setUUID(buf);

        std::ofstream of("config/uuid");
        if (of.is_open()) {
            of << buf;
        }
        return;
    }

    // 3) 兜底:CoCreateGuid 失败(极罕见)
    setUUID("none");
    std::cout << "host UUID generation failed." << std::endl;
}

void Initializer::initNeededStruct() {
    setListenCallStack(callstackRequested);
    // Event source selection:
    //   -e <mask>          -> exactly those kernel events
    //   -u <provider>       -> that user-mode provider only (documented usage)
    //   neither             -> all kernel events (README: "default trace all")
    // The old code left enabledFlags at 0 when -e was omitted, so a bare
    // `kellect.exe -c` started no session at all and silently collected nothing.
    if (!enbaleFlagsInited) {
        if (userProvider != 0) {
            enabledFlags = 0;   // user-mode session only
            std::cout << "no -e given: tracing only the user-mode provider" << std::endl;
        } else {
            initDefaultEnabledEvents();
            enbaleFlagsInited = true;   // let initEnabledEvent build the mask
        }
    }
    initEnabledEvent(userEnabledFlags);
    enabledFlags |= extraKernelFlags;
    if (EventParser::evidenceOnly) {
        MyLogger::initLogger();
        initHostUUID();
        return;
    }
    if (EventParser::op != nullptr)
        EventParser::op->setOutputThreashold(opThreashold);
    MyLogger::initLogger();//初始化日志系统
    Tools::initVolume2DiskMap();//构建一个卷标到磁盘符号的映射，便于后续的磁盘操作和管理
    std::cout << "Step 1: Initializing processor-thread mapping..." << std::endl;
    initProcessor2ThreadAndThread2Process();//设置相关数组初始值
    
    std::cout << "Step 2: Initializing process map..." << std::endl;
    STATUS processStatus = InitProcessMap();
    
    std::cout << "Step 3: Initializing thread process map..." << std::endl;
    STATUS threadStatus = initThreadProcessMap();
    
    std::cout << "Process map status: " << processStatus << ", Thread process map status: " << threadStatus << std::endl;
    
    // Only exit if both InitProcessMap and initThreadProcessMap failed
    if (processStatus != STATUS_SUCCESS && threadStatus != STATUS_SUCCESS) {
        std::cout << "------Initialize process and thread failed!------" << std::endl;
        exit(-1);
    }
    EventImage::setAdaptiveExports(prewarmMode == "adaptive" || prewarmMode == "hybrid");
    if (callstackRequested && (prewarmMode == "static" || prewarmMode == "hybrid")) {
        const bool background = !evidenceDirectory.empty();
        if (background)
            EventImage::startApiLoader();
        initImages(background);
    }
    
    // Phase 1b: snapshot modules too, so Image DCStart rundown is not needed
    // for the module map (it is fast-dropped in the ETW callback).
    EventImage::PreEnumerateModules();

    std::cout << "Step 4: Process and thread initialization completed!" << std::endl;
    initEventPropertiesMap();       //2

    if(opThreashold == 0){
        initOutputThreashold(userEnabledFlags);
    }
    initFilter();       //3
    initPrasePool();
    initHostUUID();
    //set output threashold value, which depends on the event types we want to trace

    initOutputThread();
}

void Initializer::showCommandList(bool full) {

    if (!full) {
        std::cout
            << "Kellect Windows Collector\n\n"
            << "Usage:\n"
            << "  kellect.exe [options]\n\n"
            << "Common:\n"
            << "  -f <file>            output JSONL (omit = stats only, no file)\n"
            << "  -e all|<mask>        kernel behaviour events (legacy hex mask accepted)\n"
            << "  -c                   print every event to console (slow)\n"
            << "  --mqtt               also publish to SecArgus MQTT\n"
            << "  --profile <name>     behavior (default) | diagnostic\n"
            << "  -h                   this help\n"
            << "  --help-all           all advanced options\n\n"
            << "Behaviour events: Process, FileIO, Registry, TCP/IP, UDP/IP.\n"
            << "Thread and CallStack are opt-in (advanced: --enable-thread-events / --callstack).\n";
        return;
    }


    std::string cmdList =
        "Usage:\n"
        "  kellect.exe [options]\n"
        "\n"
        "Common:\n"
        "  -f <file>                output JSONL file (omit = stats only, no file)\n"
        "  -e <mask>                legacy event mask (0x40 = CallStack)\n"
        "  --profile <name>         behavior (default) | diagnostic\n"
        "  --callstack              force CallStack on for a legacy -e mask\n"
        "  --mqtt                   also publish to SecArgus over MQTT\n"
        "\n"
        "Advanced:\n"
        "  --evidence-dir <dir>     write raw evidence archive\n"
        "  --kernel-etl             also write kernel.etl\n"
        "  --replay-etl <etl>       replay a kernel ETL offline\n"
        "  --symbolize <dir>        offline PE/PDB symbolization\n"
        "  --schema-probe <file>    write schema drift report\n"
        "  --init-images <file>     prewarm image list\n"
        "  --serialize-threads <n>  JSON builder threads (1..8)\n"
        "  --no-adaptive            disable dynamic serializer/buffer tuning\n"
        "\n"
        "All options:\n";

    cmdList.append("-e , the event type you want to trace\n");
    cmdList.append("\trguments details:\n"
                   "\t\t0x1(PROCESS)\n"
                   "\t\t0x2(THREAD)\n"
                   "\t\t0x4(IMAGE)\n"
                   "\t\t0x8(FILE)\n"
                   "\t\t0x10(DISK) Win7 is not supported.\n"
                   "\t\t0x20(REGISTRY)\n"
//                   "\t\t0x40(SYSTEMCALL)\n"
                   "\t\t0x40(CALLSTACK, only with --callstack)\n"
                   "\t\t0x80(TCPIP)\n"
                   "\t\tall(tracing all event types)\n"
                   "\tUsage:-e 0x11 ,which will trace events of Process and Disk.\n"
                   "\tUsage:-e 0xbf ,trace all kernel events without API info (the default).\n"
                   "\tUsage:-e all  ,which will trace all events, the args of Win7 is 0xef.\n"
                   "\tNote:Do not listen 'DISK' events on Win7,kellect will crash.\n"
    );
    cmdList.append("--callstack , also collect API call stacks (off by default;\n"
                   "\tadds a second event stream and CPU cost).\n");
    cmdList.append("--profile <behavior|diagnostic|lightweight|provenance|full_kernel|full_research>\n"
                   "\tbehavior (default) keeps file/registry/network lifecycle + key stacks.\n"
                   "--evidence-dir <directory> , write raw ETW, stack artifacts and coverage.\n"
                   "\tDefault (no -e/-u/--profile) is behavior: process/thread/image/\n""\tfile/registry/TCP-IP plus key call stacks.\n""\tUse diagnostic only when DiskIO/CSwitch/memory/ALPC are needed.\n"
                   "--kernel-etl , also save the native kernel ETL to the evidence run directory.\n"
                   "--replay-etl <file> --evidence-dir <directory> , archive a kernel ETL offline.\n"
                   "--symbolize <archive-dir> --image-dir <dir> [--pdb-dir <dir>] --symbols-out <new-file>\n"
                   "--prewarm-mode <off|static|adaptive|hybrid> , legacy stack PE export loading.\n"
                   "--init-images <file> , UTF-8 prewarm list (default config/initImages.txt).\n");
    cmdList.append("-u , the UserProvider you want to trace\n");
    cmdList.append("\trguments details:\n"
                   "\t\t0x01(Thread_Pool)\n"
                   "\t\t0x02(Microsoft_Windows_DNS_Client)\n"
                   "\t\t0x03(Microsoft_Windows_PrintService)\n"
    );
    cmdList.append("-wdm , the event type you want to trace and out by wdm\n");
    cmdList.append("\trguments details:\n"
                   "\t\t0x1(PROCESS)\n"
                   "\t\t0x2(THREAD)\n"
                   "\t\t0x8(FILE)\n"
                   "\t\t0x20(REGISTRY)\n"
                   "\t\t0x80(TCPIP)\n"
                   "\t\tall\n");
    cmdList.append("-f , the file path that you want to output the events\n"
                   "\tUsage: c:\\123.txt ,output events to file c:\\123.txt\n");
    cmdList.append("-c , output events to the console \n");
    cmdList.append("-s , the socket that you want to transmit events\n"
                   "\tUsage: 192.168.1.2:66 ,output events to host 192.168.1.2 \n");
    cmdList.append("--outputThreshold , set the threshold number of output events.\n");
    cmdList.append("-x , comma-separated event names to drop before parsing (noise control)\n"
                   "\tUsage: -x FileIODirNotify,FileIODirEnum\n"
                   "\tEvent names come from config/eventStruct_win10.xml\n");
    cmdList.append("--schema-strict , drop events whose raw frame does not match the\n"
                   "\tdeclared layout (default: keep the valid prefix)\n");
    cmdList.append("--schema-probe <file> , record per-event frame lengths and write a\n"
                   "\tschema drift report to <file> on exit (use this on a new\n"
                   "\tWindows build to rebuild config/eventStruct_*.xml)\n");
    cmdList.append("--max-file-mb <n> , rotate the -f output file every n MB (0 = never).\n"
                   "\tRecommended for long-running (service) collection.\n");
    cmdList.append("--append , append to the -f file instead of truncating it (service\n"
                   "\trestarts keep the events already collected).\n");
    cmdList.append("--probe , stream events to the Kellect backend over WebSocket +\n"
                   "\tMessagePack (protocol v1). Reads config/probe.ini.\n"
                   "\tOverrides: --probe-url <ws://host:port/ws/probe> --probe-id <id>\n"
                   "\t--probe-token <token> --probe-config <file> --probe-queue <n>\n"
                   "\t--probe-batch <n<=500> --probe-rate <events/sec, 0=unlimited>\n");
    cmdList.append("--serialize-threads <1..8> , JSON builder threads (default 1 keeps\n"
                   "\tevent order; more threads trade ordering for throughput).\n");
    cmdList.append("--mqtt , additionally publish event batches to the SecArgus backend\n"
                   "\tover MQTT. Additive: works together with -c/-f/-s/-k/--probe.\n"
                   "\tConfig: config/secargus.ini (--mqtt-config <file>).\n"
                   "\tBroker override: --mqtt-host <ip> --mqtt-port <port>.\n");
    cmdList.append("-h , get the manual\n");

    std::cout << cmdList;
}

inline bool Initializer::validArgLength(int i,STATUS& status) {

    if (i >= argc) {
        MyLogger::writeLog("-e arguments length error");
        status = STATUS_FAIL;

        return 0;
    }
    status = STATUS_SUCCESS;
    return 1;
}

inline bool Initializer::isOutPutOption(char* option) {

    return !strcmp(option, "-c") || !strcmp(option, "-f") || !strcmp(option, "-s")
        || !strcmp(option, "--probe");
}

//change the opThreashold according to the event type we traced.
//deprecated!
STATUS Initializer::initOutputThreashold(ULONG64 eventType) {
    opThreashold = 0;

    //the accumulated value was not tested experimentally, all based on experience
    if (eventType & PROCESSEVENT)
        opThreashold += 5;
    if (eventType & THREADEVENT)
        opThreashold += 30;
    if (eventType & REGISTEREVENT)
        opThreashold += 50;
    if (eventType & FILEEVENT)
        opThreashold += 20;
    if (eventType & DISKEVENT)
        opThreashold += 5;
//    if (eventType & SYSTEMCALLEVENT)
//        opThreashold += 1000;
    if (eventType & IMAGEEVENT)
        opThreashold += 10;
    if (eventType & TCPIPEVENT)
        opThreashold += 5;
    if (eventType & CALLSTACKEVENT)
        opThreashold += 20;

    return STATUS_SUCCESS;
}

ULONG64 Initializer::init(GUID &p) {
    STATUS status = 0;
    int i = 1;
    char* currentArv = nullptr;
    if (argc < 1) return 0;
    //default trace all events
    while (i < argc) {
        // Borrowed pointer into the CRT argv - never freed here. The old code
        // malloc'd sizeof(char*) bytes and strcpy'd the whole option into it:
        // a heap overflow for every option longer than 7 characters
        // (e.g. "--outputThreshold").
        currentArv = argV[i++];

        if (strcmp(currentArv, "-c") == 0 && !outputInited && !probeRequested) {

            EventParser::op = new ConsoleOutPut();
            outputInited = true;
        }
        else if(strcmp(currentArv,"-wdm")==0){
            EventParser::isWdm=true;
        }
        else if (strcmp(currentArv, "-f") == 0 && !outputInited && !probeRequested) {

            if (!validArgLength(i,status))   break;

            EventParser::op = new FileOutPut(argV[i++]);
            outputInited = true;
        }
        else if (strcmp(currentArv, "-s") == 0 && !outputInited && !probeRequested) {

            if (!validArgLength(i, status))   break;

            EventParser::op = new SocketOutPut(argV[i++]);
            outputInited = true;
        }
        else if (strcmp(currentArv, "-e") == 0) {
            EventParser::isWdm=false;
            if (!validArgLength(i, status))   break;
//            std::cout<<strcmp(argV[i++],"all")<<std::endl;
            std::string arg = argV[i++];
            userEnabledFlags = strcmp(arg.c_str(),"all") == 0 ? 0xab : Tools::HexStr2DecInt(arg);

            if(status == STATUS_SUCCESS)    enbaleFlagsInited = true;
        }
//        else if(strcmp(currentArv,"-wdm")==0){
//            if (!validArgLength(i, status))   break;
//            std::string arg = argV[i++];
//         userEnabledFlags = strcmp(arg.c_str(),"all") ==( 0x1|0x2|0x8|0x20|0x80)? 0x1ff:Tools::HexStr2DecInt(arg);
//            EventParser::op = new ConsoleOutPut();
//            EventParser::isWdm=true;
//            status = EventParser::op->init();
//            outputInited = true;
//            if(status == STATUS_SUCCESS)    enbaleFlagsInited = true;
//        }
        else if (strcmp(currentArv, "--outputThreshold") == 0) {

            if (!validArgLength(i, status))   break;
            std::string threshold = argV[i++];
            opThreashold = Tools::String2ULONG64(threshold);
            status = STATUS_SUCCESS;
        }
        else if (strcmp(currentArv, "--schema-probe") == 0) {
            // Collect a per-(provider, opcode) frame-length report; written on
            // stop. This is how a new Windows build's layouts are measured.
            if (!validArgLength(i, status))   break;
            schemaProbeFile = argV[i++];
            kellect::schema::SetProbeReportPath(schemaProbeFile);
            kellect::schema::DriftTracker::Instance().SetProbeEnabled(true);
            status = STATUS_SUCCESS;
        }
        else if (strcmp(currentArv, "--profile") == 0 ||
                 strcmp(currentArv, "--evidence-dir") == 0) {
            if (!validArgLength(i, status)) break;
            std::string& value = strcmp(currentArv, "--profile") == 0 ? profile : evidenceDirectory;
            value = argV[i++];
            if (value.empty())
                status = STATUS_FORMAT_ERROR;
        }
        else if (strcmp(currentArv, "--kernel-etl") == 0) {
            kernelEtl = true;
            if (evidenceDirectory.empty())
                evidenceDirectory = "evidence";
        }
        else if (strcmp(currentArv, "--prewarm-mode") == 0) {
            if (!validArgLength(i, status)) break;
            prewarmMode = argV[i++];
            if (prewarmMode != "off" && prewarmMode != "static" &&
                prewarmMode != "adaptive" && prewarmMode != "hybrid") {
                std::cerr << "Error: invalid --prewarm-mode '" << prewarmMode << "'.\n";
                status = STATUS_FORMAT_ERROR;
            }
        }
        else if (strcmp(currentArv, "--init-images") == 0) {
            if (!validArgLength(i, status)) break;
            initImagesFile = argV[i++];
            if (initImagesFile.empty())
                status = STATUS_FORMAT_ERROR;
        }
        else if (strcmp(currentArv, "--schema-strict") == 0) {
            // Drop events whose frame does not fit the declared layout instead
            // of emitting the best-effort prefix.
            schemaStrict = true;
            kellect::schema::SetStrictMode(true);
            status = STATUS_SUCCESS;
        }
        else if (strcmp(currentArv, "--max-file-mb") == 0) {
            // Rotate the -f output file once it reaches N MB (0 = never).
            if (!validArgLength(i, status))   break;
            maxFileMB = Tools::String2ULONG64(argV[i++]);
            status = STATUS_SUCCESS;
        }
        else if (strcmp(currentArv, "--append") == 0) {
            // Keep appending to an existing -f file instead of truncating it
            // (the service uses this so a restart does not wipe collected data).
            appendMode = true;
            status = STATUS_SUCCESS;
        }
        else if (strcmp(currentArv, "--probe") == 0) {
            // Output to the Kellect backend (WebSocket + MessagePack, protocol
            // v1). Credentials and URL come from config/probe.ini.
            if (outputInited || probeRequested) {
                status = STATUS_DUPLICATE_OUTPUT;
                break;
            }
            probeRequested = true;
            status = STATUS_SUCCESS;
        }
        else if (strcmp(currentArv, "--probe-url") == 0) {
            if (!validArgLength(i, status))   break;
            probeUrl = argV[i++];
            status = STATUS_SUCCESS;
        }
        else if (strcmp(currentArv, "--probe-id") == 0) {
            if (!validArgLength(i, status))   break;
            probeId = argV[i++];
            status = STATUS_SUCCESS;
        }
        else if (strcmp(currentArv, "--probe-token") == 0) {
            if (!validArgLength(i, status))   break;
            probeToken = argV[i++];
            status = STATUS_SUCCESS;
        }
        else if (strcmp(currentArv, "--probe-config") == 0) {
            if (!validArgLength(i, status))   break;
            probeConfigFile = argV[i++];
            status = STATUS_SUCCESS;
        }
        else if (strcmp(currentArv, "--probe-queue") == 0) {
            if (!validArgLength(i, status))   break;
            probeQueue = static_cast<size_t>(Tools::String2ULONG64(argV[i++]));
            status = STATUS_SUCCESS;
        }
        else if (strcmp(currentArv, "--probe-batch") == 0) {
            if (!validArgLength(i, status))   break;
            probeBatch = static_cast<size_t>(Tools::String2ULONG64(argV[i++]));
            status = STATUS_SUCCESS;
        }
        else if (strcmp(currentArv, "--probe-rate") == 0) {
            if (!validArgLength(i, status))   break;
            probeRate = static_cast<int>(Tools::String2ULONG64(argV[i++]));
            status = STATUS_SUCCESS;
        }
        else if (strcmp(currentArv, "--serialize-threads") == 0) {
            // JSON serialisation threads (1 = default, preserves order).
            if (!validArgLength(i, status))   break;
            serializeThreads = static_cast<size_t>(Tools::String2ULONG64(argV[i++]));
            if (serializeThreads < 1) serializeThreads = 1;
            if (serializeThreads > 8) serializeThreads = 8;
            status = STATUS_SUCCESS;
        }
        else if (strcmp(currentArv, "--callstack") == 0) {
            // Opt-in: collect/parse API stack traces (extra event stream + CPU).
            callstackRequested = true;
            status = STATUS_SUCCESS;
        }
        else if (strcmp(currentArv, "--mqtt") == 0) {
            // Additive SecArgus output; works together with any primary sink.
            mqttRequested = true;
            status = STATUS_SUCCESS;
        }
        else if (strcmp(currentArv, "--mqtt-config") == 0) {
            if (!validArgLength(i, status))   break;
            mqttConfigFile = argV[i++];
            mqttConfigExplicit = true;
            status = STATUS_SUCCESS;
        }
        else if (strcmp(currentArv, "--mqtt-host") == 0) {
            if (!validArgLength(i, status))   break;
            mqttHostOverride = argV[i++];
            status = STATUS_SUCCESS;
        }
        else if (strcmp(currentArv, "--mqtt-port") == 0) {
            if (!validArgLength(i, status))   break;
            mqttPortOverride = atoi(argV[i++]);
            if (mqttPortOverride <= 0 || mqttPortOverride > 65535) {
                std::cerr << "Error: --mqtt-port must be 1..65535" << std::endl;
                exit(7);
            }
            status = STATUS_SUCCESS;
        }
        else if (strcmp(currentArv, "--stats-interval") == 0) {
            if (!validArgLength(i, status)) break;
            statsInterval = atoi(argV[i++]);
            if (statsInterval < 1 || statsInterval > 3600) {
                std::cerr << "Error: --stats-interval must be 1..3600 seconds.\n";
                status = STATUS_FORMAT_ERROR;
            }
        }
        else if (strcmp(currentArv, "--stop-event") == 0) {
            // Internal: used by KellectService's supervisor for graceful stop.
            if (!validArgLength(i, status))   break;
            stopEventName = argV[i++];
            status = STATUS_SUCCESS;
        }
        else if (strcmp(currentArv, "--enable-thread-events") == 0) {
            threadEventsEnabled = true;
        }
        else if (strcmp(currentArv, "--enable-image") == 0) {
            imageEventsEnabled = true;
        }
        else if (strcmp(currentArv, "--no-adaptive") == 0) {
            adaptiveEnabled = false;
        }
        else if (strcmp(currentArv, "--adaptive") == 0) {
            adaptiveEnabled = true;
        }
        else if (strcmp(currentArv, "--help-all") == 0) {
            helpAll = true;
            status = STATUS_SHOW_MANUAL;
        }
        else if (strcmp(currentArv, "-h") == 0) {

            status = STATUS_SHOW_MANUAL;
        }
        else if(strcmp(currentArv,"-u")==0){
            if (!validArgLength(i, status))   break;
            std::string arg = argV[i++];
            userProvider = Tools::HexStr2DecInt(arg);
            initUserGuid(userProvider,p);
        }
        else if (strcmp(currentArv, "-x") == 0) {
            //comma-separated event names to drop at firstFilter, e.g. -x FileIODirNotify,FileIODirEnum
            if (!validArgLength(i, status))   break;
            std::string arg = argV[i++];
            size_t start = 0;
            while (start <= arg.size()) {
                size_t comma = arg.find(',', start);
                std::string name = arg.substr(start, (comma == std::string::npos ? arg.size() : comma) - start);
                size_t b = name.find_first_not_of(" \t"), e = name.find_last_not_of(" \t");
                if (b != std::string::npos) userDroppedEventNames.insert(name.substr(b, e - b + 1));
                if (comma == std::string::npos) break;
                start = comma + 1;
            }
            status = STATUS_SUCCESS;
        }
        else {
            status = isOutPutOption(currentArv) ? STATUS_DUPLICATE_OUTPUT : STATUS_UNKNOWN_OPTION;
        }


        if (status != STATUS_SUCCESS)   break;
    }

    // Remote desired config (written by update_collection_config) is applied on
    // startup; this is why the command replies requires_restart.
    // Desired config is applied *after* the profile so a remote command can
    // override a GUI/service default on the next start.

    // Default mode is behavior: process/thread/image/file/registry/TCP-IP/
    // UDP-IP plus key stacks. No evidence archive unless --evidence-dir /
    // --kernel-etl asked for it.
    if (status == STATUS_SUCCESS && profile.empty() && !enbaleFlagsInited &&
        userProvider == 0)
        profile = "behavior";

    if (status == STATUS_SUCCESS && !profile.empty()) {
        if (enbaleFlagsInited) {
            std::cerr << "Error: choose either --profile or -e.\n";
            exit(3);
        }
        char iniPath[MAX_PATH];
        const DWORD pathLength = GetFullPathNameA("config\\profiles.ini", MAX_PATH, iniPath, nullptr);
        auto readProfileValue = [&](const char* name, ULONG max, ULONG& value) {
            char field[32];
            const DWORD length = GetPrivateProfileStringA(profile.c_str(), name, "", field,
                static_cast<DWORD>(sizeof(field)), iniPath);
            char* end = nullptr;
            const auto parsed = std::strtoul(field, &end, 0);
            if (length == 0 || length >= sizeof(field) - 1 || *end || parsed > max)
                return false;
            value = parsed;
            return true;
        };
        ULONG mask = 0, stack = 0;
        if (pathLength == 0 || pathLength >= MAX_PATH ||
            !readProfileValue("event_mask", 0xbf, mask) || (mask & CALLSTACKEVENT) || !mask ||
            !readProfileValue("extra_kernel_flags", 0xffffffff, extraKernelFlags) ||
            !readProfileValue("callstack", 1, stack)) {
            std::cerr << "Error: invalid or missing profile '" << profile << "' in config/profiles.ini.\n";
            exit(3);
        }
        userEnabledFlags = mask;
        enbaleFlagsInited = true;
        callstackRequested = callstackRequested || stack != 0;

        char scope[32] = { 0 };
        GetPrivateProfileStringA(profile.c_str(), "stack_scope", "behavior", scope,
                                 static_cast<DWORD>(sizeof(scope)), iniPath);
        stackScope = (strcmp(scope, "full") == 0) ? "full" : "behavior";
        EventCallstack::SetStackScope(stackScope != "full");
        std::cout << "profile: " << profile << " (stack scope: " << stackScope << ")" << std::endl;

        // Compatibility: the older research profiles still default to an
        // evidence archive. behavior/diagnostic do not (pass --evidence-dir).
        if (evidenceDirectory.empty() && profile != "behavior" &&
            profile != "diagnostic")
            evidenceDirectory = "evidence";
    }

    if (status == STATUS_SUCCESS)
        applyDesiredConfig();

    // Callstack is opt-in. Strip 0x40 from every mask (including -e all and a
    // remote desired config) unless --callstack was passed; likewise never
    // start stack tracing. The kernel event stream itself is unchanged.
    if (enbaleFlagsInited) {
        // Explicit -e masks keep their legacy meaning (0x40 = callstack);
        // --callstack only adds the bit. The behaviour profile already has
        // 0x40 stripped and sets it via its callstack=1 field.
        if (callstackRequested)
            userEnabledFlags |= CALLSTACKEVENT;
        else
            userEnabledFlags &= ~CALLSTACKEVENT;
    }
    if (!callstackRequested)
        setListenCallStack(false);
    if (enbaleFlagsInited && userEnabledFlags == 0 && !callstackRequested) {
        // The mask only contained 0x40 (callstack), which is now opt-in.
        std::cerr << "Warning: -e only selected 0x40 (callstack); callstack is "
                     "disabled unless --callstack is passed."
                  << std::endl;
    }
    if (status == STATUS_SUCCESS && threadEventsEnabled) {
        userEnabledFlags |= THREADEVENT;
        std::cout << "thread events: enabled (advanced)" << std::endl;
    }
    if (status == STATUS_SUCCESS && imageEventsEnabled) {
        userEnabledFlags |= IMAGEEVENT;
        std::cout << "image events: enabled (ImageLoad/Unload; DCStart discarded, "
                     "startup may report etw_lost)" << std::endl;
    }

    if (status == STATUS_SUCCESS) {
        const bool stackOn = callstackRequested ||
                             (enbaleFlagsInited && (userEnabledFlags & CALLSTACKEVENT) != 0);
        std::cout << "callstack: "
                  << (stackOn ? (stackScope == "full" ? "enabled (full scope)"
                                                      : "enabled (behavior scope)")
                              : "disabled")
                  << std::endl;
    }

    // Options that must reach the primary file sink before it can be wrapped in
    // the tee and before init() opens the file.
    if (status == STATUS_SUCCESS && EventParser::op != nullptr) {
        FileOutPut* primaryFile = dynamic_cast<FileOutPut*>(EventParser::op);
        if (primaryFile != nullptr) {
            if (appendMode)
                primaryFile->setAppend(true);
            if (maxFileMB > 0) {
                primaryFile->setMaxFileBytes(maxFileMB * 1024ull * 1024ull);
                std::cout << "file rotation: every " << maxFileMB << " MB" << std::endl;
            }
        }
    }

    // Probe channel is constructed after all options are parsed (credentials
    // may be overridden per flag).
    if (status == STATUS_SUCCESS && probeRequested && EventParser::op == nullptr) {
        kellect::channel::ProbeConfig probeConfig;
        std::string configError;
        if (!kellect::channel::LoadProbeConfig(probeConfigFile, probeConfig, configError)) {
            std::cerr << "Error: cannot parse " << probeConfigFile << ": "
                      << configError << std::endl;
            MyLogger::writeLog("probe config parse error: " + configError);
            exit(6);
        }
        if (!probeUrl.empty()) probeConfig.url = probeUrl;
        if (!probeId.empty()) probeConfig.probeId = probeId;
        if (!probeToken.empty()) probeConfig.token = probeToken;
        if (probeQueue > 0) probeConfig.queueCapacity = probeQueue;
        if (probeBatch > 0) probeConfig.batchEvents = probeBatch;
        if (probeRate >= 0) probeConfig.ratePerSecond = probeRate;

        if (probeConfig.url.empty() || probeConfig.probeId.empty() ||
            probeConfig.token.empty()) {
            std::cerr << "Error: probe channel needs url, probe_id and token.\n"
                         "       Fill " << probeConfigFile
                      << " (see the sample) or pass --probe-url/--probe-id/--probe-token."
                      << std::endl;
            MyLogger::writeLog("probe channel: url/probe_id/token missing");
            exit(6);
        }
        if (probeConfig.token == "replace-with-your-token" ||
            probeConfig.probeId == "probe-000000000000") {
            std::cerr << "Error: " << probeConfigFile
                      << " still holds the sample probe_id/token. Register the probe"
                         " and put the real values in (token is shown only once)."
                      << std::endl;
            MyLogger::writeLog("probe channel: sample probe_id/token not replaced");
            exit(6);
        }

        EventParser::op = new kellect::channel::ProbeChannel(probeConfig);
        outputInited = true;
        std::cout << "probe channel: " << probeConfig.url
                  << " (probe_id=" << probeConfig.probeId << ")" << std::endl;
    }

    // ---- SecArgus MQTT output (additive) -----------------------------------
    // Wraps the existing sink in a TeeOutput: the primary output keeps its
    // exact behaviour, and an MQTT failure only degrades the MQTT sink.
    if (status == STATUS_SUCCESS && mqttRequested) {
        if (EventParser::isWdm) {
            std::cerr << "Error: --mqtt cannot be combined with -wdm "
                         "(WDM output is not the Kellect event JSON)." << std::endl;
            exit(7);
        }

        kellect::secargus::MqttSettings mqttSettings;
        std::string mqttError;
        if (mqttConfigExplicit && GetFileAttributesA(mqttConfigFile.c_str()) == INVALID_FILE_ATTRIBUTES) {
            std::cerr << "Error: mqtt config not found: " << mqttConfigFile << std::endl;
            exit(7);
        }
        if (!kellect::secargus::LoadMqttSettings(mqttConfigFile, mqttSettings, mqttError)) {
            std::cerr << "Error: cannot parse " << mqttConfigFile << ": "
                      << mqttError << std::endl;
            exit(7);
        }
        mqttSettings.enabled = true;   // explicit --mqtt overrides enabled=0
        if (!mqttHostOverride.empty())
            mqttSettings.host = mqttHostOverride;
        if (mqttPortOverride > 0)
            mqttSettings.port = mqttPortOverride;

        std::string hostname = "windows-host";
        char hostBuffer[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
        DWORD hostLength = static_cast<DWORD>(sizeof(hostBuffer));
        if (GetComputerNameA(hostBuffer, &hostLength))
            hostname.assign(hostBuffer, hostLength);

        const kellect::schema::OsInfo os = kellect::schema::DetectOs();

        kellect::secargus::EndpointIdentity identity;
        if (!kellect::secargus::LoadOrCreateIdentity(
                mqttSettings.endpointConfig, Initializer::getUUID(), hostname,
                os.displayName, identity, mqttError)) {
            std::cerr << "Error: endpoint identity: " << mqttError << std::endl;
            exit(7);
        }
        if (mqttSettings.clientId.empty())
            mqttSettings.clientId = identity.clientId;

        // Snapshot of the effective collection config, reported by
        // get_collection_config. Values are the real ones the process runs with.
        kellect::secargus::CollectionInfo collection;
        collection.eventMask = userEnabledFlags;
        collection.userProviders = userProvider;
        collection.filterFile = "config\\filter.txt";
        collection.schemaName = kellect::schema::ProfileName(os.profile);
        collection.schemaFile = os.schemaFile;
        collection.startedAt = kellect::secargus::IsoNowUtc();
        collection.hotReload = false;

        std::unique_ptr<Output> mqttSink(
            new kellect::secargus::MqttOutput(mqttSettings, identity, collection));

        if (EventParser::op == nullptr) {
            EventParser::op = mqttSink.release();
            outputInited = true;
        } else {
            TeeOutput* tee = new TeeOutput();
            std::unique_ptr<Output> primary(EventParser::op);
            tee->addSink(std::move(primary), "primary", true);
            tee->addSink(std::move(mqttSink), "mqtt", false);
            EventParser::op = tee;
        }

        std::cout << "secargus mqtt: " << mqttSettings.host << ":"
                  << mqttSettings.port << " endpoint_id=" << identity.endpointId
                  << " spool=" << mqttSettings.spoolDirectory << std::endl;
    }

    if (status == STATUS_SUCCESS && !outputInited && !evidenceDirectory.empty()) {
        EventParser::op = new Output();
        EventParser::evidenceOnly = schemaProbeFile.empty();
        outputInited = true;
    }

    // Default: no file. A bare `kellect.exe` only runs the pipeline and prints
    // live stats; pass -f <file> (GUI: choose a path) to persist JSONL.
    if (status == STATUS_SUCCESS && !outputInited && !probeRequested && !mqttRequested) {
        outputInited = true;   // run the collector, but EventParser::op stays null
        std::cout << "output: disabled (stats only; use -f <file> to save events)"
                  << std::endl;
    }

    // Fail before touching the output file: a non-elevated run must not
    // truncate the destination and then abort.
    if (status == STATUS_SUCCESS && outputInited && !IsProcessElevated()) {
        std::cerr << "Error: kellect must run elevated (Run as administrator): "
                     "creating an ETW session requires it." << std::endl;
        exit(2);
    }

    // Open the output destination only after every option has been parsed:
    // --append/--max-file-mb must work regardless of their position relative to
    // -f, and an open failure (bad path or unreachable socket
    // ) still flows through the error switch below.
    if (status == STATUS_SUCCESS && outputInited && EventParser::op) {
        status = EventParser::op->init();
    }

    if (status == STATUS_SUCCESS && outputInited) {
        if(userEnabledFlags==0x1ff&&EventParser::isWdm){
            userEnabledFlags=( 0x1|0x2|0x8|0x20|0x80);
        }
        initNeededStruct();     //init config files
    }
    else {

        switch (status) {
            case STATUS_FILE_OPEN_FAILED: {
                MyLogger::writeLog("-f the file open failed.");
                break;
            }
            case STATUS_SOCKET_CONNECT_ERROR: {
                MyLogger::writeLog("-s socket connect filed.");
                break;
            }
            case STATUS_FORMAT_ERROR: {
                MyLogger::writeLog("ip:port format error ,the value should be like: \"ip:port\"(i.e 192.168.1.1:8888)");
                break;
            }
            case STATUS_DUPLICATE_OUTPUT: {
                MyLogger::writeLog("duplicate output destination.");
                break;
            }
            case STATUS_SHOW_MANUAL: {
                MyLogger::writeLog("the following is help manual.");
                break;
            }
            case STATUS_EVENT_TYPE_ERROR:{
                MyLogger::writeLog("-e format error.");
                break;
            }
            case STATUS_UNKNOWN_OPTION:{
                MyLogger::writeLog("unknown option specified.");
                break;
            }
            case STATUS_FAIL: {
                MyLogger::writeLog("options or arguments error. ");
                break;
            }
            case STATUS_SOCKET_FORMAT_ERROR:{
                MyLogger::writeLog("socket argument format error. ");
                break;
            }
        }
        showCommandList(helpAll);
        exit(-1);
    }

    return enabledFlags;
}

void Initializer::initUserGuid(ULONG64 userProvider,GUID &ProviderId){
    if (userProvider != 0x01 && userProvider != 0x02 && userProvider != 0x03 &&
        userProvider != 0) {
        std::cerr << "Warning: unknown -u provider 0x" << std::hex << userProvider
                  << std::dec << " (valid: 0x01 thread pool, 0x02 DNS client,"
                     " 0x03 print service); no user-mode session will be created."
                  << std::endl;
    }
    if(userProvider==0x01){
        struct __declspec(uuid("{C861D0E2-A2C1-4D36-9F9C-970BAB943A12}")) Thread_Pool;
        ProviderId = __uuidof(Thread_Pool);
    }
    if(userProvider==0x02){
        struct __declspec(uuid("{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}")) Microsoft_Windows_DNS_Client;
        ProviderId  = __uuidof(Microsoft_Windows_DNS_Client);
    }
    if(userProvider==0x03){
        struct __declspec(uuid("{DE7B24EA-73C8-4A09-985D-5BDADCFA9017}")) Microsoft_Windows_PrintService;
        ProviderId  = __uuidof(Microsoft_Windows_PrintService);
    }
}
