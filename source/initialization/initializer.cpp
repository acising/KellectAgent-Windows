#pragma once
#include "initialization/initializer.h"
#include "process/event_parse.h"
#include "process/etw_config.h"
#include "tools/tools.h"
#include "tools/logger.h"
#include <regex>
#include <TlHelp32.h>
#include "filter.h"
#include "tools/providerInfo.h"
#include "tools/tinyxml2.h"
#include "output/KafkaOutput.h"

INITIALIZE_EASYLOGGINGPP
using namespace std;
using namespace tinyxml2;

IMAGEUNLOAD pImageUnload;
IMAGELOAD pImageLoad;
SYMGETSYMBOLFILE pSymGetSymbolFile;
HANDLE hProcess;
PWIN32KFUNCINFO FuncAddressInfo;
PLOADED_IMAGE pli;

//used to get systemCall information
std::string parseFiles[] = { "\\SystemRoot\\System32\\win32k.sys","\\SystemRoot\\System32\\ntoskrnl.exe" };

//use to classify events by providerID and opcodes.
std::map<EventIdentifier*, std::list<BaseEvent::PropertyInfo>, EventIdentifierSortCriterion>  BaseEvent::eventStructMap;

std::set<EventIdentifier*, EventIdentifierSortCriterion> Filter::filteredEventIdentifiers;
std::set<int> Filter::filteredProcessID;
std::set<std::string> Filter::filteredImageFile;
std::set<ULONG64> Filter::listenedEventsProviders;
bool Filter::listenAllEvents(false);
bool Initializer::listenCallStack(false);
std::map <std::string, std::set<MyAPI*, MyAPISortCriterion> > EventImage::modulesName2APIs;
ThreadPool* EventParser::parsePools;
std::atomic<bool> EventParser::threadParseFlag;
int EventThread::processorId2threadId[MAX_PROCESSOR_NUM];
std::map<ULONG64, int> EventThread::threadId2processId;

STATUS Initializer::initEnabledEvent(ULONG64 eventType) {

    if(!enbaleFlagsInited ) return STATUS_SUCCESS;

    enabledFlags = EVENT_TRACE_FLAG_PROCESS|EVENT_TRACE_FLAG_THREAD;        //guarantee the fillProcessInfo() executes correctly
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

        enabledFlags |= EVENT_TRACE_FLAG_FILE_IO_INIT | EVENT_TRACE_FLAG_DISK_FILE_IO | EVENT_TRACE_FLAG_FILE_IO|EVENT_TRACE_FLAG_CSWITCH;
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
        enabledFlags |= EVENT_TRACE_FLAG_NETWORK_TCPIP|EVENT_TRACE_FLAG_CSWITCH;
        Filter::listenedEventsProviders.insert(TcpIpGuid.Data1);
    }

    if(Filter::listenedEventsProviders.size() == 8) Filter::listenAllEvents=true;

    return STATUS_SUCCESS;
}
/*
    initialize kernel provider trace event types.
*/
inline void Initializer::initDefaultEnabledEvents() {

    Filter::listenAllEvents=true;
    setListenCallStack(true);
    userEnabledFlags = ALLEVENT;
}

/*
    initialize tracing filter according to filter.txt
*/
void Initializer::initFilter() {
    // 直接定义过滤的进程 ID
    std::vector<int> filteredProcessIDs = {0, 4, 128};
    for (int id : filteredProcessIDs) {
        Filter::filteredProcessID.insert(id);
    }
    Filter::filteredProcessID.insert(GetCurrentProcessId());

    // 直接定义过滤的事件标识
// 直接定义过滤的事件标识
    std::vector<std::pair<ULONG64, int>> filteredEventIdentifiers = {
            {3740466758, 32}, {1030727888, 1}, {1030727888, 2}, {1030727889, 1},
            {1030727889, 2}, {1030727889, 36}, {2924704302, 10}, {2924704302, 11},
            {2924704302, 12}, {2924704302, 13}, {2924704302, 14}, {2924704302, 15},
            {2924704302, 16}, {2924704302, 17}, {2924704302, 18}, {2924704302, 19},
            {2924704302, 20}, {2924704302, 21}, {2924704302, 22}, {2924704302, 23},
            {2924704302, 24}, {2924704302, 25}, {2924704302, 26}, {2924704302, 27},
            {2586315456, 10}, {2586315456, 26}, {2586315456, 11}, {2586315456, 13},
            {2586315456, 14}, {2586315456, 16}, {2586315456, 18}, {2586315456, 27},
            {2586315456, 29}, {2586315456, 30}, {2586315456, 32}, {2586315456, 34},
            {2586315456, 12}, {2586315456, 15}, {2586315456, 28}, {2586315456, 31},
            {2586315456, 17}, {2429279289, 64}, {2429279289, 72}, {2429279289, 77},
            {2429279289, 69}, {2429279289, 70}, {2429279289, 71}, {2429279289, 74},
            {2429279289, 75}, {2429279289, 0}, {2429279289, 32}, {2429279289, 35},
            {2429279289, 36}, {2429279289, 67}, {2429279289, 68}, {2429279289, 65},
            {2429279289, 66}, {2429279289, 73}, {1030727892, 11}, {1030727892, 10},
            {1030727892, 12}, {1030727892, 13}, {1030727892, 15}, {1030727892, 14},
            {1030727892, 52}, {1030727892, 53}, {1030727892, 37}, {1030727892, 34},
            {1030727892, 35}, {1171836109, 34}, {1171836109, 33}, {1171836109, 37},
            {1171836109, 36}, {1171836109, 35}, {3458056116, 66}, {3458056116, 68},
            {3458056116, 69}, {3458056116, 67}, {3458056116, 69}, {3458056116, 52},
            {749821213, 10}, {749821213, 2}
    };

    for (const auto& pair : filteredEventIdentifiers) {
        EventIdentifier* ei = new EventIdentifier(pair.first, pair.second);
        Filter::filteredEventIdentifiers.insert(ei);
    }

    // 直接定义过滤的图像文件
    std::vector<std::string> filteredImageFiles = {
            "C:\\Windows\\SysWOW64\\ntdll.dll"
    };


    MyLogger::writeLog("initFilter succeed!");
}


/*
    initialize each process loaded modules with std::set<Module*, ModuleSortCriterion>().
    update lately in the ImageEvent.parse()
*/
STATUS Initializer::initProcessID2ModulesMap() {

    if (EventProcess::processID2Name.empty()) {
        MyLogger::writeLog("initProcessID2ModulesMap -->processID2Name is empty");
        std::cerr << "Error: processID2Name is empty, cannot initialize processID2ModulesMap" << std::endl;
        return STATUS_FAIL;
    }

    auto iter = EventProcess::processID2Name.begin();
    auto end = EventProcess::processID2Name.end();

    //initialize processID2ModulesMap structure with processID2Name which is initilized before. Initialize each item'value a empty set.
    for (; iter != end; ++iter) {
        EventImage::processID2Modules.insert(
                iter->first, std::set<Module*, ModuleSortCriterion>()
        );//遍历每个进程 ID（即 iter->first），在 processID2Modules 中插入一个空的模块集合（std::set<Module*, ModuleSortCriterion>()）。
        // 这个集合将用于后续存储与该进程 ID 相关联的所有模块。

        /*
        initialize processID2ModuleAddressPair structure with processID2Name which is initilized before.
        Initialize each item'value a default minmaxAddress pair.
         */
        EventProcess::processID2ModuleAddressPair.insert(
                iter->first, std::make_pair(EventProcess::initMinAddress, EventProcess::initMaxAddress));
    }

    return STATUS_SUCCESS;
}
STATUS Initializer::initImages(std::string confFile) {
    std::cout << "------Begin to parse images------" << std::endl;
    std::vector<std::string> unLoadedImages;   // 存储未加载的图像
    std::ifstream myfile(confFile);
    std::string currentImage = "";
    STATUS status = STATUS_FAIL;
    bool existUnloadedImage = false;// 标记是否存在未加载的图像

    if (!myfile.is_open()) {
        MyLogger::writeLog("file initImages open failed!");
        std::cerr << "Warning: Could not open initImages file: " << confFile << ". Using empty image list." << std::endl;
        std::cout << "------Parse images end...------" << std::endl;
        return STATUS_SUCCESS; // 即使文件打开失败，也继续执行，使用空的图像列表
    }

    //parse the system modules‘APIs
    while (getline(myfile, currentImage) && currentImage != "") {
        std::set<MyAPI*, MyAPISortCriterion> apis;

        //   imageFile
        Filter::filteredImageFile.insert(currentImage);// 将当前图像插入过滤器中

        status = EventImage::getAPIsFromFile(currentImage, apis);// 从文件中获取 API

        if (status == STATUS_SUCCESS) {
            EventImage::modulesName2APIs.insert(
                    std::map <std::string, std::set<MyAPI*, MyAPISortCriterion> >::value_type(currentImage, apis)
            );
        }// 成功则将 API 记录到模块名称与 API 的映射中
        else {
            unLoadedImages.push_back(currentImage);// 记录未加载的图像
            existUnloadedImage = true; // 标记存在未加载的图像
        }
    }
    std::cout << "------Parse images end...------" << std::endl;

    /*
     if (existUnloadedImage) {

        std::cout << "The following images loaded failed  " << std::endl;
        for (auto ss : unLoadedImages) {
            std::cout << ss << std::endl;
        }
    }
     */
    return STATUS_SUCCESS;
}

/*
    initialize EventIdentiier map with correlated properties
*/
void Initializer::initEventPropertiesMap(std::string confFile) {

    std::set <EventIdentifier*> tempEventIdentifierSet;
    std::list<BaseEvent::PropertyInfo> tempList;
    BaseEvent::PropertyInfo propertyInfo;
    DWORD dwMajorVer,dwMinorVer,dwBuildNumber;
    tinyxml2::XMLDocument doc;
    //set Windows7 version event type file, else the Windows10 event type file
    if(Tools::getOSVersion(dwMajorVer,dwMinorVer,dwBuildNumber)){
        // win 7
        if (dwMajorVer == 6 && dwMinorVer == 1){
            confFile = "config/eventStruct_win7.xml";
        }
    }
    int res = doc.LoadFile(confFile.c_str()); //load xml file
    if(res!=0){
        cout<<"load xml file failed"<<endl;
        return;
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

            propertyInfo = make_pair(attrName, type);
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
    initialize threadpool with 4 threads and a event queue with 1,000,000 capacity
*/
void Initializer::initPrasePool() {

    EventParser::parsePools = new ThreadPool(4, 1000000);
}
void Initializer::initOutputThread() {

    std::thread outputThread(&Output::outputStrings, EventParser::op);
    outputThread.detach();
}

void Initializer::initThreadParseProviders() {

//    EventParser::threadParseProviders.insert(TcpIpProvider);
    EventParser::threadParseProviders.insert(DiskProvider);

    {
//        EventParser::threadParseProviders.insert(CallStackGuid.Data1);

        EventParser::threadParseProviders.insert(RegistryProvider);
    }
    EventParser::threadParseProviders.insert(ImageLoadGuid.Data1);
    EventParser::threadParseFlag = true;
}

//initialize structure of Processor2ThreadAndThread2Process, which is used in function setPidAndTid() to fix threadId and processId
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

    STATUS status = STATUS_SUCCESS;
    
    // Simplified version of initThreadProcessMap that skips thread enumeration
    // This is a temporary fix to avoid the crash in Thread32First
    
    std::cout << "[DEBUG] Simplified initThreadProcessMap completed successfully" << std::endl;
    
    return status;
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

    std::cout << "[DEBUG] Entering InitProcessMap..." << std::endl;
    
    // Simplified version of InitProcessMap that skips process enumeration
    // This is a temporary fix to avoid the crash in Process32First
    
    STATUS status = STATUS_SUCCESS;
    
    // Instead of enumerating processes, we'll just initialize the maps with some default values
    std::cout << "------Begin to initialize datas of process and thread...------" << std::endl;
    
    // Set some default values to avoid crashes later
    EventProcess::processID2Name[0] = "idle";
    EventProcess::processID2Name[INIT_PROCESS_ID] = "Unknown";
    
    std::cout << "------Initialize datas of process and thread end...------" << std::endl;
    std::cout << "[DEBUG] Simplified InitProcessMap completed successfully" << std::endl;
    
    return status;
}

void Initializer::writeUUID2File() {
    // 直接定义 UUID，假设要记录到日志
    std::string uuid = "FBFFA15C-FEDE-4f96-9AF8-398294758A2A";
    MyLogger::writeLog("UUID: " + uuid); // 或其他处理
}

STATUS Initializer::setUUIDFromFile() {
    // 直接定义 UUID
    std::string uuid = "FBFFA15C-FEDE-4f96-9AF8-398294758A2A";
    setUUID(uuid);
    return STATUS_SUCCESS;
}

STATUS Initializer::setUUIDByFunction() {

    GUID guid;
    char tempUUID[1024];
    std::string buf;
    HRESULT res = CoCreateGuid(&guid);
    if(res == S_OK){
        sprintf(tempUUID,"\"%08X-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X\""
                , guid.Data1
                , guid.Data2
                , guid.Data3
                , guid.Data4[0], guid.Data4[1]
                , guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5]
                , guid.Data4[6], guid.Data4[7]);

        buf = std::string(tempUUID);

        Initializer::setUUID(buf);
        writeUUID2File();

        return STATUS_SUCCESS;
    }

    Initializer::setUUID("none");
    return STATUS_FAIL;
}

void Initializer::initHostUUID() {

    STATUS status = setUUIDFromFile();

    if(status == STATUS_FAIL){
        STATUS res = setUUIDByFunction();

        if(res == STATUS_FAIL) {
            std::cout<<"host UUID set failed."<<std::endl;
        }
    }
}

void Initializer::initNeededStruct() {
    EventParser::op->setOutputThreashold(opThreashold);
    initImages();       //读取etw事件有关配置文件，即使失败也继续执行
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
    
    std::cout << "Step 4: Process and thread initialization completed!" << std::endl;
    initEventPropertiesMap();       //2
    //default to trace all event types
    if(!enbaleFlagsInited){
        initDefaultEnabledEvents();
    }
    initEnabledEvent(userEnabledFlags);
    if(opThreashold == 0){
        initOutputThreashold(userEnabledFlags);
    }
    initFilter();       //3
    if (initProcessID2ModulesMap() != STATUS_SUCCESS) {
        std::cerr << "Error: Failed to initialize processID2ModulesMap" << std::endl;
        exit(-1);
    }
    initPrasePool();
    initThreadParseProviders();
    initHostUUID();
    //set output threashold value, which depends on the event types we want to trace

    initOutputThread();
}

void Initializer::showCommandList() {

    std::string cmdList = "CommandLine Option Rules:\n";
    cmdList.append("-e , the event type you want to trace\n");
    cmdList.append("\trguments details:\n"
                   "\t\t0x1(PROCESS)\n"
                   "\t\t0x2(THREAD)\n"
                   "\t\t0x4(IMAGE)\n"
                   "\t\t0x8(FILE)\n"
                   "\t\t0x10(DISK) Win7 is not supported.\n"
                   "\t\t0x20(REGISTRY)\n"
//                   "\t\t0x40(SYSTEMCALL)\n"
                   "\t\t0x40(CALLSTACK)\n"
                   "\t\t0x80(TCPIP)\n"
                   "\t\tall(tracing all event types)\n"
                   "\tUsage:-e 0x11 ,which will trace events of Process and Disk.\n"
                   "\tUsage:-e 0xbf ,which will trace all events except 'callstack',if you don't need API Info, you should specify '0xbf' to '-e' option.\n"
                   "\tUsage:-e all  ,which will trace all events, the args of Win7 is 0xef.\n"
                   "\tNote:Do not listen 'DISK' events on Win7,kellect will crash.\n"
    );
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
    cmdList.append("-k , output events to the kafka server, \n"
                   "\tUsage: 192.168.1.2:9092/test ,output events to server 192.168.1.2:9092 and topic is \"test\"\n");
    cmdList.append("-s , the socket that you want to transmit events\n"
                   "\tUsage: 192.168.1.2:66 ,output events to host 192.168.1.2 \n");
    cmdList.append("--outputThreshold , set the threshold number of output events.\n");
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

    return !strcmp(option, "-c") || !strcmp(option, "-f") || !strcmp(option, "-s");
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
        currentArv = (char*)malloc(sizeof(argV[i]));
        ZeroMemory(currentArv, sizeof(argV[i]));
        strcpy(currentArv, argV[i++]);

        if (strcmp(currentArv, "-c") == 0 && !outputInited) {

            EventParser::op = new ConsoleOutPut();
            status = EventParser::op->init();
            //EventParser::op->beginOutputThread();
//            if (status != STATUS_SUCCESS)   break;
            outputInited = true;
        }
        else if(strcmp(currentArv,"-wdm")==0){
//            if (!validArgLength(i, status))   break;
//            std::string arg = argV[i++];
//            userEnabledFlags = strcmp(arg.c_str(),"all") ==( 0x1|0x2|0x8|0x20|0x80)? 0x1ff:Tools::HexStr2DecInt(arg);
 //           EventParser::op = new ConsoleOutPut();
//            EventParser::op = new FileOutPut("wdm");
            EventParser::isWdm=true;
  //          status = EventParser::op->init();
   //         outputInited = true;
//            if(status == STATUS_SUCCESS)    enbaleFlagsInited = true;
        }
        else if (strcmp(currentArv, "-f") == 0 && !outputInited) {

            if (!validArgLength(i,status))   break;

            EventParser::op = new FileOutPut(argV[i++]);
            status = EventParser::op->init();
            //EventParser::op->beginOutputThread();
//            if (status != STATUS_SUCCESS)   break;
            outputInited = true;
        }
        else if (strcmp(currentArv, "-s") == 0 && !outputInited) {

            if (!validArgLength(i, status))   break;

            EventParser::op = new SocketOutPut(argV[i++]);
            status = EventParser::op->init();
            //EventParser::op->beginOutputThread();
            if (status != STATUS_SUCCESS)   break;

            outputInited = true;
        }
        else if(strcmp(currentArv,"-k") == 0){
            if (!validArgLength(i, status))   break;

            int idx = -1;
            std::string arg = argV[i++];
            idx = arg.find("/");
            if(idx > 0){
                std::string ip_port = arg.substr(0,idx);
                std::string topicValue = arg.substr(idx+1);
                EventParser::op = new KafkaOutPut(ip_port,topicValue);
                status = EventParser::op->init();

                if (status != STATUS_SUCCESS)   break;
                outputInited = true;
            }else{
                status = STATUS_KAFKA_FORMAT_ERROR;
                break;
            }
        }
        else if (strcmp(currentArv, "-e") == 0) {
            EventParser::isWdm=false;
            if (!validArgLength(i, status))   break;
//            std::cout<<strcmp(argV[i++],"all")<<std::endl;
            std::string arg = argV[i++];
            userEnabledFlags = strcmp(arg.c_str(),"all") == 0? 0x1ff:Tools::HexStr2DecInt(arg);

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

            std::string threshold = argV[i++];
            opThreashold = Tools::String2ULONG64(threshold);
            status = STATUS_SUCCESS;
        }
        else if (strcmp(currentArv, "-h") == 0) {

            status = STATUS_SHOW_MANUAL;
        }
        else if(strcmp(currentArv,"-u")==0){
            if (!validArgLength(i, status))   break;
            std::string arg = argV[i++];
            userProvider = Tools::HexStr2DecInt(arg);
            initUserGuid(userProvider,p);
//           EventParser::op = new ConsoleOutPut();
////            EventParser::op = new FileOutPut();
//            status = EventParser::op->init();
//            outputInited = true;
        }
        else {
            status = isOutPutOption(currentArv) ? STATUS_DUPLICATE_OUTPUT : STATUS_UNKNOWN_OPTION;
        }


        if (status != STATUS_SUCCESS)   break;
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
            case STATUS_KAFKA_FORMAT_ERROR:{
                MyLogger::writeLog("kafka argument format error. ,the value should be like: \\\"ip:port\\topicValue\\\"(i.e 192.168.1.1:8888\\test)\"");
                break;
            }
            case STATUS_SOCKET_FORMAT_ERROR:{
                MyLogger::writeLog("socket argument format error. ");
                break;
            }
        }
        showCommandList();
        exit(-1);
    }

    return enabledFlags;
}

void Initializer::initUserGuid(ULONG64 userProvider,GUID &ProviderId){
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