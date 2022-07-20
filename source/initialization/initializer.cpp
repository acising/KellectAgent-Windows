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
int FuncCount = 0;
HANDLE hProcess;
PWIN32KFUNCINFO FuncAddressInfo;
PLOADED_IMAGE pli;

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
//ReadWriteMap <std::string, std::set<MyAPI*, MyAPISortCriterion> > EventImage::modulesName2APIs;
ThreadPool* EventParser::parsePools;
std::atomic<bool> EventParser::threadParseFlag;
//ReadWriteMap<ULONG64, ULONG64> EventThread::processorId2threadId;
int EventThread::processorId2threadId[MAX_PROCESSOR_NUM];
//ReadWriteMap<ULONG64, ULONG64> EventThread::threadId2processId;
int EventThread::threadId2processId[MAX_THREAD_NUM];

STATUS Initializer::initEnabledEvent(ULONG64 eventType) {

    enabledFlags = EVENT_TRACE_FLAG_PROCESS|EVENT_TRACE_FLAG_THREAD;        //guarantee the fillProcessInfo() execute correctly

    //callstack initialize in
    if (eventType & CALLSTACKEVENT){
        setListenCallStack(true);   // set listenCallStack true;
        enabledFlags |= EVENT_TRACE_FLAG_IMAGE_LOAD;
        Filter::listenedEventsProviders.insert(CallStackProvider);
    }
    if (eventType & PROCESSEVENT){
        enabledFlags |= EVENT_TRACE_FLAG_PROCESS;
        Filter::listenedEventsProviders.insert(ProcessProvider);
    }
    if (eventType & THREADEVENT){
        enabledFlags |= EVENT_TRACE_FLAG_THREAD;
        Filter::listenedEventsProviders.insert(ThreadProvider);
    }
    if (eventType & REGISTEREVENT){
        enabledFlags |= EVENT_TRACE_FLAG_REGISTRY;
        Filter::listenedEventsProviders.insert(RegistryProvider);
    }
    if (eventType & FILEEVENT){

        enabledFlags |= EVENT_TRACE_FLAG_FILE_IO_INIT | EVENT_TRACE_FLAG_DISK_FILE_IO | EVENT_TRACE_FLAG_FILE_IO|EVENT_TRACE_FLAG_CSWITCH;
        Filter::listenedEventsProviders.insert(FileProvider);
    }
    if (eventType & DISKEVENT){
        enabledFlags |= EVENT_TRACE_FLAG_DISK_IO | EVENT_TRACE_FLAG_DISK_IO_INIT;
        Filter::listenedEventsProviders.insert(DiskProvider);
    }
//    if (eventType & SYSTEMCALLEVENT)
//        enabledFlags |= EVENT_TRACE_FLAG_SYSTEMCALL;
    if (eventType & IMAGEEVENT){
        enabledFlags |= EVENT_TRACE_FLAG_IMAGE_LOAD;
        Filter::listenedEventsProviders.insert(ImageProvider);
    }
    if (eventType & TCPIPEVENT){
        enabledFlags |= EVENT_TRACE_FLAG_NETWORK_TCPIP|EVENT_TRACE_FLAG_CSWITCH;
        Filter::listenedEventsProviders.insert(TcpIpProvider);
    }

    if(Filter::listenedEventsProviders.size() == 8) Filter::listenAllEvents=true;

    return STATUS_SUCCESS;
}
/*
    initialize kernel provider trace events type.
*/
inline void Initializer::initDefaultEnabledEvents() {

    Filter::listenAllEvents=true;
    setListenCallStack(true);
    userEnabledFlags = ALLEVENT;
//    enabledFlags = 0
//                   | EVENT_TRACE_FLAG_PROCESS
//                   | EVENT_TRACE_FLAG_THREAD
//                   | EVENT_TRACE_FLAG_REGISTRY       //many events
//                   | EVENT_TRACE_FLAG_FILE_IO_INIT   //enable FileIo_OpEnd
//                   | EVENT_TRACE_FLAG_DISK_FILE_IO
//                   | EVENT_TRACE_FLAG_FILE_IO
//                   | EVENT_TRACE_FLAG_CSWITCH        //too many events
//                   | EVENT_TRACE_FLAG_DISK_IO
//                   |EVENT_TRACE_FLAG_DISK_IO_INIT
//                   //| EVENT_TRACE_FLAG_SYSTEMCALL     //too many events
//                   | EVENT_TRACE_FLAG_IMAGE_LOAD       //lead to memory keeps increasing
//                   | EVENT_TRACE_FLAG_NETWORK_TCPIP
//            ;
}

/*
    initialize tracing filter according to filter.txt
*/
void Initializer::initFilter() {

    std::ifstream filterFile(filterFileName);
    std::string tempString = "";

    if (!filterFile.is_open()) {
        MyLogger::writeLog("file filteredFile open failed!");
        exit(-1);
    }

    std::regex re(" ");
    std::sregex_token_iterator p;
    std::sregex_token_iterator end;

    while (getline(filterFile, tempString) && tempString != "") {

        if (strcmp(tempString.c_str(), "filteredProcessID") == 0) {
            while (getline(filterFile, tempString) && tempString != "") {
                p = std::sregex_token_iterator(tempString.begin(), tempString.end(), re, -1);

                while (p != end) {
                    Filter::filteredProcessID.insert(Tools::String2Int(*p));
                    ++p;
                }
            }
            Filter::filteredProcessID.insert(GetCurrentProcessId());
        }
        else if (strcmp(tempString.c_str(), "filteredEventIdentifier") == 0) {

            while (getline(filterFile, tempString) && tempString != "") {
                p = std::sregex_token_iterator(tempString.begin(), tempString.end(), re, -1);

                EventIdentifier* ei;

                while (p != end) {
                    ULONG64 providerID = Tools::String2ULONG64(*p);
                    int opCode = Tools::String2Int(*(++p));

                    ei = new EventIdentifier(providerID, opCode);

                    Filter::filteredEventIdentifiers.insert(ei);
                    ++p;
                }
            }
        }
        else if (strcmp(tempString.c_str(), "filteredImageFile") == 0) {
            while (getline(filterFile, tempString) && tempString != "") {
                //modulesName2APIs.insert(std::map <std::string, std::set<std::string> >::value_type(tempString, std::set<std::string>()));
            }
        }
        else {
            // TODO report error

            MyLogger::writeLog("filter.txt format error!");
        }
    }

    MyLogger::writeLog("initFilter succeed!");
}

/*
    initialize each process loaded modules with std::set<Module*, ModuleSortCriterion>().
    update lately in the ImageEvent.parse()
*/
void Initializer::initProcessID2ModulesMap() {

    if (EventProcess::processID2Name.empty()) {
        MyLogger::writeLog("initProcessID2ModulesMap -->processID2Name");
        exit(-1);
    }

    auto iter = EventProcess::processID2Name.begin();
    auto end = EventProcess::processID2Name.end();

    //initialize processID2ModulesMap structure with processID2Name which is initilized before. Initialize each item'value a empty set.
    for (iter; iter != end; ++iter) {
        EventImage::processID2Modules.insert(
                //std::map<int, std::set<Module*, ModuleSortCriterion> >::value_type(iter->first, std::set<Module*, ModuleSortCriterion>())
                iter->first, std::set<Module*, ModuleSortCriterion>()
        );

        /*
        initialize processID2ModuleAddressPair structure with processID2Name which is initilized before.
        Initialize each item'value a default minmaxAddress pair.
         */
        //EventProcess::processID2ModuleAddressPair.insert(std::map<int, EventProcess::MinMaxModuleAddressPair>::
        //    value_type(iter->first, std::make_pair(EventProcess::initMinAddress,EventProcess::initMaxAddress)));


        EventProcess::processID2ModuleAddressPair.insert(
                iter->first, std::make_pair(EventProcess::initMinAddress, EventProcess::initMaxAddress));
//        EventProcess::processID2ModuleAddressPair.insert(
//                iter->first, std::make_pair(EventProcess::initMaxAddress, EventProcess::initMinAddress));
    }

}
void Initializer::initImages(std::string confFile) {

    std::cout << "------Begin to parse images------" << std::endl;

    std::vector<std::string> unLoadedImages;
    std::ifstream myfile(confFile);
    std::string currentImage = "";
    STATUS status = STATUS_FAIL;
    bool existUnloadedImage = false;

    if (!myfile.is_open()) {
        MyLogger::writeLog("file initImages open failed!");
        std::exit(-1);
    }
    while (getline(myfile, currentImage) && currentImage != "") {
        //images.insert(tempString);

        std::set<MyAPI*, MyAPISortCriterion> apis;

        //   imageFile
        Filter::filteredImageFile.insert(currentImage);

        status = EventImage::getAPIsFromFile(currentImage, apis);

        if (status == STATUS_SUCCESS) {
            //std::cout << currentImage << "  " << apis.size() << std::endl;
            EventImage::modulesName2APIs.insert(
                    std::map <std::string, std::set<MyAPI*, MyAPISortCriterion> >::value_type(currentImage, apis)
                    //currentImage, apis
            );
        }
        else {
            unLoadedImages.push_back(currentImage);
            existUnloadedImage = true;
        }
    }
    std::cout << "------Parse images end...------" << std::endl;

    if (existUnloadedImage) {

        std::cout << "The following images loaded failed  " << std::endl;

        for (auto ss : unLoadedImages) {
            std::cout << ss << std::endl;
        }
    }
}

/*
    initialize EventIdentiier map with correlated properties
*/
void Initializer::initEventPropertiesMap(std::string confFile) {

//    std::string propertyName;
//    std::string tempString = "";
    std::set <EventIdentifier*> tempEventIdentifierSet;
    std::list<BaseEvent::PropertyInfo> tempList;
    BaseEvent::PropertyInfo propertyInfo;
    //std::vector<std::wstring> testPropertyIndex;

    tinyxml2::XMLDocument doc;
    int res = doc.LoadFile(confFile.c_str()); //load xml file
    if(res!=0){
        cout<<"load xml file failed"<<endl;
        return;
    }

    EventIdentifier* ei;
    XMLElement* root = doc.RootElement();
    XMLElement* evnt = root->FirstChildElement("Event");
    while(evnt!= nullptr){
        XMLElement* opCodeElement = evnt->FirstChildElement("OpCode");
        XMLElement* providerIDElement = evnt->FirstChildElement("ProviderID");
        XMLElement* eventNameElement = evnt->FirstChildElement("EventName");
        XMLElement* attributesElement = evnt->FirstChildElement("Attributes");

        int opCode = opCodeElement->Int64Text();
        const char *pidstring = providerIDElement->GetText();
        ULONG64 providerID = Tools::String2ULONG64(providerIDElement->GetText());
        const char *eventName = eventNameElement->GetText();
        ei = new EventIdentifier(providerID , opCode, eventName);

//        BaseEvent::eventProviderID2Opcodes[providerID].insert(ei);
//        tempEventIdentifierSet.insert(ei);

        XMLElement * attrElement = attributesElement->FirstChildElement("Attribute");

        while(attrElement!=nullptr){        //get attributes of current event

            const char *attrName = attrElement->GetText();
            int type = attrElement->Int64Attribute("type");

            if (BaseEvent::propertyNameSet.find(attrName) == BaseEvent::propertyNameSet.end()) {
                BaseEvent::propertyNameVector.push_back(attrName);
                BaseEvent::propertyNameSet.insert(attrName);
                //BaseEvent::propertyName2IndexMap.insert()
            }

            propertyInfo = make_pair(attrName, type);
            tempList.push_back(propertyInfo);
            attrElement = attrElement->NextSiblingElement();
        }

        BaseEvent::eventIdentifierSet.insert(ei);
        BaseEvent::eventStructMap.insert(
                    std::map<EventIdentifier*, std::list<BaseEvent::PropertyInfo>, EventIdentifierSortCriterion>::value_type(ei, tempList));
        tempList.clear();

        evnt = evnt->NextSiblingElement();  //next sibling node
    }

//    for debug: get propertyIndex
//    for (auto item : BaseEvent::propertyNameVector) {
//        std::cout << item << ",";
//    }
//
}

/*
    initialize threadpool with 8 threads and a task queue of 10000000 capacity
*/
void Initializer::initPrasePool() {

    EventParser::parsePools = new ThreadPool(4, 1000000);
    //EventParser::parsePools = new ThreadPool(1, 50000);
}
void Initializer::initOutputThread() {

    std::thread outputThread(&Output::outputStrings, EventParser::op);
    outputThread.detach();
}

void Initializer::initThreadParseProviders() {

    EventParser::threadParseProviders.insert(TcpIpProvider);
    EventParser::threadParseProviders.insert(DiskProvider);
    {
//        EventParser::threadParseProviders.insert(CallStackProvider);
        EventParser::threadParseProviders.insert(RegistryProvider);
//        std::cout << "parse registry events in thread" << std::endl;
    }
//    EventParser::threadParseProviders.insert(ProviderImage);
    EventParser::threadParseFlag = true;
}

//initialize structure of Processor2ThreadAndThread2Process, which is used in function setPidAndTid() to fix threadId and processId
void Initializer::initProcessor2ThreadAndThread2Process(){

    for(int i = 0 ; i<MAX_PROCESSOR_NUM; i++)
        EventThread::processorId2threadId[i] = INIT_THREAD_ID;

    for(int i = 0 ; i<MAX_THREAD_NUM; i++)
        EventThread::threadId2processId[i] = INIT_PROCESS_ID;

    for(int i = 0 ; i<EventProcess::ProcessNumSize; i++)
        EventProcess::processID2ParentProcessID[i] = -1;
}

STATUS Initializer::initThreadProcessMap() {

    STATUS status = STATUS_SUCCESS;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(te32);
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (hThreadSnap == INVALID_HANDLE_VALUE){
        MyLogger::writeLog("CreateToolhelp32Snapshot of thread failed.\n");
        status = STATUS_FAIL;

    }else{
        BOOL tMore = Thread32First(hThreadSnap, &te32);

        while (tMore) {
            //ReadWriteMap will OverWrite the item if the key is exist.
            //EventThread::threadId2processId.insert(te32.th32ThreadID, pid);
            EventThread::threadId2processId[te32.th32ThreadID] = te32.th32OwnerProcessID;

//            std::cout<<te32.th32ThreadID<<","<<te32.th32OwnerProcessID<<std::endl;
            EventThread::threadSet.insert(te32.th32ThreadID);
            tMore = Thread32Next(hThreadSnap, &te32);
        }
        CloseHandle(hThreadSnap);
    }

    return status;
}

STATUS Initializer:: InitProcessMap() {

    std::vector<int> parentProcessIDs = std::vector<int>();

    STATUS status = STATUS_SUCCESS;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);

    //get the snapshot current processes
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        printf("CreateToolhelp32Snapshot of process failed.\n");
        status = STATUS_FAIL;

    }else{
        std::cout << "------Begin to initialize datas of process and thread...------" << std::endl;

        //search first process infomation by snapshot got before
        BOOL bMore = Process32First(hProcessSnap, &pe32);
        while (bMore)
        {
            //printf("processName:%ls\n", pe32.szExeFile);
            //printf("processID:%u\n\n", pe32.th32ProcessID);
            if (pe32.th32ProcessID != 0) {		//skip pid=0, which is idle process
                EventProcess::processID2Name[pe32.th32ProcessID] = pe32.szExeFile;
                EventProcess::processID2ParentProcessID[pe32.th32ProcessID] = pe32.th32ParentProcessID;

//                parentProcessIDs.push_back(pe32.th32ParentProcessID);

                //EventProcess::processID2Name.insert(pe32.th32ProcessID,Tools::WString2String((LPCWSTR)pe32.szExeFile));
                //EventProcess::processIDSet.insert(pe32.th32ProcessID);

                //std::wcout << EventProcess::processID2Name[pe32.th32ProcessID] << std::endl;
            }

            //search next process infomation by snapshot got before
            bMore = Process32Next(hProcessSnap, &pe32);
        }

//        int len = parentProcessIDs.size();
//        for(int i = 0;i<len;i++){
//
//            int ppid = parentProcessIDs[i];
//            std::string ppname = EventProcess::processID2Name[ppid];
//            if(ppname.empty()){
//                //fill parentProcessName
//                std::string ppName = Tools::getProcessNameByPID(ppid);
//
//                EventProcess::processID2Name[ppid] = ppName;
////                std::cout<<"ppid:" << ppid <<"  ppName:"<< ppName <<std::endl;
//            }
//
//        }
        //set idle process mapping
        EventProcess::processID2Name[0] = "idle";
        EventProcess::processID2Name[INIT_PROCESS_ID] =  "Unknown" ;
        //EventProcess::processID2Name.insert(EventProcess::UnknownProcess, "Unknown" );
        //EventProcess::processID2Name.insert(0, "idle" );

        std::cout << "------Initialize datas of process and thread end...------" << std::endl;

        //release snapshot
        CloseHandle(hProcessSnap);
    }

    return status;
}

//TODO
void Initializer::initTerminalListening() {

}

void Initializer::initNeededStruct() {

    initOutputThread();
    initImages();       //1
    MyLogger::initLogger();
    Tools::initVolume2DiskMap();
    initProcessor2ThreadAndThread2Process();

    //initSysNameMap();
    //EventPerfInfo::initSystemCallMap();
    if (InitProcessMap() || initThreadProcessMap()) {
        std::cout << "------Initialize process and thread failed!------" << std::endl;
        exit(-1);
    }
    initEventPropertiesMap();       //2

    //default trace all events
    if(!enbaleFlagsInited){
        initDefaultEnabledEvents();
    }
    initEnabledEvent(userEnabledFlags);

    if(opThreashold == 0){
        initOutputThreashold(userEnabledFlags);
    }
    initFilter();       //3
    initProcessID2ModulesMap();
    initPrasePool();
    initThreadParseProviders();

    //set output threashold value, which depends on the event type we traced
    EventParser::op->setOutputThreashold(opThreashold);
//    std::cout<<EventParser::op->getOutputThreashold()<<std::endl;
//    initTerminalListening();
}

void Initializer::showCommandList() {

    std::string cmdList = "CommandLine Option Rules:\n";
    cmdList.append("-e , the event type you want to trace\n");
    cmdList.append("\targuments details:\n"
                   "\t\t0x1(PROCESS)\n"
                   "\t\t0x2(THREAD)\n"
                   "\t\t0x4(IMAGE)\n"
                   "\t\t0x8(FILE)\n"
                   "\t\t0x10(DISK)\n"
                   "\t\t0x20(REGISTRY)\n"
//                   "\t\t0x40(SYSTEMCALL)\n"
                   "\t\t0x40(CALLSTACK)\n"
                   "\t\t0x80(TCPIP)\n"
                   "\t\tall(tracing all event types)\n"
                   "\tusage:-e 0x11 ,which will trace events of Process and Disk.\n"
                   "\tusage:-e 0xff ,which will trace all events except callstack, if you don't need API Info, you should specify 0xff to '-e' option.\n"
                   "\tusage:-e all  ,which will trace all events.\n"
    );
    cmdList.append("-f , the file path that you want to output the events\n"
                   "\tusage: c:\\123.txt ,which will output events to file c:\\123.txt\n");
    cmdList.append("-c , output events to the console \n");
    cmdList.append("-k , output events to the kafka server, \n"
                   "\tusage: 192.168.1.2:9092/test ,which will output events to server which address is 192.168.1.2:9092 and topic is \"test\"\n");
    cmdList.append("-s , the socket that you want to transmission events\n"
                   "\tusage: 192.168.1.2:66 ,which will output events to host which address is 192.168.1.2 \n");
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

ULONG64 Initializer::init() {

    STATUS status = 0;
    int i = 1;
    char* currentArv = nullptr;
//    string errorMsg = "";

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

            if (!validArgLength(i, status))   break;
//            std::cout<<strcmp(argV[i++],"all")<<std::endl;
            std::string arg = argV[i++];
            userEnabledFlags = strcmp(arg.c_str(),"all") == 0? 0x1ff:Tools::HexStr2DecInt(arg);

            if(status == STATUS_SUCCESS)    enbaleFlagsInited = true;
        }
        else if (strcmp(currentArv, "--outputThreshold") == 0) {

            std::string threshold = argV[i++];
            opThreashold = Tools::String2ULONG64(threshold);
            status = STATUS_SUCCESS;
        }
        else if (strcmp(currentArv, "-h") == 0) {

            status = STATUS_SHOW_MANUAL;
        }
        else {
            status = isOutPutOption(currentArv) ? STATUS_DUPLICATE_OUTPUT : STATUS_UNKNOWN_OPTION;
        }

        if (status != STATUS_SUCCESS)   break;
    }

    if (status == STATUS_SUCCESS && outputInited) {
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

    //ULONG enabledFlags = initEnabledEvent(a);
    //initOutPut(a);

    return enabledFlags;
}


BOOLEAN Initializer::InitSymHandler()
{
    HANDLE hfile;
    char Path[MAX_PATH] = { 0 };
    char SymSrvPath[MAX_PATH] = { 0 };
    char FileName[MAX_PATH] = { 0 };
    char SymPath[MAX_PATH * 2] = { 0 };
    char* SymbolsUrl = (char*)"http://msdl.microsoft.com/download/symbols";

    if (!GetCurrentDirectoryA(MAX_PATH, Path))
    {
        printf("cannot get current directory \n");
        return FALSE;
    }

    strcat(SymSrvPath, Path);
    strcat(SymSrvPath, "\\symsrv.dll");

    if (CopyFile(reinterpret_cast<LPCSTR>(Tools::StringToWString(SymSrvPath).c_str()),
                 reinterpret_cast<LPCSTR>(L"c:\\Windows\\System32\\symsrv.dll"), true)) {
        MyLogger::writeLog("symsrv.dll loading error");
        exit(-1);
    }

    strcat(Path, "\\Symbols");
    CreateDirectoryA(Path, NULL);

    strcpy(FileName, Path);
    strcat(FileName, "\\symsrv.yes");

    //printf("%s \n", FileName);

    hfile = CreateFileA(FileName,
                        FILE_ALL_ACCESS,
                        FILE_SHARE_READ,
                        NULL,
                        OPEN_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);

    if (hfile == INVALID_HANDLE_VALUE)
    {
        printf("create or open file error: 0x%X \n", GetLastError());
        return FALSE;

    }
    CloseHandle(hfile);

    //Sleep(3000);

    hProcess = GetCurrentProcess();

    SymSetOptions(SYMOPT_CASE_INSENSITIVE | SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);

    SymSetSearchPath(hProcess, Path);

    //SRV*d:\localsymbols*http://msdl.microsoft.com/download/symbols
    sprintf(SymPath, "SRV*%s*%s", Path, SymbolsUrl);

    //printf("%s\n", SymPath);
    if (!SymInitialize(hProcess,
                       SymPath,
                       TRUE))
    {
        printf("SymInitialize failed %d \n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

ULONG Initializer::GetKernelInfo(char* lpKernelName, ULONG* ulBase, ULONG* ulSize)
{
    DWORD    dwsize;
    DWORD    dwSizeReturn;
    PUCHAR    pBuffer = nullptr;

    PMODULES    pSmi = nullptr;
    NTSTATUS    ntStatus = STATUS_UNSUCCESSFUL;

    //NtQuerySystemInformation
    PRTL_PROCESS_MODULES sysModuleInfo = { 0 };
    HMODULE hNtDll = nullptr;
    DWORD   dwNumberBytes;
    DWORD   dwReturnLength;

    ULONG retlen = 2;
    NTSTATUS status = STATUS_SUCCESS;
    HLOCAL hMem = nullptr;

    NTQUERYSYSTEMINFORMATION NtQuerySystemInformation;
    __try
    {
        hNtDll = LoadLibrary(reinterpret_cast<LPCSTR>(L"NtDll.dll"));
        if (hNtDll == nullptr)
        {
            printf("LoadLibrary Error: %d\n", GetLastError());
            __leave;
        }

        //  ȡ    ָ
        NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(hNtDll, "NtQuerySystemInformation");

        if (NtQuerySystemInformation == nullptr)
        {
            printf("GetProcAddress for NtQuerySystemInformation Error: %d\n", GetLastError());
            __leave;
        }

        status = NtQuerySystemInformation(SystemModuleInformation, &status, sizeof(status), &retlen);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            do
            {
                hMem = LocalAlloc(0, retlen);
                if (hMem)
                {
                    sysModuleInfo = (PRTL_PROCESS_MODULES)LocalLock(hMem);
                    if (sysModuleInfo)
                    {
                        memset(sysModuleInfo, 0, retlen);
                        status = NtQuerySystemInformation(SystemModuleInformation, sysModuleInfo, retlen, &retlen);
                        if (status == 0)    break;
                    }
                    LocalFree(hMem);
                }
            } while (status == STATUS_INFO_LENGTH_MISMATCH);
        }

        if (status != STATUS_SUCCESS)
        {
            printf("NtQuerySystemInformation for SystemModuleInfomation Error: %d\n", GetLastError());
            __leave;
        }
        for (int i = 0; i < sysModuleInfo->NumberOfModules; ++i)
        {
            //printf("imagename: %s\n", sysModuleInfo->Modules[i].FullPathName);
            int idx = -1;
            LL tmpModuleBaseAddr = -1;
            LL low32 = -1;
            if (_stricmp(sysModuleInfo->Modules[i].FullPathName, lpKernelName) == 0)
            {
                //printf("found %08X %X\,,%s,,,r\n", pSmi->smi[i].Base, pSmi->smi[i].Size, pSmi->smi[i].ImageName);
                tmpModuleBaseAddr = (LL)sysModuleInfo->Modules[i].ImageBase;
                low32 = (tmpModuleBaseAddr & 0xffffffff);

                *ulBase = low32;
                *ulSize = (LL)sysModuleInfo->Modules[i].ImageSize;
                break;
            }

        }
    }
    __finally
    {
        if (hNtDll != nullptr)
        {
            FreeLibrary(hNtDll);
        }
    }
    return TRUE;
}

BOOLEAN Initializer::LoadSymModule(
        char* ImageName,
        DWORD ModuleBase)
{
    DWORD64 tmp;
    //char    SymFileName[MAX_PATH] = { 0 };
    char    SymFileName[MAX_PATH];
    BOOL bRetOK = FALSE;

    HINSTANCE hmod = LoadLibraryA("Imagehlp.dll");
    if (!hmod)
        return FALSE;

    pImageLoad = (IMAGELOAD)GetProcAddress(hmod, "ImageLoad");
    pImageUnload = (IMAGEUNLOAD)GetProcAddress(hmod, "ImageUnload");
    if (!pImageLoad ||
        !pImageUnload)
        return FALSE;

    pli = pImageLoad(ImageName, NULL);
    if (pli == nullptr)
    {
        printf("cannot get loaded module of %s \n", ImageName);
        return FALSE;
    }
    //printf("ModuleName:%s:%08x\n", pli->ModuleName, pli->SizeOfImage);

    HINSTANCE hDbgHelp = LoadLibraryA("dbghelp.dll");
    if (!hDbgHelp)
        return FALSE;

    pSymGetSymbolFile = (SYMGETSYMBOLFILE)GetProcAddress(hDbgHelp, "SymGetSymbolFile");
    if (!pSymGetSymbolFile) {
//        printf("pSymGetSymbolFile() failed %d\r\n", pSymGetSymbolFile);
        std::cout<<"pSymGetSymbolFile() failed %d"<< pSymGetSymbolFile<<std::endl;
        return FALSE;
    }

    std::cout << "loading  "<< ImageName << " success "<< std::endl;

    //Second parameter indicates the symbol path  NULL indicates uses the symbol path set using the SymInitialize or SymSetSearchPath function.
    if (pSymGetSymbolFile(hProcess,
                          NULL,
                          pli->ModuleName,
                          sfPdb,
                          SymFileName,
                          MAX_PATH,
                          SymFileName,
                          MAX_PATH))
    {
        std::cout << ImageName <<std::endl;

        tmp = SymLoadModule64(hProcess,
                              pli->hFile,
                              pli->ModuleName,
                              NULL,
                              (DWORD64)ModuleBase,
                              pli->SizeOfImage);
        if (tmp)
        {
            bRetOK = TRUE;
        }
    }
    pImageUnload(pli);
    return bRetOK;
}

BOOLEAN Initializer::EnumSyms(
        char* ImageName,
        DWORD ModuleBase,
        PSYM_ENUMERATESYMBOLS_CALLBACK EnumRoutine,
        PVOID Context)
{
    BOOLEAN bEnum;

    if (!LoadSymModule(ImageName, ModuleBase))
    {
        printf("cannot load symbols ,error: %d \n", GetLastError());
        return FALSE;
    }
    //
    bEnum = SymEnumSymbols(hProcess,
                           ModuleBase,
                           NULL,
                           EnumRoutine,
                           Context);
    if (!bEnum)
    {
        printf("cannot enum symbols ,error: %d \n", GetLastError());
    }
    return bEnum;
}


BOOLEAN CALLBACK Initializer::EnumSymRoutine(
        PSYMBOL_INFO psi,
        ULONG     SymSize,
        PVOID     Context)
{
    ULONG64 temp = psi->Flags & SYMFLAG_FUNCTION;

    EventPerfInfo::systemCallMap[(ULONG64)psi->Address] = new std::string(psi->Name);
    //printf("%s : 0x%x\n", psi->Name, (ULONG)psi->Address);
    return TRUE;
}

VOID Initializer::initSysNameMap() {

    ULONG ulBase = 1;
    ULONG ulSize = 1;
    int x = sizeof(parseFiles) / sizeof(parseFiles[0]);
    if (InitSymHandler()) {
        //GetKernelInfo  ȡimagebase  imagesize
        while (x-- > 0) {
            if (GetKernelInfo((char*)parseFiles[x].c_str(), &ulBase, &ulSize)) {

                FuncAddressInfo = (PWIN32KFUNCINFO)VirtualAlloc(0, (sizeof(WIN32KFUNCINFO) + sizeof(KERNELFUNC_ADDRESS_INFORMATION)) * 10, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                if (FuncAddressInfo)
                {
                    memset(FuncAddressInfo, 0, (sizeof(WIN32KFUNCINFO) + sizeof(KERNELFUNC_ADDRESS_INFORMATION)) * 10);
                    Tools::convertFileNameInDiskFormat(parseFiles[x]);
                    std::string fileName = parseFiles[x];
                    EnumSyms((char*)fileName.c_str(), ulBase, (PSYM_ENUMERATESYMBOLS_CALLBACK)EnumSymRoutine, NULL);
                }
            }
        }
        SymUnloadModule64(GetCurrentProcess(), ulBase);

        //
        SymCleanup(GetCurrentProcess());
    }

    //std::ofstream outs("c://systemCallmap.txt", std::ios::app);
    //for (std::map< ULONG64, std::wstring>::iterator iter = EventPerfInfo::systemCallMap .begin();
    //    iter != EventPerfInfo::systemCallMap.end(); ++iter) {
    //    //outs << std::hex << iter->first << " : " << Tools::WString2String(iter->second.c_str()) << std::endl;
    //
    //    //std::cout << Tools::DecInt2HexStr(iter->first) << " : " <<Tools::WString2String(iter->second.c_str()) << std::endl;
    //    //std::cout << iter->first << " : " << iter->second << std::endl;
    //    //iter++;
    //}
}