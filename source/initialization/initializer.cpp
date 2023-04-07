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
int EventThread::threadId2processId[MAX_THREAD_NUM];

STATUS Initializer::initEnabledEvent(ULONG64 eventType) {

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

    std::ifstream filterFile(filterFileName);
    std::string tempString = "";

    if (!filterFile.is_open()) {
        MyLogger::writeLog("filter.txt open failed!");
        exit(-1);
    }

    std::regex re(" ");
    std::sregex_token_iterator p;
    std::sregex_token_iterator end;

    //set the filtered processIDs, kellect will not parse events with these IDs.
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
        //set parsed events.
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
        //set filtered image events.
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
    for (; iter != end; ++iter) {
        EventImage::processID2Modules.insert(
                iter->first, std::set<Module*, ModuleSortCriterion>()
        );

        /*
        initialize processID2ModuleAddressPair structure with processID2Name which is initilized before.
        Initialize each item'value a default minmaxAddress pair.
         */
        EventProcess::processID2ModuleAddressPair.insert(
                iter->first, std::make_pair(EventProcess::initMinAddress, EventProcess::initMaxAddress));
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

    //parse the system modules‘APIs
    while (getline(myfile, currentImage) && currentImage != "") {
        std::set<MyAPI*, MyAPISortCriterion> apis;

        //   imageFile
        Filter::filteredImageFile.insert(currentImage);

        status = EventImage::getAPIsFromFile(currentImage, apis);

        if (status == STATUS_SUCCESS) {
            EventImage::modulesName2APIs.insert(
                    std::map <std::string, std::set<MyAPI*, MyAPISortCriterion> >::value_type(currentImage, apis)
            );
        }
        else {
            unLoadedImages.push_back(currentImage);
            existUnloadedImage = true;
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
    ifstream infile("config/propertyName.txt",ios::in);
    std::regex re(",");
    std::sregex_token_iterator p;
    std::sregex_token_iterator end;
    std::string tempString;

    if (!infile.is_open())
    {
        cout << "read file 'config/propertyName.txt' failed..." << endl;
        return;
    }
    if (getline(infile, tempString) && tempString != "") {

        p = std::sregex_token_iterator(tempString.begin(), tempString.end(), re, -1);

        while (p != end) {
            BaseEvent::propertyNameVector.push_back(*p);
            ++p;
        }
    }
    infile.close();

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

    EventParser::threadParseProviders.insert(TcpIpGuid.Data1);
    EventParser::threadParseProviders.insert(DiskIoGuid.Data1);
    {
//        EventParser::threadParseProviders.insert(CallStackGuid.Data1);
        EventParser::threadParseProviders.insert(RegistryGuid.Data1);
    }
//    EventParser::threadParseProviders.insert(ImageLoadGuid.Data1);
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

        //search first process information by snapshot got before
        BOOL bMore = Process32First(hProcessSnap, &pe32);
        while (bMore)
        {
            if (pe32.th32ProcessID != 0) {		//skip pid=0, which is idle process
                EventProcess::processID2Name[pe32.th32ProcessID] = pe32.szExeFile;
                EventProcess::processID2ParentProcessID[pe32.th32ProcessID] = pe32.th32ParentProcessID;
            }

            //search next process infomation by snapshot got before
            bMore = Process32Next(hProcessSnap, &pe32);
        }

        //set idle process mapping
        EventProcess::processID2Name[0] = "idle";
        EventProcess::processID2Name[INIT_PROCESS_ID] =  "Unknown" ;

        std::cout << "------Initialize datas of process and thread end...------" << std::endl;

        //release snapshot
        CloseHandle(hProcessSnap);
    }

    return status;
}

void Initializer::writeUUID2File(){

    ofstream fout;
    fout.open(uuidFile);

    fout<<getUUID();
    fout.close();
}

STATUS Initializer::setUUIDFromFile(){

    ifstream infile;
    infile.open(uuidFile, ios::in);
    if (!infile.is_open())
    {
//        cout << "Read uuid File failed,set uuid now." << endl;
        return STATUS_FAIL;
    }
    //第一种读取方法，
    char buf[1024] = { 0 };
    while (infile>>buf)
    {
        setUUID(buf);
        break;
    }

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

    initOutputThread();
    initImages();       //1
    MyLogger::initLogger();
    Tools::initVolume2DiskMap();
    initProcessor2ThreadAndThread2Process();

    if (InitProcessMap() || initThreadProcessMap()) {
        std::cout << "------Initialize process and thread failed!------" << std::endl;
        exit(-1);
    }
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
    initProcessID2ModulesMap();
    initPrasePool();
    initThreadParseProviders();
    initHostUUID();

    //set output threashold value, which depends on the event types we want to trace
    EventParser::op->setOutputThreashold(opThreashold);
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

ULONG64 Initializer::init() {

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

    return enabledFlags;
}