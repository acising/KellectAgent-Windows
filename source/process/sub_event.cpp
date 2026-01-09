#include "tools/logger.h"
#include "tools/tools.h"
#include "process/sub_event.h"
#include <fstream>
#include <regex>
#include <algorithm>
#include <codecvt>
#include <atlconv.h>
#include "nlohmann/json.hpp"
#include "filter.h"
//#include "process/etw_config.h"
#include "process/event_parse.h"
#include "tools/providerInfo.h"

ReadWriteMap<ULONG64,std::string> EventRegistry::keyHandle2KeyName;
std::map< ULONG64, std::string*> EventPerfInfo::systemCallMap;
std::map< ULONG64, std::string*> EventPerfInfo::systemCallMapUsed;
std::set<ULONG64> EventThread::threadSet;
std::set <Module*, ModuleSortCriterion> EventImage::globalModuleSet;
std::set <Module*, ModuleSortCriterion> EventImage::usedModuleSet;
ReadWriteMap<int, EventProcess::MinMaxModuleAddressPair> EventProcess::processID2ModuleAddressPair;
std::map<CallStackIdentifier, std::string*> EventCallstack::callStackRecord;
std::atomic<int> EventCallstack::callStackRecordNum(0);
std::map<int, int> EventProcess::processID2ParentProcessID;
std::map<std::string, std::string> processList;
std::map<std::string, std::string> fileList;
std::map<std::string, std::string> registryList;
std::map<std::string, std::string> socketList;
std::set<std::string> noEventList;
std::string Initializer::uuid;  //declare static property
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
            // if not match any filename , filter it
            ev->setValueableEvent(false);
        }
	}
}
void EventFile::parse() {

    dataType* dt = getProperty(FileObject);
	ULONG64 fileObject = 1;

	if (dt) {
		fileObject = dt->getULONG64();
	}

	switch (getEventIdentifier()->getOpCode()) {

	case NOTDEFINEDTYPE1:
	case NOTDEFINEDTYPE2:
		return;
	case RUNDOWN:
	case NAME:
	case FILECREATE: {

        setTIDAndPID(this);

        removeQuotesFromProperty(FileName);

		//ReadWriteMap will OverWrite the item if the key is exist.
		//fileKey2Name.insertOverwirte(fileObject, fileName);
		fileKey2Name[fileObject] =getProperty(FileName)->getString();

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
		fileObject2Name[fileObject] = getProperty(OpenPath)->getString();

		break;
	}
	case DIRENUM:
	case NOTIFY: {
        // do nothing in directory enumeration and directory notification events

        removeQuotesFromProperty(FileName);

        //To be verified
        std::string fileName = getProperty(FileName)->getString();
        ULONG64 fileKey = getProperty(FileKey)->getULONG64();
        fileKey2Name[fileKey] = fileName;

        if(fileObject!= 1)
            fileObject2Name[fileObject] = fileName;

		break;
	}
	case CLEANUP:{
//        ULONG64 fileKey = getProperty(FileKey)->getULONG64();
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
		ULONG64 fileKey = getProperty(FileKey)->getULONG64();
		setFileName(this);

		fileObject2Name.erase(fileObject);
		fileKey2Name.erase(fileKey);
		break;
	}
	default:
		setValueableEvent(false);
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

		pid = getProperty(ProcessId)->getULONG64();
		tid = getProperty(TThreadId)->getULONG64();

		//threadId2processId.insert(tid, pid);
		threadId2processId[tid] = pid;

		break;
	}
	case THREADEND:
	case THREADDCEND: {

		pid = getProperty(ProcessId)->getULONG64();
		tid = getProperty(TThreadId)->getULONG64();

        //assume default id is 0
		threadId2processId[tid] = 0;
		break;
	}
	case CSWITCH: {
		//processorId2threadId.insert(getProcessorID(), getProperty(NewThreadId)->getULONG64());
        //set the newTID with processorID
		processorId2threadId[getProcessorID()] = getProperty(NewThreadId)->getULONG64();
	}
	default: {
		setValueableEvent(false);	//filter cswitch
		break;
	}
	}

	if (isValueableEvent()) {

		setProcessID(pid);
		setThreadID(tid);

        fillProcessInfo(); //fill parentProcess and process Information
	}
}

STATUS EventImage::getExportAPIs(LPVOID hModule, std::string& fileName, std::set<MyAPI*, MyAPISortCriterion>& apis) {
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;//指向导出目录结构。
	PIMAGE_DOS_HEADER pDosHeader;//指向 DOS 头部结构。
	PIMAGE_NT_HEADERS pNtHeader;//指向 NT 头部结构。
	PIMAGE_SECTION_HEADER pSecHeader;
	PDWORD pAddressName;//指向导出函数名称
	PWORD pAddressOfNameOrdinals;//指向导出函数序号
	PDWORD pAddresOfFunction;//指向导出函数地址
	std::set<MyAPI> tempAPIs;
    PCHAR pApi;
    DWORD rva;
	pDosHeader = (PIMAGE_DOS_HEADER)hModule;//将 hModule 转换为 DOS 头指针，并检查其魔数是否为 IMAGE_DOS_SIGNATURE。如果不匹配，记录日志并返回失败状态。
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		MyLogger::writeLog("Not PE file-2");
		return STATUS_FAILED;
	}

	//get the PIMAGE_NT_HEADERS structure
	pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDosHeader->e_lfanew);//获取 NT 头部，验证其签名是否为 IMAGE_NT_SIGNATURE。如果不匹配，记录日志并返回失败状态。

	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		MyLogger::writeLog("Not PE file-2");
		return STATUS_FAILED;
	}
	if (pNtHeader->FileHeader.Machine == 0x014c) {
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(((PIMAGE_NT_HEADERS32)pNtHeader)->OptionalHeader.DataDirectory[0].VirtualAddress + (PBYTE)hModule);
	}//查文件的机器类型（32位或64位），并根据类型计算导出目录的地址。
	else {
        //AMD64 machine architecture
        pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(((PIMAGE_NT_HEADERS64)((PBYTE)hModule + pDosHeader->e_lfanew))->
                OptionalHeader.DataDirectory[0].VirtualAddress + (PBYTE)hModule);
    }
    pAddressName = (PDWORD)((PBYTE)hModule + pExportDirectory->AddressOfNames);
    pAddressOfNameOrdinals = (PWORD)((PBYTE)hModule + pExportDirectory->AddressOfNameOrdinals);
    pAddresOfFunction = (PDWORD)((PBYTE)hModule + pExportDirectory->AddressOfFunctions);//根据导出目录的字段获取指向名称、序号和函数地址的指针。

    if (pExportDirectory->AddressOfFunctions + pExportDirectory->AddressOfNames == 0 || pExportDirectory->NumberOfNames == 0) {
		return STATUS_FAILED;
	}//检查导出函数地址和名称的有效性。如果无效，返回失败状态。
	//parse export table
	for (DWORD i = 0; i < (pExportDirectory->NumberOfNames); ++i) {

        pApi = (PCHAR)((PBYTE)hModule + *pAddressName);
		++pAddressName;
		rva = pAddresOfFunction[*pAddressOfNameOrdinals];
		++pAddressOfNameOrdinals;
		//module.insertAPI(Tools::StringToWString(std::string(pFunc)), module.getAddressBegin() + rva);
		apis.insert(std::set<MyAPI*, MyAPISortCriterion>::value_type
		(new MyAPI(rva,pApi)));

	}
	return STATUS_SUCCESS;
}

STATUS EventImage::getAPIsFromFile(std::string& fileName, std::set<MyAPI*, MyAPISortCriterion>& apis) {
	
	HANDLE hFile = nullptr;
	HANDLE hMap = nullptr;
	LPVOID hBase = nullptr;
	STATUS status = STATUS_FAILED;

	hFile = CreateFileA(fileName.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		MyLogger::writeLog("Open file"+fileName+ " failed\n");
		MyLogger::writeLog("error code:" + Tools::DecInt2HexStr(GetLastError()));
		goto cleanup;
	}
	hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, 0);
	if (hMap == nullptr) {
		MyLogger::writeLog("hMap file failed:");
		goto cleanup;
	}
	hBase = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
	if (hBase == nullptr)
	{
		MyLogger::writeLog("MapViewOfFile failed-2: ");
		goto cleanup;
	}

	//current_module_name = moduleName;
	status = getExportAPIs(hBase,fileName, apis);
cleanup:
	CloseHandle(hFile);
	CloseHandle(hMap);
	UnmapViewOfFile(hBase);

	return status;
}

void  EventImage::parse() {

	ULONG64 baseAddress = getProperty(ImageBase)->getULONG64();
	ULONG64 moduleSize = getProperty(ImageSize)->getULONG64();
	ULONG64 processID = getProperty(ProcessId)->getULONG64();
	int opCode = getEventIdentifier()->getOpCode();

	std::string imageFileName = getProperty(FileName)->getString();

	setProcessID(processID);

    //filter pid
    if(Filter::pidFilter(processID)){
        setValueableEvent(false);
        return;
    }
    if(!Initializer::getListenCallStack()){
        if (Filter::filterImageFile(imageFileName)||Filter::secondFilter(this)) {
            setValueableEvent(false);
            return;
        }
    }

	//set process info
    fillProcessInfo(); //fill parentProcess and process Information

    if(imageFileName.find(".exe") != -1){   //won't parse ".exe" PE file
        return;
    }

	switch (opCode)
	{
	case IMAGEDCEND:
	case IMAGEUNLOAD: {

		Module tempModule = Module(baseAddress, baseAddress + moduleSize, imageFileName);

		//erase unloaded image in correlate process_module map. 
		processID2Modules.eraseValueItemWithKey(processID, &tempModule);

		//TODO : update the min and max module address of the exact process, skip this now.

		break;
	}
	case IMAGELOAD:
	case IMAGEDCSTART: {
		Module* module = new Module(baseAddress, baseAddress + moduleSize, imageFileName);

		int cnt = -1;
		cnt = processID2Modules.countValueNumWithKey(processID,module);

		if (cnt == 0 || cnt == -1) {	//there are no modules set mapping with the processID, so add the pid-modules item.

			auto globalModuleIter = globalModuleSet.find(module);

			//push unloaded image module to globalModuleSet
			if(globalModuleIter == globalModuleSet.end())	globalModuleSet.insert(module);		
			else {
				Module* tempModule = module;
				delete tempModule;		//avoid memory leak
						
				module = *globalModuleIter;			//if this image module has been stored into globalModuleSet, reuses it.
			}
			
            if (cnt == 0) {	// pid2moduleSet item exists,just update the item
				processID2Modules.insertValueItemWithKey(processID, module);

				//modify min and max module begin address to filter callstack addresses
				//the reason why do not get the reference pair here is for thread safe, in processEnd part ,there will be some erase operations.
				auto minmaxPair = EventProcess::processID2ModuleAddressPair[processID];	
				if (baseAddress < minmaxPair.first)	minmaxPair.first = baseAddress;
				if (baseAddress + moduleSize > minmaxPair.second)	minmaxPair.second = baseAddress + moduleSize;

				//reassign the updated pair
				EventProcess::processID2ModuleAddressPair.insertOverwirte(processID,minmaxPair);
			}
			else {	// pid2moduleset item not exists, so insert the item into processID2Modules .

				processID2Modules.insert(processID, std::set<Module*, ModuleSortCriterion>());
				
				processID2Modules.insertValueItemWithKey(processID, module);	//not overwrited

				EventProcess::processID2ModuleAddressPair.insert
				(processID, std::make_pair(baseAddress, baseAddress + moduleSize));
			}
            //===============================================================

            if(Filter::filteredImageFile.count(imageFileName) == 0){
//                std::cout<< processID <<" ,imageName:"<<imageFileName<<"  BaseAddress:"<< baseAddress<<std::endl;
                std::set<MyAPI*, MyAPISortCriterion> apis;
                Filter::filteredImageFile.insert(imageFileName);
                int status = EventImage::getAPIsFromFile(imageFileName, apis);

                if (status == STATUS_SUCCESS) {
                    //std::cout << currentImage << "  " << apis.size() << std::endl;
                    EventImage::modulesName2APIs.insert(
                            std::map <std::string, std::set<MyAPI*, MyAPISortCriterion> >::value_type(imageFileName, apis)
                    );
                }
            }
            //===============================================================
		}
		else	//find moduleSet mapping with the processID, do nothing.
		{
			delete module;
		}
			
		break;
	}
	default:
		break;
	}

}

//start tracing callstack configuration
void EventCallstack::initCallStackTracing(TRACEHANDLE &SessionHandle) {

    int idx = 0;
    CLASSIC_EVENT_ID callStackEvents[100]={};

    if(Filter::listenedEventsProviders.count(ProcessProvider)){
        callStackEvents[idx++] = { ProcessGuid, 1,{ 0 }};   //start
        callStackEvents[idx++] = { ProcessGuid, 2,{ 0 }};   //end
        callStackEvents[idx++] = { ProcessGuid, 3,{ 0 }};   //dcstart
        callStackEvents[idx++] = { ProcessGuid, 4,{ 0 }};   //dcend
    }
    if(Filter::listenedEventsProviders.count(FileProvider)){
        callStackEvents[idx++] = { FileGuid, 32,{ 0 }}; //filecreate
        callStackEvents[idx++] = { FileGuid, 35,{ 0 }}; //filedelete
        callStackEvents[idx++] = { FileGuid, 64,{ 0 }}; //create
        callStackEvents[idx++] = { FileGuid, 67,{ 0 }}; //read
        callStackEvents[idx++] = { FileGuid, 68,{ 0 }}; //write
        callStackEvents[idx++] = { FileGuid, 70,{ 0 }}; //delete
        callStackEvents[idx++] = { FileGuid, 72,{ 0 }}; //direnum
        callStackEvents[idx++] = { FileGuid, 73,{ 0 }}; //flush
        callStackEvents[idx++] = { FileGuid, 74,{ 0 }}; //Query
        callStackEvents[idx++] = { FileGuid, 75,{ 0 }}; // control
        callStackEvents[idx++] = { FileGuid, 71,{ 0 }}; //Rename
    }
    if(Filter::listenedEventsProviders.count(DiskProvider)){
        callStackEvents[idx++] = { DiskIoGuid, 11,{ 0 }}; //write
        callStackEvents[idx++] = { DiskIoGuid, 10,{ 0 }}; //read
    }
    if(Filter::listenedEventsProviders.count(ThreadProvider)){
        callStackEvents[idx++] = { ThreadGuid, 1,{ 0 }};    //  start
        callStackEvents[idx++] = { ThreadGuid, 2,{ 0 }};    //  end
        callStackEvents[idx++] = { ThreadGuid, 3,{ 0 }};    //  dcstart
        callStackEvents[idx++] = { ThreadGuid, 4,{ 0 }};    //  dcend
    }
    if(Filter::listenedEventsProviders.count(TcpIpProvider)){
        callStackEvents[idx++] = { TcpIpGuid, 10,{ 0 }};    //TcpIpSendIPV4
        callStackEvents[idx++] = { TcpIpGuid, 11,{ 0 }};    //TcpIpRecvIPV4
        callStackEvents[idx++] = { TcpIpGuid, 12,{ 0 }};    //TcpIpConnectIPV4
        callStackEvents[idx++] = { TcpIpGuid, 13,{ 0 }};    //TcpIpDisconnectIPV4
        callStackEvents[idx++] = { TcpIpGuid, 14,{ 0 }};    //TcpIpRetransmitIPV4
        callStackEvents[idx++] = { TcpIpGuid, 15,{ 0 }};    //TcpIpAcceptIPV4
        callStackEvents[idx++] = { TcpIpGuid, 16,{ 0 }};    //TcpIpReconnectIPV4
        callStackEvents[idx++] = { TcpIpGuid, 18,{ 0 }};    //TcpIpTCPCopyIPV4

        callStackEvents[idx++] = { TcpIpGuid, 26,{ 0 }};    //TcpIpSendIPV6
        callStackEvents[idx++] = { TcpIpGuid, 27,{ 0 }};    //TcpIpRecvIPV6
        callStackEvents[idx++] = { TcpIpGuid, 28,{ 0 }};    //TcpIpConnectIPV6
        callStackEvents[idx++] = { TcpIpGuid, 29,{ 0 }};    //TcpIpDisconnectIPV6
        callStackEvents[idx++] = { TcpIpGuid, 30,{ 0 }};    //TcpIpRetransmitIPV6
        callStackEvents[idx++] = { TcpIpGuid, 31,{ 0 }};    //TcpIpAcceptIPV6
        callStackEvents[idx++] = { TcpIpGuid, 32,{ 0 }};    //TcpIpReconnectIPV6
        callStackEvents[idx++] = { TcpIpGuid, 34,{ 0 }};    //TcpIpTCPCopyIPV6

    }
    if(Filter::listenedEventsProviders.count(ImageProvider)){
        callStackEvents[idx++] = { ImageLoadGuid, 10,{ 0 }};    //imagheload
        callStackEvents[idx++] = { ImageLoadGuid, 2,{ 0 }};    //imageunload
        callStackEvents[idx++] = { ImageLoadGuid, 3,{ 0 }};    //imagedcstart
        callStackEvents[idx++] = { ImageLoadGuid, 4,{ 0 }};    //imagedcend
    }
    if(Filter::listenedEventsProviders.count(RegistryProvider)){
        callStackEvents[idx++] = { RegistryGuid, 10,{ 0 }}; //RegistryCreate
        callStackEvents[idx++] = { RegistryGuid, 11,{ 0 }}; //RegistryOpen
        callStackEvents[idx++] = { RegistryGuid, 12,{ 0 }}; //RegistryDelete
        callStackEvents[idx++] = { RegistryGuid, 13,{ 0 }}; //RegistryQuery
        callStackEvents[idx++] = { RegistryGuid, 14,{ 0 }}; //RegistrySetValue
        callStackEvents[idx++] = { RegistryGuid, 15,{ 0 }}; //RegistryDeleteValue
        callStackEvents[idx++] = { RegistryGuid, 16,{ 0 }}; //RegistryQueryValue
        callStackEvents[idx++] = { RegistryGuid, 17,{ 0 }}; //RegistryEnumerateKey
        callStackEvents[idx++] = { RegistryGuid, 22,{ 0 }}; //RegistryKCBCreate
        callStackEvents[idx++] = { RegistryGuid, 23,{ 0 }}; //RegistryKCBDelete
        callStackEvents[idx++] = { RegistryGuid, 27,{ 0 }}; //RegistryClose
    }

	TraceSetInformation(SessionHandle, TraceStackTracingInfo, &callStackEvents, sizeof(callStackEvents));
}

void  EventCallstack::parse() {

 	int stackProcessID = getProcessID();
  	std::string* callInfo = nullptr;
	int callStackDepth = stackAddresses.size();

    fillProcessInfo(); //fill parentProcess and process Information

	if (callStackDepth>0) {		

        CallStackIdentifier tempCallStackIdentifier(callStackDepth, stackAddresses);
		auto rec = callStackRecord.find(tempCallStackIdentifier);
		if (rec != callStackRecord.end()) {			//this callstack has been parsed before and stored in callStackRecord, just reused it
			callInfo = rec->second;
		}
		else {
			auto moduleSet = EventImage::processID2Modules.find(stackProcessID);		//pass value, thread safe
			if (moduleSet != EventImage::processID2Modules.end() && moduleSet->second.size() != 0) {
                ULONG64 currentStackAddress;
                ULONG64 currentModuleBaseAddress;
                ULONG64 rvaStackAddress;
                std::string moduleName;
                Module tempStackAddressModule;
                MyAPI tempAPI;
                //MyAPI* targetAPI;
                std::set<MyAPI *, MyAPISortCriterion> apis;
                int stackIdx = 0;    //stacks index
                std::vector<std::string> calls;

                auto moduleSetEnd = moduleSet->second.end();
                auto apisEnd = EventImage::modulesName2APIs.end();

                //if (moduleSet->second.size() != 0){}
                while (stackIdx < callStackDepth) {

                    currentStackAddress = stackAddresses[stackIdx++];
                    tempStackAddressModule = Module(currentStackAddress);

                    //look up module in current process_moudle map, searched module must match the eauql: module.endAddr()>currentStackAddress>module.beginAddr
                    //auto targetModule = std::find_if(EventImage::usedModuleSet.begin(), EventImage::usedModuleSet.end(), EventCallstack::find_by_address(currentStackAddress));
                    //auto targetModule = std::find_if(moduleSet.begin(), moduleSet.end(), EventCallstack::find_by_address(currentStackAddress));

                    //find the first module which baseAddress larger than currentStackAddress
                    auto targetModuleIter = moduleSet->second.lower_bound(&tempStackAddressModule);
                    /*
                    get the target module.because the values of stackAdresses are all larger than the modules'set baseAddress,
                    so --targetModuleIter is valid.
                    */
                    if (targetModuleIter == moduleSetEnd ||--targetModuleIter == moduleSetEnd) continue;

                    moduleName = (*targetModuleIter)->getModuleName();      //get the target module name to fetch correlate apis.
                    currentModuleBaseAddress = (*targetModuleIter)->getAddressBegin();
                    //get apis
                    auto apisTarget = EventImage::modulesName2APIs.find(moduleName);

                    if (apisTarget != apisEnd && apisTarget->second.size() != 0) {
                        rvaStackAddress = currentStackAddress - currentModuleBaseAddress;
                        tempAPI = MyAPI(rvaStackAddress);

                        auto targetAPIIter = apisTarget->second.lower_bound(&tempAPI);

                        //in case targetAPIIter==apisTarget->second.begin(), so --targetAPIIter will be an end() and unreference it is invalid.
                        if (targetAPIIter == apisTarget->second.end() ||--targetAPIIter == apisTarget->second.end()) {
                            continue;
                        }

                        calls.push_back(moduleName + ":" + (*targetAPIIter)->getAPIName());
                        //calls.push_back(moduleName + ":" + (*targetAPIIter)->getAPIName() + ":" + std::to_string(rvaStackAddress));

                        //only parse top stack call
                        //break;
                    }
                }

				int i = 0;
				callInfo = new std::string();	//init callInfo
				for (auto c : calls) {
					if (i++ != 0)	callInfo->append(",");
					callInfo->append(c);
				}

				//record each callstackinfo which maybe reused later.
                //use priority_queue to dequeue callstack with low frequency used?
                if(callStackRecordNum.load()<2000){
                    callStackRecord[tempCallStackIdentifier] =callInfo;
                    callStackRecordNum.fetch_add(1);
                }else{
                    auto begin = callStackRecord.begin();
                    delete begin->second;

                    callStackRecord.erase(begin->first);
                    callStackRecord[tempCallStackIdentifier] =callInfo;
                    callStackRecordNum--;
                }

//                std::cout<<"addressSize:"<<stackAddresses.size()<<"callsSize:"<<calls.size() <<std::endl;
//				std::cout << *callInfo << std::endl << std::endl;
			}
        }

        if(callInfo == nullptr || callInfo->empty())   //TODO ,need to fix the problem, callstack maybe empty?
            setValueableEvent(false);
        else
            setProperty("stackInfo", new dataType(callInfo==nullptr?"NoInfo":*callInfo));

    }else
        setValueableEvent(false);

//    delete callInfo;
}

void  EventUnImportant::parse() {

	setValueableEvent(false);
	//MyLogger::writeLog("EventUnImportant parse successfully!");
}

void  EventProcess::parse() {

	ULONG64 pid = getProperty(ProcessId)->getULONG64();
	setProcessID(pid);

	switch (getEventIdentifier()->getOpCode())
	{
	case PROCESSSTART:
	case PROCESSDCSTART: {

        removeQuotesFromProperty(ImageFileName);
		// for both update and add value
		processID2Name[pid] = getProperty(ImageFileName)->getString();

		if (EventImage::processID2Modules.count(pid) == 0)  {

            //for readwritemap
			EventImage::processID2Modules.insert(pid, std::set<Module*, ModuleSortCriterion>());

			//record min and max module begin address to filter callstack addresses
            //for readwritemap
            EventProcess::processID2ModuleAddressPair.insert(pid, std::make_pair(initMinAddress, initMaxAddress));
		}

		break;
	}
	case PROCESSEND:
	case PROCESSDCEND: {

		// do not erase , for thread safe
		//processID2Name.erase(processID);

		//process end ,clear correlate modules set
		EventImage::processID2Modules.erase(pid);
		processID2ModuleAddressPair.erase(pid);
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
		ULONG64 ppid = getProperty(ParentId)->getULONG64();
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
            std::string keyName = getProperty(KeyName)->getString();
            ULONG64 keyHandle = getProperty(KeyHandle)->getULONG64();
            keyHandle2KeyName.insertOverwirte(keyHandle,keyName);
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

		ULONG64 sysCallAddress = getProperty(SysCallAddress)->getULONG64();
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
            pid = getProperty(PID)->getULONG64();
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
if (!event) return STATUS_FAIL;
std::string eventName = event->getEventIdentifier()->getEventName().c_str();
ULONG64 ProviderID = event->getEventIdentifier()->getProviderID();
int OpCode = event->getEventIdentifier()->getOpCode();
bool flag = false;
sJson->append(
        "{\"Event\":\"" + eventName +
        "\",\"PID\":" + std::to_string(event->getProcessID()) +
        ",\"PName\":\"" + event->getProcessName() +
        "\",\"PPID\":" + std::to_string(event->getParentProcessID()) +
        ",\"PPName\":\"" + event->getParentProcessName() +
        "\",\"TID\":" + std::to_string(event->getThreadID()) +
        ",\"TimeStamp\":" + std::to_string(event->getTimeStamp()) +
        ",\"Host-UUID\":" + Initializer::getUUID() +
        ",\"args\":{");

//event->getProperty
for (auto pty : event->getProperties()) {

    if (pty.second) {

        if (flag) {
            sJson->append(",");
        }

        flag = true;
        if (pty.second->getIsString()) {
            std::string argValue = pty.second->getString();
            sJson->append("\"" + pty.first + "\":\"" +
                          argValue + "\"");
        }
        else {
            sJson->append("\"" + pty.first + "\":" +
                          std::to_string(pty.second->getULONG64()));
        }
    }

    delete pty.second;		//delete properies
}

sJson->append("}}");
event->setPropertiesDeleted(true);	//set properies deleted true

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