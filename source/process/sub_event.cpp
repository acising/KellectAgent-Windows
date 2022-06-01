#include "tools/logger.h"
#include "tools/tools.h"
#include "process/sub_event.h"
#include <fstream>
#include <regex>
#include <algorithm>
#include "tools/json.hpp"
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
//ReadWriteMap<CallStackIdentifier, std::string*> EventCallstack::callStackRecord;
std::map<CallStackIdentifier, std::string*> EventCallstack::callStackRecord;
std::atomic<int> EventCallstack::callStackRecordNum(0);
int EventProcess::processID2ParentProcessID[ProcessNumSize];

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
	if (EventFile::fileKey2Name.count(fileKey) != 0 && fileKey !=0) {

		//tempDataType = new dataType(EventFile::fileKey2Name.getValue(fileKey));		//to avoid undefined behavior, because mutex needs before iterator.
		tempDataType = new dataType(EventFile::fileKey2Name[fileKey]);		//to avoid undefined behavior, because mutex needs before iterator.
		ev->setProperty(BaseEvent::FileName, tempDataType);
	}
	else {
		if (EventFile::fileObject2Name.count(fileObject) != 0 && fileObject != 0) {

			//tempDataType = new dataType(EventFile::fileObject2Name.getValue(fileObject));	//to avoid undefined behavior, because mutexe needs before iterator.
			tempDataType = new dataType(EventFile::fileObject2Name[fileObject]);	//to avoid undefined behavior, because mutexe needs before iterator.
			ev->setProperty(BaseEvent::FileName, tempDataType);
		}
		else {
			tempDataType = new dataType("UnknownFile");
			ev->setProperty(BaseEvent::FileName, tempDataType);
		}
	}
}
void EventFile::parse() {

	dataType* dt = getProperty(FileObject);
	ULONG64 fileObject;

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
        fileObject2Name[fileObject] = fileName;

//        std::cout<<getProperty(FileName)->getString()<<std::endl;
		break;
	}
	case CLEANUP:{
//        ULONG64 fileKey = getProperty(FileKey)->getULONG64();
        setFileName(this);
        break;
    }
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
			int threadId = tmp->getULONG64();
			setThreadID(threadId);

			if (EventThread::threadId2processId[threadId] != -1) {
				int pid = EventThread::threadId2processId[threadId];
				setProcessID(pid);
			}
		}

        //fill parentProcess Information
        fillProcessInfo();
	}
}

//some events need to revise tid and pid, return pid
int BaseEvent::setTIDAndPID(BaseEvent* ev) {

    int processorId = ev->getProcessorID();
    int threadId = EventThread::processorId2threadId[processorId];
    int processId = INIT_PROCESS_ID;

	if (threadId != INIT_THREAD_ID) {
        processId = EventThread::threadId2processId[threadId];

        //if there is no mapping of tid to pid , then call CreateToolhelp32Snapshot to enumerate all pids
		if (processId == INIT_PROCESS_ID) {
			processId = Tools::getProcessIDByTID(threadId);
			EventThread::threadId2processId[threadId]=processId;
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

	PIMAGE_EXPORT_DIRECTORY pExportDirectory;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;

	PIMAGE_SECTION_HEADER pSecHeader;
	PDWORD pAddressName;
	PWORD pAddressOfNameOrdinals;
	PDWORD pAddresOfFunction;
	std::set<MyAPI> tempAPIs;
    PCHAR pApi;
    DWORD rva;

	pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		MyLogger::writeLog("Not PE file-2");
		return STATUS_FAILED;
	}

	//get the PIMAGE_NT_HEADERS structure
	pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDosHeader->e_lfanew);
	//ULONG64 base = pNtHeader->OptionalHeader.ImageBase;
	//pSecHeader = (PIMAGE_SECTION_HEADER)((PBYTE)hModule + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		MyLogger::writeLog("Not PE file-2");
		return STATUS_FAILED;
	}
	if (pNtHeader->FileHeader.Machine == 0x014c) {
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(((PIMAGE_NT_HEADERS32)pNtHeader)->OptionalHeader.DataDirectory[0].VirtualAddress + (PBYTE)hModule);
	}
	else {
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress + (PBYTE)hModule);
	}

	pAddressName = PDWORD((PBYTE)hModule + pExportDirectory->AddressOfNames);
	pAddressOfNameOrdinals = (PWORD)((PBYTE)hModule + pExportDirectory->AddressOfNameOrdinals);
	pAddresOfFunction = (PDWORD)((PBYTE)hModule + pExportDirectory->AddressOfFunctions);

	if (pExportDirectory->AddressOfFunctions + pExportDirectory->AddressOfNames == 0 || pExportDirectory->NumberOfNames == 0) {
		//MyLogger::writeLog("imageFile: "+ Tools::WString2String(fileName.c_str()) +" have no apis");
		//return tempAPIs;
		return STATUS_FAILED;
	}

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
	//EventImage::modulesName2APIs.insert(std::map < std::wstring, std::set<MyAPI> >::value_type(fileName,retAPIsSet));
	//module_btree_map[moduleName] = temp_tree;
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

	//filter unnecessary events according to revise processID and imagefile
	//this event always needs to output. So do not call setValueableEvent(false)
//	if (Filter::filterImageFile(imageFileName)||Filter::secondFilter(this)) {
		//setValueableEvent(false);
//	}

	//set process info
    fillProcessInfo(); //fill parentProcess and process Information

	switch (opCode)
	{
	case IMAGEDCEND:
	case IMAGEUNLOAD: {

		Module tempModule = Module(baseAddress, baseAddress + moduleSize, imageFileName);

		//erase unloaded image in correlate process_module map. 
		processID2Modules.eraseValueItemWithKey(processID, &tempModule);

		/*	//for synchronize version
		processID2Modules[processID].erase(&tempModule);
		auto it = processID2Modules.find(processID);
		if ( it != processID2Modules.end()) {
			it->second.erase(&tempModule);	// erase(module*) won't call module's destructor
		}
		*/
		//TODO : update the min and max module address of the exact process, for convenient, skip this.

		break;
	}
	case IMAGELOAD:
	case IMAGEDCSTART: {

		//create module instance
		Module* module = new Module(baseAddress, baseAddress + moduleSize, imageFileName);
		//TargetProcess2ModuleIter targetIter = processID2Modules.count(processID) == 0 ?
		//	processID2Modules.insert(processID, std::set<Module*, ModuleSortCriterion>()).first : processID2Modules.find(processID);
		int cnt = -1;
		//auto it = processID2Modules.find(processID);
		//if (it != processID2Modules.end()) cnt = it->second.count(module);
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
			
			if (cnt == 0) {	// pid2moduleset item exists,just update the item
				processID2Modules.insertValueItemWithKey(processID, module);
				//processID2Modules[processID].insert(module);

				//modify min and max module begin address to filter callstack addresses
				//the reason why do not get the reference pair here is for thread safe, in processend part ,there will be some erase operation.
				auto minmaxPair = EventProcess::processID2ModuleAddressPair[processID];	
				if (baseAddress < minmaxPair.first)	minmaxPair.first = baseAddress;
				if (baseAddress + moduleSize > minmaxPair.second)	minmaxPair.second = baseAddress + moduleSize;

				//reassign the updated pair
				//EventProcess::processID2ModuleAddressPair[processID] = minmaxPair;
				EventProcess::processID2ModuleAddressPair.insertOverwirte(processID,minmaxPair);
			}
			else {	// pid2moduleset item not exists, so insert the item into processID2Modules .

				/*auto insertPair = processID2Modules.insert(std::map <int, std::set<Module*, ModuleSortCriterion> >::value_type(
					processID, std::set<Module*, ModuleSortCriterion>()));*/
				processID2Modules.insert(processID, std::set<Module*, ModuleSortCriterion>());
				
				//push unloaded image module to process_module map; insertPair.second must equal true
				//if (insertPair.second) {
					//insertPair.first->second.insert(module);	//for synchronize version
				processID2Modules.insertValueItemWithKey(processID, module);	//not overwrited
				//}

				//record min and max module begin address to filter callstack addresses
				/*EventProcess::processID2ModuleAddressPair.insert
				(std::map<int, EventProcess::MinMaxModuleAddressPair>::
					value_type(processID, std::make_pair(baseAddress, baseAddress + moduleSize)));*/
				EventProcess::processID2ModuleAddressPair.insert
				(processID, std::make_pair(baseAddress, baseAddress + moduleSize));
			}
		}
		else	//found modules set mapping with the processID, do nothing.
		{
			//delete existing module instance
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

	//second filter, filter according to revise processID
	if (Filter::secondFilter(this))	return;
	
	int stackProcessID = getProcessID();
	int stackThreadID = getThreadID();
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
                ULONG64 imageBeginAddress;
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

                    //find the first module whose baseAddress larger than currentStackAddress
                    auto targetModuleIter = moduleSet->second.lower_bound(&tempStackAddressModule);
                    /*
                    get the target module.because the values of stackAdresses are all larger than the modules'set baseAddress,
                    so --targetModuleIter is valid.
                    */
                    if (--targetModuleIter == moduleSetEnd) {
                        //return;
                        continue;
                    }

                    moduleName = (*targetModuleIter)->getModuleName();      //get the target module name to fetch correlate apis.
                    currentModuleBaseAddress = (*targetModuleIter)->getAddressBegin();
                    //get apis
                    auto apisTarget = EventImage::modulesName2APIs.find(moduleName);

                    if (apisTarget != apisEnd && apisTarget->second.size() != 0) {
                        rvaStackAddress = currentStackAddress - currentModuleBaseAddress;
                        tempAPI = MyAPI(rvaStackAddress);

                        auto targetAPIIter = apisTarget->second.lower_bound(&tempAPI);

                        //in case targetAPIIter==apisTarget->second.begin(), so --targetAPIIter will be an end() and unreference it is invalid.
                        if (--targetAPIIter == apisTarget->second.end()) {
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
                if(callStackRecordNum.load()<2000){
                    callStackRecord[tempCallStackIdentifier] =callInfo;
                    callStackRecordNum++;
                }else{
                    auto begin = callStackRecord.begin();
                    delete begin->second;

                    callStackRecord.erase(begin);
                    callStackRecord[tempCallStackIdentifier] =callInfo;
                }
				//std::cout << *callInfo << std::endl << std::endl;
			}
		}
	}

	setProperty("stackInfo", new dataType(callInfo==nullptr?"NoInfo":*callInfo));
//    delete callInfo;
}

void  EventUnImportant::parse() {

	setValueableEvent(false);
	//MyLogger::writeLog("EventUnImportant parse successfully!");
}

/*
std::wstring& EventProcess::getProcessName(std::wstring& exeImageName) {

	int rPos = exeImageName.find_last_of(L"\\");
	int len = exeImageName.length();

	if (rPos != len - 1) {

		exeImageName = exeImageName.substr(rPos);
	}
	
	return exeImageName;
}
*/

void  EventProcess::parse() {

	ULONG64 pid = getProperty(ProcessId)->getULONG64();
	setProcessID(pid);

	switch (getEventIdentifier()->getOpCode())
	{
	case PROCESSSTART: {

//		if (!EventParser::threadParseFlag) {
//			EventParser::parsePools->enqueueTask([]() {
//
//				EventParser::beginThreadParse();
//				//multithread parse events continue about 50 seconds when a process starts
//				std::this_thread::sleep_for(std::chrono::microseconds(50000000));
//				EventParser::endThreadParse();
//				});
//		}
	}
	case PROCESSDCSTART: {
		//int pid = getProcessID();

        removeQuotesFromProperty(ImageFileName);
		// for both update and add value
		processID2Name[pid] = getProperty(ImageFileName)->getString();

		if (EventImage::processID2Modules.count(pid) == 0)  {
            /*
             //for normal std::map
                 EventImage::processID2Modules.insert(std::map <int, std::set<Module*, ModuleSortCriterion> >::value_type(
                 pid, std::set<Module*, ModuleSortCriterion>()));
             */
            //for readwritemap
			EventImage::processID2Modules.insert(pid, std::set<Module*, ModuleSortCriterion>());
			//record min and max module begin address to filter callstack addresses
            /*
            //for normal std::map
                processID2ModuleAddressPair.insert(std::map<int, MinMaxModuleAddressPair>::
                value_type(pid, std::make_pair(initMinAddress, initMaxAddress)));
            */

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
			//return;
		}
	}
}

void EventPerfInfo::initSystemCallMap() {
	/*
	std::wstring win32k = L"C:\\Windows\\System32\\win32k.sys";
	//std::wstring win32k = L"C:\\Windows\\System32\\ntdll.dll";
	std::wstring ntoskrnl = L"C:\\Windows\\System32\\ntoskrnl.exe";

	HANDLE h = GetModuleHandle(win32k.c_str());

	//MEMORY_BASIC_INFORMATION mbi;
	//if (::VirtualQueryEx(::GetCurrentProcess(), (LPCVOID)&GetCurrentProcess, &mbi, sizeof(mbi)) != 0)
	//{
	//	printf("VirtualQueryEx : 0x%X\n", mbi.AllocationBase);
	//}
	//else
	//{
	//	printf("VirtualQueryEx failed, LastError : %d\n", ::GetLastError());
	//}
	
	EventImage::getAPIsFromFile(win32k);
	EventImage::getAPIsFromFile(ntoskrnl);


	auto win32kAPIsSet = EventImage::modulesName2APIs.find(win32k);
	auto ntoskrnlAPIsSet = EventImage::modulesName2APIs.find(ntoskrnl);

	if (win32kAPIsSet == EventImage::modulesName2APIs.end()) {
		MyLogger::writeLog("win32k �ļ���API����ʧ��");
		exit(-1);
	}
	if (ntoskrnlAPIsSet == EventImage::modulesName2APIs.end()) {
		MyLogger::writeLog("ntoskrnl �ļ���API����ʧ��");
		exit(-1);
	}

	auto win32kItBegin = win32kAPIsSet->second.begin();
	auto win32kItEnd = win32kAPIsSet->second.end();
	std::ofstream sysMapOut("C:\\sysMapOut2.txt", std::ios::out, _SH_DENYNO);

	for (win32kItBegin; win32kItBegin != win32kItEnd; win32kItBegin++) {
		systemCallMap.insert(std::map<ULONG64, std::wstring>::value_type(win32kItBegin->getAPIAddress(), win32kItBegin->getAPIName()));
		sysMapOut << Tools::DecInt2HexStr(win32kItBegin->getAPIAddress()) << " : "
			<< Tools::WString2String(win32kItBegin->getAPIName().c_str()) << std::endl;
	}

	auto ntoskrnlItBegin = ntoskrnlAPIsSet->second.begin();
	auto ntoskrnlItEnd = ntoskrnlAPIsSet->second.end();



	for (ntoskrnlItBegin; ntoskrnlItBegin != ntoskrnlItEnd; ntoskrnlItBegin++) {
		systemCallMap.insert(std::map<ULONG64, std::wstring>::value_type(ntoskrnlItBegin->getAPIAddress(), ntoskrnlItBegin->getAPIName()));
		sysMapOut << Tools::DecInt2HexStr(ntoskrnlItBegin->getAPIAddress()) << " : " 
			<<Tools::WString2String(ntoskrnlItBegin->getAPIName().c_str()) << std::endl;
	}
*/
}

void  EventRegistry::parse() {

    fillProcessInfo(); //fill parentProcess and process Information

    switch (getEventIdentifier()->getOpCode()) {
        case REG_OPEN:
        case REG_CREATE:
        case REG_QUERYVALUE:
//        case REG_KCBDELETE:
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
    EventRegistry::keyHandle2KeyName;
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
                int processId = EventThread::threadId2processId[issuingThreadId];

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
		//std::wcout << getSysCallName() << std::endl;
		//res_json["arguments"]["SysCallName"] = it->second;
	}
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

	//if (EventProcess::processID2Name.count(pid) != 0) {
	//	setProcessName(EventProcess::processID2Name[pid]);
	//}
	//else {
	//	setProcessName("Unknown");
	//}
	fillProcessInfo();
	//setProcessName(EventProcess::processID2Name[pid]);
}

//using nlohmann::json library to format jsonstring
nlohmann::json getCommonJson(BaseEvent* event) {

	nlohmann::json tempJson;

	if (event) {

		//std::string eventName = event->getEventIdentifier()->getEventName();
		
		//if(strcmp(event->getProcessName() , "") == 0)

		//std::string processName = event->getProcessName();

		tempJson = nlohmann::json{
			//{"ProviderID",event->getEventIdentifier().getProviderID()},
			//{"OpCode",event->getEventIdentifier().getOpCode()},
			{"EventName",event->getEventIdentifier()->getEventName()},
			{"ProcessID",event->getProcessID() },
			{"ProcessName",event->getProcessName()},
			{"ThreadID",event->getThreadID()},
			{"TimeStamp",event->getTimeStamp()},
			//{"ProcessorID",event->getProcessorID()},
			{"arguments",{}}
		};

		std::string ss = tempJson.dump();
		//auto it = event->getProperties().begin();
		//auto end = event->getProperties().end();
		for(auto it : event->getProperties())
		//for (it; it != end; ++it) 
		{
			std::string propertyName =it.first;

			if(it.second){
				if (it.second->getIsString()) {
					std::string argValue = it.second->getString();
					tempJson["arguments"][propertyName] = argValue;
				}
				else {
					tempJson["arguments"][propertyName] = it.second->getULONG64();
				}
			}
			else {
				tempJson["arguments"][propertyName] = -1;
			}

		}

	}
	else {
		MyLogger::writeLog("parse json error,event is nullptr");
		//exit(-1);
	}

	return tempJson;
}

//self parse jsonstring
STATUS getCommonJsonNoLib(BaseEvent* event, std::string* sJson) {

	if (!event) return STATUS_FAIL;

	std::string eventName = event->getEventIdentifier()->getEventName().c_str();
	ULONG64 ProviderID = event->getEventIdentifier()->getProviderID();
	int OpCode = event->getEventIdentifier()->getOpCode();
	bool flag = false;

	sJson->append(
		"{\"EventName\":\"" + eventName +
		"\",\"ProcessID\":" + std::to_string(event->getProcessID()) +
		",\"ProcessName\":\"" + event->getProcessName() +
		"\",\"ParentProcessID\":" + std::to_string(event->getParentProcessID()) +
		",\"ParentProcessName\":\"" + event->getParentProcessName() +
		"\",\"ThreadID\":" + std::to_string(event->getThreadID()) +
		",\"TimeStamp\":" + std::to_string(event->getTimeStamp()) +
		",\"arguments\":{");

	//event->getProperty
	for (auto pty : event->getProperties()) {

		if (pty.second) {

			if (flag) {
				sJson->append(",");
			}

			flag = true;
			if (pty.second->getIsString()) {
				std::string argValue = pty.second->getString();
				//tempJson["arguments"][propertyName] = argValue;
				sJson->append("\"" + pty.first + "\":\"" +
					argValue + "\"");
			}
			else {
				//tempJson["arguments"][propertyName] = it->second->getULONG64();
				sJson->append("\"" + pty.first + "\":" +
					std::to_string(pty.second->getULONG64()));
			}
		}
		else {
			//tempJson["arguments"][propertyName] = -1;
		}
		delete pty.second;		//delete properies
	}

	sJson->append("}}");
	event->setPropertiesDeleted(true);	//set properies deleted true

	return STATUS_SUCCESS;
}

STATUS BaseEvent::toJsonString(std::string* sJson) {
	
	STATUS res = getCommonJsonNoLib(this, sJson);

	return res;
}

//std::string EventPerfInfo::toJsonString(std::string* sJson) {
//
//	nlohmann::json tempJson = getCommonJson(this);
//
//	//��sysclenter �¼����syscallname
//	if (getEventIdentifier()->getOpCode() == 51) {
//
//		//std::string sysCallName = *getSysCallName();
//		tempJson["arguments"]["sysCallName"] = *getSysCallName();
//	}
//	return tempJson.dump();
//}
//
//std::string EventProcess::toJsonString(std::string* sJson) {
//
//	//nlohmann::json tempJson = getCommonJson(this);
//	std::string res = getCommonJsonNoLib(this);
//
//	//std::string parentProcessName = Tools::WString2String(getParentProcessName().c_str());
//	//tempJson["arguments"]["parentProcessName"] = parentProcessName;
//	return res;
//}
//
//std::string  EventRegister::toJsonString(std::string* sJson) {
//
//	std::string res = getCommonJsonNoLib(this);
//	//nlohmann::json tempJson = getCommonJson(this);
//
//	//tempJson["arguemtns"]["parentProcessName"] = getParentProcessName();
//	return res;
//}
//
//std::string EventThread::toJsonString(std::string* sJson) {
//
//	std::string res = getCommonJsonNoLib(this);
//	//nlohmann::json tempJson = getCommonJson(this);
//
//	//tempJson["arguemtns"]["parentProcessName"] = getParentProcessName();
//	return res;
//}
//
//std::string EventUnImportant::toJsonString(std::string* sJson) {
//
//	std::string res = getCommonJsonNoLib(this);
//	//nlohmann::json tempJson = getCommonJson(this);
//
//	//tempJson["arguemtns"]["parentProcessName"] = getParentProcessName();
//	return res;
//}
//
//std::string EventImage::toJsonString(std::string* sJson) {
//
//	std::string res = getCommonJsonNoLib(this);
//	//nlohmann::json tempJson = getCommonJson(this);
//
//	//std::cout << res << std::endl;
//	//tempJson["arguemtns"]["parentProcessName"] = getParentProcessName();
//	return res;
//	//return "";
//	//return tempJson.dump();
//}
//
//std::string EventCallstack::toJsonString(std::string* sJson) {
//
//	std::string res = getCommonJsonNoLib(this);
//	//nlohmann::json tempJson = getCommonJson(this);
//
//	//std::wstring wsStackInfo = getCallStackInfo();
//	//tempJson["arguments"]["callStackInfo"] = Tools::WString2String(wsStackInfo.c_str());
//	return res;
//}
//
//std::string EventFile::toJsonString(std::string* sJson) {
//
//	std::string res = getCommonJsonNoLib(this);
//	//nlohmann::json tempJson = getCommonJson(this);
//	//tempJson["arguemtns"]["parentProcessName"] = getParentProcessName();
//	return res;
//}
//
//std::string EventTCPIP::toJsonString(std::string* sJson) {
//
//	std::string res = getCommonJsonNoLib(this);
//	//nlohmann::json tempJson = getCommonJson(this);
//	//tempJson["arguemtns"]["parentProcessName"] = getParentProcessName();
//	return res;
//}