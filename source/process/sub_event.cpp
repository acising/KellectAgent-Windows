#include "tools/logger.h"
#include "tools/providerGUID.h"
#include "tools/tools.h"
#include "process/sub_event.h"
#include <fstream>
#include <iostream> 
#include <regex>
#include <algorithm>
#include "tools/json.hpp"
#include "filter.h"
#include "process/event_parse.h"

//CLASSIC_EVENT_ID  callStackEvents[256];
std::map< ULONG64, std::string*> EventPerfInfo::systemCallMap;
std::map< ULONG64, std::string*> EventPerfInfo::systemCallMapUsed;
//ReadWriteMap<ULONG64, ULONG64> EventThread::processorId2threadId;
std::map<ULONG64, ULONG64> EventThread::processorId2threadId;
//ReadWriteMap<ULONG64, ULONG64> EventThread::threadId2processId;
std::map<ULONG64, ULONG64> EventThread::threadId2processId;
std::set<ULONG64> EventThread::threadSet;
std::set <Module*, ModuleSortCriterion> EventImage::globalModuleSet;
std::set <Module*, ModuleSortCriterion> EventImage::usedModuleSet;
ReadWriteMap<int, EventProcess::MinMaxModuleAddressPair> EventProcess::processID2ModuleAddressPair;
ReadWriteMap<CallStackIdentifier, std::string*> EventCallstack::callStackRecord;

void setFileName(Event* ev) {

	ULONG64 fileObject = 0;
	ULONG64 fileKey = 0;

	dataType* dt = ev->getProperty(Event::FileObject);
	if (dt) {
		fileObject = dt->getULONG64();
	}

	dt = ev->getProperty(Event::FileKey);
	if (dt) {
		fileKey = dt->getULONG64();
	}

	dataType* tempDataType;
	if (EventFile::fileKey2Name.count(fileKey) != 0 && fileKey !=0) {

		//tempDataType = new dataType(EventFile::fileKey2Name.getValue(fileKey));		//to avoid undefined behavior, because mutexe needs before iterator.
		tempDataType = new dataType(EventFile::fileKey2Name[fileKey]);		//to avoid undefined behavior, because mutexe needs before iterator.
		ev->setProperty(Event::FileName, tempDataType);
	}
	else {
		if (EventFile::fileObject2Name.count(fileObject) != 0 && fileObject != 0) {

			//tempDataType = new dataType(EventFile::fileObject2Name.getValue(fileObject));	//to avoid undefined behavior, because mutexe needs before iterator.
			tempDataType = new dataType(EventFile::fileObject2Name[fileObject]);	//to avoid undefined behavior, because mutexe needs before iterator.
			ev->setProperty(Event::FileName, tempDataType);
		}
		else {
			tempDataType = new dataType("UnknownFile");
			ev->setProperty(Event::FileName, tempDataType);
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
		break;
	case RUNDOWN:
	case NAME:
	case FILECREATE: {

		//setTIDAndPID(this);

		//std::string fileName = modifyFileNameProperty(FileName);
		//std::string fileName = modifyFileNameProperty(FileName);

		//ReadWriteMap will OverWrite the item if the key is exist.
		//fileKey2Name.insertOverwirte(fileObject, fileName);
		fileKey2Name.insert(std::map<ULONG64, std::string>::value_type(fileObject, getProperty(FileName)->getString()));
		break;
	}
	case FILEDELETE_: {

		//std::string fileName = modifyFileNameProperty(FileName);

		fileKey2Name.erase(fileObject);
		break;
	}
	case CREATE: {

		//std::string openPath = modifyFileNameProperty(OpenPath);

		//ReadWriteMap will OverWrite the item if the key is exist.
		//fileObject2Name.insertOverwirte(fileObject, openPath);
		//fileObject2Name.insert(std::map<ULONG64, std::string>::value_type(fileObject,getProperty(OpenPath)->getString()));
		fileObject2Name[fileObject] = getProperty(OpenPath)->getString();

		break;
	}
	case DIRENUM:
	case NOTIFY: {
		
		
		
		break;
	}
	case CLEANUP:
	case CLOSE: {

		ULONG64 fileKey = getProperty(FileKey)->getULONG64();
		setFileName(this);

		fileObject2Name.erase(fileObject);
		fileKey2Name.erase(fileKey);

		break;
	}
	default:
		setValueableEvent(false);
		//setFileName(this);
		break;
	}

	if (isValueableEvent()) {

		dataType* tmp = getProperty(TTID);
		if(tmp){
			int threadId = tmp->getULONG64();
			setThreadID(threadId);

			if (EventThread::threadId2processId.count(threadId) != 0) {
				int pid = EventThread::threadId2processId[threadId];
				setProcessID(pid);
			}
		}

		auto res = EventProcess::processID2Name.find(getProcessID());
		if (res != EventProcess::processID2Name.end())
			setProcessName(res->second);
		else
			setProcessName("Unknown");
	}
}

//some events need to revise tid and pid
void Event::setTIDAndPID(Event* ev) {

	int processorId = ev->getProcessorID();
	int threadId = 0;
	int processId = EventProcess::UnknownProcess;

	auto targetProcessor2ThreadItem = EventThread::processorId2threadId.find(processorId);

	if (targetProcessor2ThreadItem != EventThread::processorId2threadId.end()) {
		threadId = targetProcessor2ThreadItem->second;

		auto targetThread2ProcessItem = EventThread::threadId2processId.find(threadId);

		if (targetThread2ProcessItem != EventThread::threadId2processId.end()) {
			processId = targetThread2ProcessItem->second;
		}
		else {
			processId = Tools::getProcessIDByTID(threadId);
			//EventThread::threadId2processId.insert(threadId, processId);
			EventThread::threadId2processId.insert(std::map<ULONG64, ULONG64>::value_type(threadId, processId));
		}
	}

	ev->setProcessID(processId);
	ev->setThreadID(threadId);
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
		threadId2processId.insert(std::map<ULONG64, ULONG64>::value_type(tid, pid));

		break;
	}
	case THREADEND:
	case THREADDCEND: {

		pid = getProperty(ProcessId)->getULONG64();
		tid = getProperty(TThreadId)->getULONG64();

		threadId2processId.erase(tid);
		break;
	}
	case CSWITCH: {
		//processorId2threadId.insert(getProcessorID(), getProperty(NewThreadId)->getULONG64());
		processorId2threadId.insert(std::map<ULONG64, ULONG64>::value_type (getProcessorID(), getProperty(NewThreadId)->getULONG64()));
	}
	default: {
		setValueableEvent(false);	//filter cswitch
		break;
	}
	}

	if (isValueableEvent()) {

		setProcessID(pid);
		setThreadID(tid);

		auto res = EventProcess::processID2Name.find(pid);
		if (res != EventProcess::processID2Name.end())
			setProcessName(res->second);
		else
			setProcessName("Unknown");
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

	pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		MyLogger::writeLog("Not PE file-2: ");
		return STATUS_FAILED;
	}

	//��Ҫ����PIMAGE_NT_HEADERS �ҵ���������ʼ��ַ
	pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDosHeader->e_lfanew);
	//ULONG64 base = pNtHeader->OptionalHeader.ImageBase;
	//pSecHeader = (PIMAGE_SECTION_HEADER)((PBYTE)hModule + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		MyLogger::writeLog("Not PE file-2: ");
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
		//MyLogger::writeLog("imageFile: "+ Tools::WString2String(fileName.c_str()) +"��api��Ϣ");
		//return tempAPIs;
		return STATUS_FAILED;
	}
	PCHAR pFunc;
	DWORD rva;
	//��ʼ�����������еĺ������Լ�������ַ�����浽temp_DLLAddress_map
	for (DWORD i = 0; i < (pExportDirectory->NumberOfNames); ++i) {
		//if ((ULONG64)(pAddressName - (PDWORD)hModule) >= current_module_size_) {
		//    printf("Error in");
		//    break;
		//}
		//if ((ULONG64)(pAddressOfNameOrdinals - (PWORD)hModule) >= current_module_size_) {
		//    printf("Error in");
		//    break;
		//}
		pFunc = (PCHAR)((PBYTE)hModule + *pAddressName);
		++pAddressName;
		rva = pAddresOfFunction[*pAddressOfNameOrdinals];
		++pAddressOfNameOrdinals;

		//���뺯��
		//module.insertAPI(Tools::StringToWString(std::string(pFunc)), module.getAddressBegin() + rva);
		apis.insert(std::set<MyAPI*, MyAPISortCriterion>::value_type
		(new MyAPI(rva,pFunc)));

	}

	return STATUS_SUCCESS;
}

STATUS EventImage::getAPIsFromFile(std::string& fileName, std::set<MyAPI*, MyAPISortCriterion>& apis) {
	
	HANDLE hFile = nullptr;
	HANDLE hMap = nullptr;
	LPVOID hBase = nullptr;
	STATUS status = STATUS_FAILED;
	//std::wstring fileName = module.getModuleName();

	hFile = CreateFileA(fileName.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	//hFile = CreateFile(Tools::StringToWString(fileName.c_str()), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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

	//dataType* dt = ;	
	std::string imageFileName = getProperty(FileName)->getString();

//    Tools::convertFileNameInDiskFormat(imageFileName);
	setProcessID(processID);

	//filter unnecessary events according to revise processID and imagefile
	//this event always needs to output if filter successfully.So do not call setValueableEvent(false)
//	if (Filter::filterImageFile(imageFileName)||Filter::secondFilter(this)) {
		//setValueableEvent(false);
//	}

	//set process name 
	auto res = EventProcess::processID2Name.find(processID);
	if (res != EventProcess::processID2Name.end())
		setProcessName(res->second);
	else
		setProcessName("Unknown");

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

	CLASSIC_EVENT_ID callStackEvents[256] = { 
		{ ProcessGuid, 1,{ 0 }},
		{ ProcessGuid, 2,{ 0 } },
		{ ProcessGuid, 4,{ 0 } },
		{ FileIoGuid, 64,{ 0 } },
		{ FileIoGuid, 67,{ 0 } },
		{ FileIoGuid, 68,{ 0 } },
		{ FileIoGuid, 72,{ 0 } },
		{ FileIoGuid, 74,{ 0 } },
		//{ PerfInfoGuid, 51,{ 0 }},
		//{ ALPCGuid, 33,{ 0 } },
		//{ ALPCGuid, 34,{ 0 } },
		{ ThreadGuid, 2,{ 0 } },
		{ ThreadGuid, 4,{ 0 } },
		{ RegistryGuid, 10,{ 0 }},
		{ RegistryGuid, 11,{ 0 }},
		{ RegistryGuid, 13,{ 0 }},
		//{ RegistryGuid, 16,{ 0 }},
		//{ RegistryGuid, 17,{ 0 }},
		//{ RegistryGuid, 18,{ 0 }},
		//{ RegistryGuid, 20,{ 0 }},
		//{ RegistryGuid, 22,{ 0 }},
	};

	TRACE_INFO_CLASS information_class = TraceStackTracingInfo;
	TraceSetInformation(SessionHandle, information_class, &callStackEvents, sizeof(callStackEvents));
}

void  EventCallstack::parse() {

	//second filter, filter according to revise processID
	if (Filter::secondFilter(this))	return;
	
	int stackProcessID = getProcessID();
	int stackThreadID = getThreadID();
	std::string* callInfo = nullptr;
	int callStackDepth = stackAddresses.size();

	auto res = EventProcess::processID2Name.find(stackProcessID);
	if(res!= EventProcess::processID2Name.end())
		setProcessName(res->second);
	else
		setProcessName("Unknown");

	if (callStackDepth>0) {		
		CallStackIdentifier tempCallStackIdentifier(getEventIdentifier()->getEventName(),callStackDepth, stackAddresses[0]);
		auto rec = callStackRecord.find(tempCallStackIdentifier);
		if (rec != callStackRecord.end()) {			//this callstack has been parsed before and stroed in callStackRecord, just reused it 
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
				std::set<MyAPI*, MyAPISortCriterion>  apis;
				int stackIdx = 0;	//stacks size
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

					auto targetModuleIter = moduleSet->second.lower_bound(&tempStackAddressModule);
					/*
					get the target module.because the values of stackAdresses are all larger than the modules'set baseAddress,
					so --targetModuleIter is valid.
					*/
					if (--targetModuleIter == moduleSetEnd) {
						//return;
						continue;
					}

					moduleName = (*targetModuleIter)->getModuleName();
					currentModuleBaseAddress = (*targetModuleIter)->getAddressBegin();
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

				if (calls.size() == 0) {

					int a = 1;
				}

				int i = 0;
				callInfo = new std::string();	//init callInfo
				for (auto c : calls) {
					if (i++ != 0)	callInfo->append(",");
					callInfo->append(c);
				}

				//record each callstackinfo which maybe reused later.
				callStackRecord.insert(tempCallStackIdentifier,callInfo);

				//std::cout << *callInfo << std::endl << std::endl;
			}
		}
	}

	setProperty("stackInfo", new dataType(callInfo==nullptr?"NoInfo":*callInfo));
	int a = 0;

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

		if (!EventParser::threadParseFlag) {
			EventParser::parsePools->enqueueTask([]() {

				EventParser::beginThreadParse();
				//multithread parse events continue about 50 seconds when a process starts
				std::this_thread::sleep_for(std::chrono::microseconds(50000000));
				EventParser::endThreadParse();
				});
		}
	}
	case PROCESSDCSTART: {
		//int pid = getProcessID();

		// for both update and add value
		processID2Name[pid] = getProperty(ImageFileName)->getString();
		//if (processID2Name.count(pid) == 0) {
		//	//processIDSet.insert(processID);
		//	//std::wstring pName = Tools::getProcessNameByPID(processID);
		//	std::string exeImageName = getProperty(ImageFileName)->getString();

		//	//processID2Name.insert(getProcessID(), exeImageName);
		//	processID2Name.insert(std::map<int, std::string>::value_type(pid, exeImageName));
		//}

		if (EventImage::processID2Modules.count(pid) == 0)  {
			//processIDSet.insert(processID);
			//std::wstring pName = Tools::getProcessNameByPID(processID);
			EventImage::processID2Modules.insert(pid, std::set<Module*, ModuleSortCriterion>());
			//EventImage::processID2Modules.insert(std::map <int, std::set<Module*, ModuleSortCriterion> >::value_type(
			//	pid, std::set<Module*, ModuleSortCriterion>()));

			//record min and max module begin address to filter callstack addresses
			//MinMaxModuleAddressPair tmpPair = ;
			//processID2ModuleAddressPair.insert(std::map<int, MinMaxModuleAddressPair>::
			//	value_type(pid, std::make_pair(initMinAddress, initMaxAddress)));
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
		ULONG64 ppid = getProperty(ParentId)->getULONG64();
		//ULONG64 pid = getProcessID();

		//second filter, filter according to revised processID
		if (!Filter::secondFilter(this)) {

			//std::wstring parentProcessName;
			auto res = EventProcess::processID2Name.find(ppid);
			if (res != EventProcess::processID2Name.end())
				setProperty("ParentProcessName", new dataType(res->second));
			else
				setProperty("ParentProcessName", new dataType("Unknown"));

			res = EventProcess::processID2Name.find(pid);
			if (res != EventProcess::processID2Name.end())
				setProcessName(res->second);
			else
				setProcessName("Unknown");
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

}

void  EventDisk::parse() {

}

void  EventPerfInfo::parse() {
	
	//int a = 0;
	
	setTIDAndPID(this);
	ULONG64 pid = getProcessID();
	setProcessName(EventProcess::processID2Name[pid]);

	//std::cout << Tools::DecInt2HexStr(getProperty(Event::SysCallAddress).getULONG64());
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
	auto res = EventProcess::processID2Name.find(pid);
	if (res != EventProcess::processID2Name.end())
		setProcessName(res->second);
	else
		setProcessName("Unknown");
	//setProcessName(EventProcess::processID2Name[pid]);
}

//using nlohmann::json library to format jsonstring
nlohmann::json getCommonJson(Event* event) {

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
STATUS getCommonJsonNoLib(Event* event, std::string* sJson) {

	if (!event) return STATUS_FAIL;

	std::string eventName = event->getEventIdentifier()->getEventName().c_str();
	ULONG64 ProviderID = event->getEventIdentifier()->getProviderID();
	int OpCode = event->getEventIdentifier()->getOpCode();
	bool flag = false;

	sJson->append(
		"{\"EventName\":" + eventName +
		",\"ProcessID\":" + std::to_string(event->getProcessID()) +
		",\"ProcessName\":" + event->getProcessName() +
		",\"ThreadID\":" + std::to_string(event->getThreadID()) +
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
		delete pty.second;		//properies deleted
	}

	sJson->append("}}");
	event->setPropertiesDeleted(true);	//set properies deleted

	return STATUS_SUCCESS;
}

STATUS Event::toJsonString(std::string* sJson) { 
	
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