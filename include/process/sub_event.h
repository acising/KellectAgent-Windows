#pragma once
#include "event.h"
#include "tools/tools.h"
#include "initialization/initializer.h"

class EventProcess :public Event {

private:
	using MinMaxModuleAddressPair = std::pair<ULONG64, ULONG64>;
	const static ULONG64 initMinAddress = 0xffffffff;
	const static ULONG64 initMaxAddress = 0;

public:
	friend class EventImage;
	friend class Initializer;
	static std::map<int, std::string> processID2Name;
	static std::map<std::string, int> processName2ID;
	static ReadWriteMap<int, MinMaxModuleAddressPair> processID2ModuleAddressPair;
	//static ReadWriteMap<int, std::string> processID2Name;
	//static ReadWriteMap<std::string, int> processName2ID;
	static const ULONG64 UnknownProcess = 0xffffffff - 1;

public:
	//std::string toJsonString() override;
	void parse() override;
	//std::wstring& getParentProcessName() { return parentProcessName; }
	//void setParentProcessName(const std::wstring& name) { parentProcessName = name; }
	//std::wstring& getProcessName(std::wstring &exeImageName);

	~EventProcess() {

	};

private:
	static enum { PROCESSSTART = 1, PROCESSDCSTART = 3, PROCESSEND = 2, PROCESSDCEND = 4, PROCESSDEFUNCT = 30 };
	//std::wstring parentProcessName;
};

class EventFile :public Event {
public:

	static enum {
		FILECREATE = 32, FILEDELETE_ = 35, RENAME = 71, RUNDOWN = 36, CREATE = 64,
		OPERATIONEND = 76, DELETE_ = 70, SETINFO = 69, NAME = 0, QUERYINFO = 74, FSCONTROL = 75,
		READ = 67, WRITE = 68, DIRENUM = 72, NOTIFY = 77, CLEANUP = 65, CLOSE = 66, FLUSH = 73, NOTDEFINEDTYPE1 = 84, NOTDEFINEDTYPE2 = 83
	};

	//static ReadWriteMap<ULONG64, std::string> fileKey2Name;
	static std::map<ULONG64, std::string> fileKey2Name;
	//static ReadWriteMap<ULONG64, std::string> fileObject2Name;
	static std::map<ULONG64, std::string> fileObject2Name;
	void parse() override;
	//std::string toJsonString() override;
	~EventFile() {
		//std::cout << "EventFile 析构函数调用了" << std::endl; 
	};

private:

	//revise the property to human-readable format.
	std::string modifyFileNameProperty(int propertyIndex) {
		dataType* dt = getProperty(propertyIndex);

		std::string fileName = dt->getString();
		//Tools::convertFileNameInDiskFormat(fileName);

		//delete dt;		//avoid memory leak
		//setProperty(propertyIndex, new dataType(fileName));
		return fileName;
	}
	//void fullEventName();
};

class EventThread :public Event {

	//std::string toJsonString() override;
	void parse() override;

public:

	//static ReadWriteMap<ULONG64, ULONG64> processorId2threadId;
	static std::map<ULONG64, ULONG64> processorId2threadId;
	//static ReadWriteMap<ULONG64, ULONG64> threadId2processId;
	static std::map<ULONG64, ULONG64> threadId2processId;
	static std::set<ULONG64> threadSet;
	static void initThreadStruct();
	~EventThread() {

	};

private:
	enum { THREADSTART = 1, THREADDCSTART = 3, THREADEND = 2, THREADDCEND = 4, CSWITCH = 36 };

	static std::mutex threadMutex;
	static std::unique_ptr<std::mutex> up;
};

class EventRegistry :public Event {

public:
	//std::string toJsonString() override;
	void parse() override;
	EventRegistry() {};
	~EventRegistry() {

	};

//private:
	//enum { IMAGELOAD = 10, IMAGEDCSTART = 3, IMAGEUNLOAD = 2, IMAGEDCEND = 4 };
};

class EventDisk :public Event {

	//std::string toJsonString() override;
	void parse() override;
	~EventDisk() {

	};
};
class EventUnImportant :public Event {

	//std::string toJsonString() override;
	void parse() override;
	~EventUnImportant() {

	};
};

class EventImage :public Event {

public:
	//static std::map < int, std::set<Module*, ModuleSortCriterion> > processID2Modules;
	static ReadWriteMap < int, std::set<Module*, ModuleSortCriterion> > processID2Modules;
	static std::map < std::string, std::string > volume2Disk;
	static std::map < std::string, std::set<MyAPI*, MyAPISortCriterion> > modulesName2APIs;
	//static ReadWriteMap < std::string, std::set<MyAPI*, MyAPISortCriterion> > modulesName2APIs;
	static std::map < std::string, std::set<MyAPI*, MyAPISortCriterion> > usedModulesName2APIs;
	static std::set <Module*, ModuleSortCriterion> globalModuleSet;
	static std::set <Module*, ModuleSortCriterion> usedModuleSet;

	static STATUS getAPIsFromFile(std::string& fileName, std::set<MyAPI*, MyAPISortCriterion>& apis);
	static STATUS getExportAPIs(LPVOID hModule, std::string& fileName, std::set<MyAPI*, MyAPISortCriterion>& apis);
	//std::string toJsonString() override;
	void parse() override;
	~EventImage() {

	};

private:
	enum { IMAGELOAD = 10, IMAGEDCSTART = 3, IMAGEUNLOAD = 2, IMAGEDCEND = 4 };
	using TargetProcess2ModuleIter = decltype(processID2Modules.find(0));

	struct find_by_address {
		find_by_address(const ULONG64& addr) : addr(addr) {}
		bool operator()(const Module* m) {
			return m->getAddressBegin() == addr;
		}
	private:
		ULONG64 addr;
	};
};

class CallStackIdentifier {

private:
	std::string operationName;
	int depth;		//callstacks depth
	ULONG64 topCallAddress;

public:
	CallStackIdentifier(std::string opName, int dth, ULONG64 topAddress) :
		operationName(opName), depth(dth), topCallAddress(topAddress) {}
	
	bool operator< (const CallStackIdentifier& ci)const {
		if (depth != ci.depth)	return depth < ci.depth;
		else {
			//int res = strcmp(operationName.c_str(), ci.operationName.c_str());
			//if (res != 0)	return res < 0;
			//else{
				return topCallAddress < ci.topCallAddress;
			//}
		}
	}
};

class EventCallstack :public Event {

public:
	std::vector<ULONG64> stackAddresses;

	static ReadWriteMap<CallStackIdentifier, std::string*> callStackRecord;
	static void initCallStackTracing(TRACEHANDLE& SessionHandle);
	static void initCallStackEvents();
	//std::string toJsonString() override;
	void parse() override;
	//void setCallStackInfo(std::wstring& callStackInfo) { this->callStackInfo = callStackInfo; }
	//std::wstring& getCallStackInfo() { return callStackInfo; }
	~EventCallstack() {

	};

	struct find_by_address {
		find_by_address(const ULONG64& addr) : addr(addr) {}
		bool operator()(const Module* m) {
			return m->getAddressBegin() <= addr && m->getAddressEnd() >= addr;
		}
	private:
		ULONG64 addr;
	};

private:
	//std::wstring callStackInfo;
};

class EventPerfInfo :public Event {

public:
	static std::map< ULONG64, std::string*> systemCallMap;
	static std::map< ULONG64, std::string*> systemCallMapUsed;
	static void initSystemCallMap();

	//std::string toJsonString() override;
	void parse() override;
	inline void setSysCallName(std::string* name) { sysCallName = name; }
	inline std::string* getSysCallName() { return sysCallName; }
	~EventPerfInfo() {

	};

private:
	std::string* sysCallName;
};

class EventTCPIP :public Event {

public:
	//std::string toJsonString() override;
	void parse() override;
	~EventTCPIP() {

	};

private:
	static enum {SENDIPV4 = 10, RECVIPV4 = 11, DISCONNECTIPV4 = 13, RETRANSMITIPV4 = 14, RECONNECTIPV4 = 16,
		TCPCOPYIPV4 = 18, CONNECTIPV4 = 12, ACCEPTIPV4 = 15, TCPIPFAILED = 17
	};
}; 
