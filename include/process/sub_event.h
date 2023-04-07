#pragma once
#include "event.h"
#include "tools/tools.h"
#include "initialization/initializer.h"

#define MAX_PROCESSOR_NUM 65535
#define MAX_THREAD_NUM 65535
#define INIT_THREAD_ID -1
#define INIT_PROCESS_ID -1

class EventProcess :public BaseEvent {

private:
	using MinMaxModuleAddressPair = std::pair<ULONG64, ULONG64>;
	const static ULONG64 initMinAddress = 0xffffffff;
	const static ULONG64 initMaxAddress = 0;
	const static int ProcessNumSize = 65535;

public:
	friend class EventImage;
	friend class Initializer;

    static int processID2ParentProcessID[ProcessNumSize];
	static std::map<int, std::string> processID2Name;
	static std::map<std::string, int> processName2ID;
	static ReadWriteMap<int, MinMaxModuleAddressPair> processID2ModuleAddressPair;
	//static ReadWriteMap<int, std::string> processID2Name;
	//static ReadWriteMap<std::string, int> processName2ID;
//	static const int UnknownProcess = -1;

public:
	//std::string toJsonString() override;
	void parse() override;
	//std::wstring& getParentProcessName() { return parentProcessName; }
	//void setParentProcessName(const std::wstring& name) { parentProcessName = name; }
	//std::wstring& getProcessName(std::wstring &exeImageName);

	~EventProcess() {

	};

private:
    enum ProcessEnum { PROCESSSTART = 1, PROCESSDCSTART = 3, PROCESSEND = 2, PROCESSDCEND = 4, PROCESSDEFUNCT = 30 };
    static ProcessEnum processEnum;

    //std::wstring parentProcessName;
};

class EventFile :public BaseEvent {

private:
    enum FileEnum {
        FILECREATE = 32, FILEDELETE_ = 35, RENAME = 71, RUNDOWN = 36, CREATE = 64,
        OPERATIONEND = 76, DELETE_ = 70, SETINFO = 69, NAME = 0, QUERYINFO = 74, FSCONTROL = 75,
        READ = 67, WRITE = 68, DIRENUM = 72, NOTIFY = 77, CLEANUP = 65, CLOSE = 66, FLUSH = 73, NOTDEFINEDTYPE1 = 84, NOTDEFINEDTYPE2 = 83
    };

public:
    static FileEnum fileEnum;

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

class EventThread :public BaseEvent {

	//std::string toJsonString() override;
	void parse() override;

public:

    static int processorId2threadId[MAX_PROCESSOR_NUM];
    static int threadId2processId[MAX_THREAD_NUM];

	static std::set<ULONG64> threadSet;
	static void initThreadStruct();
	~EventThread() {

	};

private:
	enum { THREADSTART = 1, THREADDCSTART = 3, THREADEND = 2, THREADDCEND = 4, CSWITCH = 36 };

	static std::mutex threadMutex;
	static std::unique_ptr<std::mutex> up;
};

class EventRegistry :public BaseEvent {
private:
    enum RegistryEnum {
        REG_CREATE = 10, REG_OPEN = 11, REG_DELETE = 12, REG_QUERY = 13, REG_SETVALUE = 14,
        REG_DELETEVALUE = 15, REG_QUERYVALUE = 16, REG_ENUMERATEKEY = 17, REG_ENUMERATEVALUEKEY = 18, REG_QUERYMULTIVALUE = 19, REG_SETINFORMATION = 20,
        REG_FLUSH = 21, REG_KCBCREATE = 22, REG_KCBDELETE = 23, REG_KCBRUNDOWNBEGIN = 24, REG_KCBRUNDOWNEND = 25, REG_VIRTUALIZE = 26, REG_CLOSE = 27
    };
public:

    static RegistryEnum registryEnum;
    static ReadWriteMap<ULONG64,std::string> keyHandle2KeyName;

public:
	//std::string toJsonString() override;
	void parse() override;
	EventRegistry() {};
	~EventRegistry() {

	};

//private:
	//enum { IMAGELOAD = 10, IMAGEDCSTART = 3, IMAGEUNLOAD = 2, IMAGEDCEND = 4 };
};

class EventDisk :public BaseEvent {
private:
    enum DiskEnum {
        DISKREAD = 10, DISKWRITE = 11, DISKREADINIT = 12, DISKWRITEINIT = 13, DISKFLUSHINIT = 15,DISKFLUSHBUFFERS = 14
    };

public:
    static DiskEnum diskEnum;
	//std::string toJsonString() override;
	void parse() override;
	~EventDisk() {

	};
};
class EventUnImportant :public BaseEvent {

	//std::string toJsonString() override;
	void parse() override;
	~EventUnImportant() {

	};
};

class EventImage :public BaseEvent {

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
	int depth;		//callstacks depth
	std::vector<ULONG64> callAddresses;

public:
    CallStackIdentifier(int depth, std::vector<ULONG64> callAddresses) :
            depth(depth), callAddresses(callAddresses) {}

	bool operator< (const CallStackIdentifier& ci)const {
		if (depth != ci.depth)	return depth < ci.depth;
		else {
            for(int i =0;i<depth;i++){
                if(ci.callAddresses[i] == this->callAddresses[i]){
                    if(i>5) return false;
                    continue;
                }
                return ci.callAddresses[i] < this->callAddresses[i];
            }
            return false;
		}
	}
};

class EventCallstack :public BaseEvent {

public:
	std::vector<ULONG64> stackAddresses;

    static std::atomic<int> callStackRecordNum;
//	static ReadWriteMap<CallStackIdentifier, std::string*> callStackRecord;
	static std::map<CallStackIdentifier, std::string*> callStackRecord;
	static void initCallStackTracing(TRACEHANDLE& SessionHandle);
	static void initCallStackEvents();
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
};

class EventPerfInfo :public BaseEvent {

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

class EventTCPIP :public BaseEvent {

public:
	//std::string toJsonString() override;
	inline std::string transferULONG2IPAddr(ULONG64& lAddr){
        CHAR sAddr[36] = { 0 };
        sprintf_s(sAddr, 36, "%lld.%lld.%lld.%lld", (lAddr >> 0) & 0xff,
                  (lAddr >> 8) & 0xff,
                  (lAddr >> 16) & 0xff,
                  (lAddr >> 24) & 0xff);
        return sAddr;
    }
    void parse() override;
	~EventTCPIP() {

	};

private:
    enum TCPIPEnum{SENDIPV4 = 10, RECVIPV4 = 11, DISCONNECTIPV4 = 13, RETRANSMITIPV4 = 14, RECONNECTIPV4 = 16,
		TCPCOPYIPV4 = 18, CONNECTIPV4 = 12, ACCEPTIPV4 = 15, TCPIPFAILED = 17
	};

    static TCPIPEnum tcpipEnum;
}; 
