#pragma once
#include <Windows.h>
#include <evntrace.h>
#include <map>
#include <string>
#include <vector>
#include <set>
#include <list>
#include <algorithm>
#include "initialization/initializer.h"

#define ULONGMAX 2^64-1

class dataType
{
private:
	ULONG64 d;
	std::string s;
	bool isString = false;
	
public:
	dataType(std::string s) :d(ULONGMAX),s(s), isString(true) {}
	dataType(ULONG64 ld) :d(ld), s("NULL"), isString(false) {}
	dataType() :s("NULL"), d(ULONGMAX), isString(false) {}

//	inline bool isEmpty() { return d == ULONGMAX && !isString; }
	inline bool getIsString() { return isString; }
	inline ULONG64 getULONG64() { return d; }
	inline std::string& getString() { return s; }
};

class EventIdentifier {

private:
	ULONG64 providerID;
	int opCode;
	std::string eventName;

public:

	EventIdentifier(ULONG64 id, int code,std::string eName="") :providerID(id), opCode(code), eventName(eName) {}
	EventIdentifier() {}
	//~EventIdentifier() { std::cout << "eventidentifier 析构函数调用" << std::endl; };

	inline int getOpCode() const  { return opCode; }
	inline ULONG64 getProviderID() const { return providerID;}
	inline const std::string getEventName() const { return eventName;}
	inline void setEventName(std::string eName) { eventName = eName; };

	bool operator<(const EventIdentifier& ei) const {
		if (this->providerID < ei.providerID) 
			return true;

		else if (this->providerID == ei.providerID && this->opCode < ei.opCode)
			return true;

		return false;
	}
};

class EventIdentifierSortCriterion {
public:
	bool operator() (const EventIdentifier* a, const EventIdentifier* b) const {
		if (a->getProviderID() < b->getProviderID())
			return true;

		else if (a->getProviderID() == b->getProviderID() && a->getOpCode() < b->getOpCode())
			return true;

		return false;
	}
};
typedef std::set <EventIdentifier*, EventIdentifierSortCriterion> EISetType;

class BaseEvent{

private:
	char* rawProperty = nullptr;
	int rawPropertyLen = 0;

protected:
	int threadID;
	int processID;
	int processorID;
	std::string processName;
	ULONG64 timestamp;
	EventIdentifier* ei;
	bool valueableEvent = true;
	bool propertiesDeleted = false;
	std::map<std::string, dataType*> properties;

public:

	using PropertyInfo = std::pair<std::string, int>;
    enum PropertyNameIndex {
		UniqueProcessKey, ProcessId, ParentId, SessionId, ExitStatus, DirectoryTableBase, Flags, UserSID, ImageFileName, CommandLine, PackageFullName,
		ApplicationId, TThreadId, StackBase, StackLimit, UserStackBase, UserStackLimit, Affinity, Win32StartAddr, TebBase, SubProcessTag, BasePriority,
		PagePriority, IoPriority, ThreadFlags, NewThreadId, OldThreadId, NewThreadPriority, OldThreadPriority, PreviousCState, SpareByte, OldThreadWaitReason,
		OldThreadState, OldThreadWaitIdealProcessor, NewThreadWaitTime, Reserved, PageFaultCount, HandleCount, PeakVirtualSize, PeakWorkingSetSize,
		PeakPagefileUsage, QuotaPeakPagedPoolUsage, QuotaPeakNonPagedPoolUsage, VirtualSize, WorkingSetSize, PagefileUsage, QuotaPagedPoolUsage,
		QuotaNonPagedPoolUsage, PrivatePageCount, InitialTime, Status, Index, KeyHandle, KeyName, PID, size, daddr, saddr, dport, sport, startime, endtime,
		seqnum, connid, mss, sackopt, tsopt, wsopt, rcvwin, rcvwinscale, sndwinscale, Proto, FailureCode, IrpPtr, FileObject, TTID, CreateOptions, FileAttributes, ShareAccess,
		OpenPath, FileKey, Length, InfoClass, FileIndex, FileName, ExtraInfo, NtStatus, Offset, IoSize, IoFlags, DiskNumber, IrpFlags, TransferSize,
		ByteOffset, Irp, IssuingThreadId, HighResResponseTime, RoutineAddr, UniqMatchId, Routine, MajorFunction, MinorFunction, MessageID, IsServerPort,
		PortName, ReturnValue, Vector, SysCallAddress, SysCallNtStatus, ImageBase, ImageSize, ImageChecksum, TimeDateStamp, SignatureLevel, SignatureType,
		Reserved0, DefaultBase, Reserved1, Reserved2, Reserved3, Reserved4
	};
    static PropertyNameIndex propertyNameIndex;

	static std::map<EventIdentifier*, std::vector<std::string>,EventIdentifierSortCriterion> eventPropertiesMap;
	static std::set <EventIdentifier*, EventIdentifierSortCriterion> eventIdentifierSet;
	static std::set <std::string> propertyNameSet;
	static std::vector <std::string> propertyNameVector;
	static std::map <std::string,int> propertyName2IndexMap;
	static std::map<EventIdentifier*, std::list<PropertyInfo>, EventIdentifierSortCriterion> eventStructMap;
//	static std::map<ULONG64, std::set<EventIdentifier*,EventIdentifierSortCriterion>> eventProviderID2Opcodes; //use to classify events by providerID and opcodes.

public:
	virtual STATUS toJsonString(std::string* sJson);
	virtual void parse() {};
	BaseEvent() {};
	virtual~BaseEvent() {
		// the arguments are deleted in function getCommonJsonNoLib(..), as to avoid twice traverse arguments
		
		if (!propertiesDeleted)
			for_each(properties.begin(), properties.end(), [](auto it) {delete it.second; });

		delete[] rawProperty;
		delete ei;	
	};
	void setPropertiesDeleted(bool deleted) { propertiesDeleted = deleted; }
	void setThreadID(int tid) { threadID = tid; }
	void setProcessID(int pid) { processID = pid; }
	void setProcessorID(int pcid) { processorID = pcid; }
	void setTimeStamp(ULONG64 timeStamp) { timestamp = timeStamp; }
	void setProcessName(std::string name) { processName = name; }
	void setEventIdentifier(EventIdentifier* eIdentifier) { ei = eIdentifier; }
	void setValueableEvent(bool vb) { valueableEvent = vb; }
	void setRawProperty(int len, void* data) {

		rawPropertyLen = len;
		rawProperty = new char[len + 1];
		//memset(rawProperty, 0, len + 1);
		memcpy((void*)rawProperty, (void*)data, len);
	};
	void deleteRawProperty() {
		
		delete rawProperty;
		rawProperty = nullptr;
	}

	const std::map<std::string, dataType*>& getProperties() { return properties; }
	bool getPropertiesDeleted() { return propertiesDeleted; }
	int getThreadID() { return threadID; }
	int getProcessID() { return processID; }
	int getProcessorID() { return processorID; }
	ULONG64 getTimeStamp() { return  timestamp; }
	bool isValueableEvent() { return  valueableEvent; }
	std::string& getProcessName() { return processName; }
	const EventIdentifier* getEventIdentifier()const { return ei; }
	EventIdentifier* getEventIdentifier() { return ei; }
	char* getRawProperty() { return rawProperty; };
	int getRawPropertyLen() { return rawPropertyLen; };
	dataType* getProperty(int propertyNameIndex);

	void setProperty(int propertyNameIdex, dataType *dt);
	inline void setProperty(std::string propertyName, dataType* dt)	//overload setProperty
	{
		this->properties.insert(std::map<std::string, dataType*>::value_type(propertyName, dt));
	};
	
	inline bool hasProperty(int propertyNameIndex) {
		if (propertyNameIndex > propertyNameVector.size())	return false;
		return properties.count(propertyNameVector[propertyNameIndex]) != 0;
	}
	int setTIDAndPID(BaseEvent* event);
	friend std::wostream& operator<< (std::wostream& os, BaseEvent& rec);
};

class MyAPI{

public:
	MyAPI(ULONG64 apiAddress=0, std::string apiName="") :apiAddress(apiAddress), apiName(apiName) 
	{
		//std::cout<< &this->apiAddress 
	}
	~MyAPI() { 
		//std::cout << "MyAPI 析构函数调用了" << std::endl; 
	};
	inline ULONG64 getAPIAddress() const { return apiAddress; }
	//ULONG64 getAPIAddressAddressed() const { return (ULONG64)(&apiAddress); }
	inline std::string getAPIName() const { return apiName; }


	//inline bool operator<(const MyAPI& api) const{
	//	if (this->apiAddress < api.apiAddress) return true;
	//	return false;
	//}
private:
	ULONG64 apiAddress;
	std::string apiName;
};

class MyAPISortCriterion {
public:
	bool operator() (const MyAPI* a, const MyAPI* b) const {
		if (a->getAPIAddress() < b->getAPIAddress())
			return true;
		return false;
	}
};

class Module{
public:
	//std::map<ULONG64, std::wstring> funcsMap;

	//Module(ULONG64 aBegin, ULONG64 aEnd, std::wstring mName) :module_address_begin(aBegin), 
	//	module_address_end(aEnd), moduleName(mName),funcsMap(std::map<ULONG64, std::wstring>()) {};
	Module(ULONG64 aBegin, ULONG64 aEnd, std::string mName) :module_address_begin(aBegin),
		module_address_end(aEnd), moduleName(mName) {};

	Module(ULONG64 aBegin) :module_address_begin(aBegin),
		module_address_end(0), moduleName("") {};

	//Module() :module_address_begin(0),
	//	module_address_end(0), moduleName(L""), funcsMap(std::map<ULONG64, std::wstring>()) {};
	Module() :module_address_begin(0),
		module_address_end(0), moduleName("") {};

	~Module() { 
		//std::cout << "Module 析构函数调用了" << std::endl;
	};

	inline ULONG64 getAddressBegin() const { return module_address_begin; }
	inline ULONG64 getAddressEnd() const { return module_address_end; }
	inline std::string getModuleName() const { return moduleName; }
	inline void setModuleName(std::string& name) { moduleName = name; }
	
	//inline void decCount() { count--; }

	//inline void incCount() { count++; }
	//inline bool noCount() { return count == 0; }
	//inline void insertAPI(std::wstring APIName, ULONG64 APIAddress) {
	//	funcsMap.insert(std::map<ULONG64, std::wstring>::value_type(APIAddress,APIName));
	//};
	//inline bool hasAPI

private:
	ULONG64 module_address_begin;
	ULONG64 module_address_end;
	std::string moduleName;
	//int count;

};

class ModuleSortCriterion {
public:
	bool operator() (const Module* a, const Module* b) const {
		//if (a->getAddressEnd() <= b->getAddressBegin())
		if (a->getAddressBegin() < b->getAddressBegin())
			return true;
		return false;
	}
};
