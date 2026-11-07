#include "tools/logger.h"
#include "process/sub_event.h"
#include "tools/tools.h"

#include <fstream>
#include <regex>

std::map<EventIdentifier*, std::vector<std::string>,EventIdentifierSortCriterion > BaseEvent::eventPropertiesMap;		//映射了event中不同的参数
std::set <std::string> BaseEvent::propertyNameSet;
std::vector <std::string> BaseEvent::propertyNameVector;
std::map <std::string, int> BaseEvent::propertyName2IndexMap;
std::set <EventIdentifier*, EventIdentifierSortCriterion> BaseEvent::eventIdentifierSet;

//ReadWriteMap<ULONG64, std::string> EventFile::fileKey2Name;
std::map<ULONG64, std::string> EventFile::fileKey2Name;
//ReadWriteMap<ULONG64, std::string> EventFile::fileObject2Name;
std::map<ULONG64, std::string> EventFile::fileObject2Name;

std::map<int, std::string> EventProcess::processID2Name;
std::map<std::string, int> EventProcess::processName2ID;
//ReadWriteMap<int, std::string> EventProcess::processID2Name;
//ReadWriteMap<std::string, int> EventProcess::processName2ID;
//std::set<INT64> EventProcess::processIDSet;

std::map<int, std::map<ULONG64, Module>> EventImage::processID2Modules;
//std::map < std::string, std::set<MyAPI*, MyAPISortCriterion> > EventImage::usedModulesName2APIs;

extern std::map<ULONG64, std::string> addr2FuncName;
extern std::map<ULONG64, std::string> addr2FuncNameUsed;
//INT64 Tools::String2INT64(std::string s);  //将string转换为INT64

void BaseEvent::fillProcessInfo(){
    int pid =getProcessID();
    
    // Find ppid in the map, if not found, default to -1
    int ppid = -1;
    auto ppidIter = EventProcess::processID2ParentProcessID.find(pid);
    if (ppidIter != EventProcess::processID2ParentProcessID.end()) {
        ppid = ppidIter->second;
    }

    setParentProcessID(ppid);

    auto res = EventProcess::processID2Name.find(pid);
    if (res != EventProcess::processID2Name.end())
        setProcessName(res->second);
    else{
        std::string pName = Tools::getProcessNameByPID(pid);

        if(pName.empty())   pName = "unknown";

        EventProcess::processID2Name[pid] = pName;
        setProcessName(pName);
    }

    if(ppid != -1){
        auto res = EventProcess::processID2Name.find(ppid);
        if(res != EventProcess::processID2Name.end())
            setParentProcessName(res->second);
        else{
            std::string ppName = Tools::getProcessNameByPID(ppid);
//
            if(ppName.empty())
                ppName = "unknown";
//
            EventProcess::processID2Name[ppid] = ppName;
            setParentProcessName(ppName);
        }
    }else{
        setParentProcessName("Unknown");
    }
}

dataType* BaseEvent::getProperty(int propertyNameIndex) {

	if (propertyNameIndex < 0) {
		MyLogger::writeLog("getProperty propertyNameIdex is negative\n");
		exit(-1);
	}
	if (BaseEvent::propertyNameVector.size() <= static_cast<size_t>(propertyNameIndex)) {
		MyLogger::writeLog("propertyNameIdex exceed EventIdentifier::propertyNameVector size！\n");
		exit(-1);
	}

	const std::string& propertyName = BaseEvent::propertyNameVector[propertyNameIndex];
	for (auto& kv : properties) {
		if (kv.first == propertyName)
			return kv.second;
	}

	// Missing field is normal (optional XML fields, per-version layouts).
	// Returning null keeps the hot path allocation-free; the previous code
	// inserted a synthetic "unknownProperty" entry (never serialised because the
	// value was null) and logged on every miss.
	return nullptr;
}

void BaseEvent::setProperty(int propertyNameIdex, dataType* dt) {

	if (BaseEvent::propertyNameVector.size() <= static_cast<size_t>(propertyNameIdex)) {
		MyLogger::writeLog("propertyNameIdex exceed EventIdentifier::propertyNameVector size！\n");
		exit(-1);
	}

	if (propertyNameIdex < 0) {
		MyLogger::writeLog("setProperty propertyNameIdex is negative\n");
		exit(-1);
	}
	const std::string& propertyName = BaseEvent::propertyNameVector[propertyNameIdex];

	for (auto& kv : properties) {
		if (kv.first == propertyName) {
			kv.second = dt;
			return;
		}
	}
	properties.emplace_back(propertyName, dt);
}

void BaseEvent::removeQuotesFromProperty(int propertyIndex) {

    replaceCharacterFromProperty(propertyIndex,'\"',"");
}

void BaseEvent::replaceCharacterFromProperty(int propertyIndex,char target ,std::string substitute){

    dataType* tempDataType = getProperty(propertyIndex);
    if (tempDataType == nullptr)
        return;

    const std::string& propertyValue = tempDataType->getString();
    // Most values contain no target at all (paths, command lines): skip the
    // allocation entirely instead of rebuilding the string field by field.
    if (propertyValue.find(target) == std::string::npos)
        return;

    std::string replaced;
    replaced.reserve(propertyValue.size() + 8);
    for (char c : propertyValue) {
        if (c == target) replaced.append(substitute);
        else replaced.push_back(c);
    }

    delete tempDataType;
    setProperty(propertyIndex, new dataType(replaced));
}

