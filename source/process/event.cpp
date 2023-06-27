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

ReadWriteMap <int, std::set<Module*, ModuleSortCriterion> > EventImage::processID2Modules;
//std::map <int, std::set<Module*, ModuleSortCriterion> > EventImage::processID2Modules;
//std::map < std::string, std::set<MyAPI*, MyAPISortCriterion> > EventImage::usedModulesName2APIs;

extern std::map<ULONG64, std::string> addr2FuncName;
extern std::map<ULONG64, std::string> addr2FuncNameUsed;
//INT64 Tools::String2INT64(std::string s);  //将string转换为INT64

void BaseEvent::fillProcessInfo(){

    int pid =getProcessID();
    int ppid = EventProcess::processID2ParentProcessID[pid];

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

	if (BaseEvent::propertyNameVector.size() <= propertyNameIndex ) {
		MyLogger::writeLog("propertyNameIdex exceed EventIdentifier::propertyNameVector size！\n");
		exit(-1);
	}
	if (propertyNameIndex < 0) {
		MyLogger::writeLog("getProperty propertyNameIdex is negative\n");
		exit(-1);
	}

	std::string propertyName = BaseEvent::propertyNameVector[propertyNameIndex];
	//event doesn't have this property
	if (!properties.count(propertyName)) {

		propertyName = "unknownProperty";
		properties.insert(std::map <std::string, dataType*>::value_type(propertyName, nullptr));
		MyLogger::writeLog("can not find propertyName\n");
	}

	return this->properties[propertyName];
}

void BaseEvent::setProperty(int propertyNameIdex, dataType* dt) {

	if (BaseEvent::propertyNameVector.size() <= propertyNameIdex) {
		MyLogger::writeLog("propertyNameIdex exceed EventIdentifier::propertyNameVector size！\n");
		exit(-1);
	}

	if (propertyNameIdex < 0) {
		MyLogger::writeLog("setProperty propertyNameIdex is negative\n");
		exit(-1);
	}
	std::string propertyName = BaseEvent::propertyNameVector[propertyNameIdex];

	properties[propertyName] = dt;
}

void BaseEvent::removeQuotesFromProperty(int propertyIndex) {

    replaceCharacterFromProperty(propertyIndex,'\"',"");
}

void BaseEvent::replaceCharacterFromProperty(int propertyIndex,char target ,std::string substitute){

    auto tempDataType = getProperty(propertyIndex);

    if(tempDataType!= nullptr){
        std::string propertyValue = tempDataType->getString();

        int len = propertyValue.size();
        for(int i =len-1;i>=0;i--){
            if(propertyValue.at(i) == target){
                propertyValue.replace(i,1,substitute);
            }
        }

//        Tools::convertFileNameInDiskFormat(propertyValue);
        delete tempDataType;
        setProperty( propertyIndex,new dataType(propertyValue));
    }
}

