#pragma once
#include <set>
#include "process/event.h"

class Filter {

public:

	Filter() {};
	~Filter() {};
	//filter according eventidentifier and processID
	static bool firstFilter(PEVENT_RECORD pEvent);
	static bool secondFilter(Event* event);
	static bool thirdFilter(Event* event);

public:

	static std::set<EventIdentifier*, EventIdentifierSortCriterion> filteredEventIdentifiers;
	static std::set<int> filteredProcessID;
	static std::set<std::string> filteredImageFile;

	static inline bool filterImageFile(std::string& imageFileName) {
		return !Filter::filteredImageFile.count(imageFileName);
	};

private:
	static inline bool filterPID(int pid) {
		//filteredProcessID是过滤黑名单
		//return filteredProcessID.find(pid) != filteredProcessID.end();
		return filteredProcessID.count(pid)!=0;
	}

	static inline bool filterEventIdentifier(ULONG64 providerId, int opCode) {
		EventIdentifier ie = EventIdentifier(providerId, opCode);
		//filteredEventIdentifiers是过滤黑名单事件
		return filteredEventIdentifiers.count(&ie);
	}
};