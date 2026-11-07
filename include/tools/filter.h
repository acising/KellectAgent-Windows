#pragma once
#include "process/event.h"
#include <string.h>
#include <wchar.h>
#include <mutex>

class Filter {

public:

	Filter() {};
	~Filter() {};
	//filter according eventidentifier and processID
	static bool firstFilter(PEVENT_RECORD pEvent);
	static bool secondFilter(BaseEvent* event);
	static bool thirdFilter(BaseEvent* event);

    static bool pidFilter(int pid){
        // filteredProcessID is read on the ETW callback (firstFilter) and
        // mutated on the ordered parse worker (ProcessStart/ProcessEnd), so the
        // lookup must be locked. Writes are rare (process churn), readers are
        // per-event; an uncontended lock is cheap.
        std::lock_guard<std::mutex> lock(processIdMutex);
        return filteredProcessID.count(pid) != 0;
    }

	//kellect toolchain processes (collector/GUI) are never collected:
	//the initial PID snapshot may miss family members that started later, so
	//EventProcess::parse also learns them dynamically from ProcessStart events
	static inline bool isKellectFamilyImage(const char* imageFileName) {
		static const char* family[] = { "kellect.exe", "KellectConsole.exe" };
		for (const char* f : family)
			if (_stricmp(imageFileName, f) == 0) return true;
		return false;
	}

	static inline bool isKellectFamilyImage(const wchar_t* imageFileName) {
		static const wchar_t* family[] = { L"kellect.exe", L"KellectConsole.exe" };
		for (const wchar_t* f : family)
			if (_wcsicmp(imageFileName, f) == 0) return true;
		return false;
	}

public:
    //listen events specified by option "-e", only output listened events and filter others
    static std::set<ULONG64> Filter::listenedEventsProviders;
    //if user listen all event types, we need not to check current event if exist in "listenedEventsProviders"
    static bool listenAllEvents;

    static std::set<EventIdentifier*, EventIdentifierSortCriterion> filteredEventIdentifiers;
	static std::set<int> filteredProcessID;
	static std::mutex processIdMutex;   // guards filteredProcessID (callback reads, worker writes)
	// Images whose Image-Load events (and callstacks) are dropped - blacklist
	// from filter.txt.
	static std::set<std::string> filteredImageFile;
	// Images whose export table has already been parsed into
	// EventImage::modulesName2APIs. This used to share filteredImageFile, which
	// conflated "do not report this image" with "I already cached its APIs".
	static std::set<std::string> parsedApiImage;
	static inline bool filterImageFile(std::string& imageFileName) {
		return !Filter::filteredImageFile.count(imageFileName);
	};

	//events dropped by name via option "-x" (high-volume low-value noise);
	//names are resolved to (provider, opcode) identifiers in initFilter(),
	//after the eventStruct xml has been loaded
	static std::set<EventIdentifier*, EventIdentifierSortCriterion> droppedEventIdentifiers;
	static inline bool filterDroppedIdentifier(ULONG64 providerId, int opCode) {
		if (droppedEventIdentifiers.empty()) return false;
		EventIdentifier ie = EventIdentifier(providerId, opCode);
		return droppedEventIdentifiers.count(&ie) != 0;
	}

private:
	static inline bool filterPID(int pid) {
		//filteredProcessID是过滤黑名单
		std::lock_guard<std::mutex> lock(processIdMutex);
		return filteredProcessID.count(pid)!=0;
	}

	static inline bool filterEventIdentifier(ULONG64 providerId, int opCode) {
		EventIdentifier ie = EventIdentifier(providerId, opCode);
		//filteredEventIdentifiers是过滤黑名单事件
		return filteredEventIdentifiers.count(&ie)==0;
	}
};