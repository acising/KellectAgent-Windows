#include "tools/filter.h"
#include <tdh.h>

bool Filter::firstFilter(PEVENT_RECORD pEvent) {

	bool flt = false;
	int pid = pEvent->EventHeader.ProcessId;
	ULONG64 providerId = pEvent->EventHeader.ProviderId.Data1;
	int opCode = pEvent->EventHeader.EventDescriptor.Opcode;

	if (filterPID(pid)) 	flt = true;
	else if (filterDroppedIdentifier(providerId, opCode))	flt = true;    //"-x"/filter.txt dropped noise: reject before parsing
	// NOTE: the former filterEventIdentifier whitelist check was removed;
	// unknown event types are handled by thirdFilter's provider-level check.
	// The hardcoded ~80-pair list is preserved (commented) in initFilter().

	return flt;
}

//this filter function called in each "Eventxxx" class parse() function which is derived from "BaseEvent" class
bool Filter::secondFilter(BaseEvent* event) {

	int pid = event->getProcessID();
	bool flt = false;
	if (filterPID(pid)) {
		event->setValueableEvent(false);
		flt = true;
	}
	return flt;
}

bool Filter::thirdFilter(BaseEvent* event) {

	bool flt = false;

    if (!event->isValueableEvent()){
        // here to return, skip the listenedEventsProviders.count() call
        return true;
    }

    if(listenAllEvents||listenedEventsProviders.count(event->getEventIdentifier()->getProviderID())){

        if (filterPID(event->getProcessID())) {
//            event->setValueableEvent(false);
            flt = true;
        }
    }else {
        flt = true;
    }

    return flt;
}