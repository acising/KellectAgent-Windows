#include "tools/filter.h"
#include <tdh.h>

bool Filter::firstFilter(PEVENT_RECORD pEvent) {
	
	bool flt = false;
	int pid = pEvent->EventHeader.ProcessId;
//	ULONG64 providerId = pEvent->EventHeader.ProviderId.Data1;
//	int opCode = pEvent->EventHeader.EventDescriptor.Opcode;

	if (filterPID(pid)) 	flt = true;
//	else if (filterEventIdentifier(providerId, opCode))	flt = true;     //do not filter checks for every event, as it is time-consuming

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

    if (!event->isValueableEvent() )
        flt = true;
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