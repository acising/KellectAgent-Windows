#include "tools/filter.h"

bool Filter::firstFilter(PEVENT_RECORD pEvent) {
	
	bool flt = false;
	int pid = pEvent->EventHeader.ProcessId;
	ULONG64 providerId = pEvent->EventHeader.ProviderId.Data1;
	int opCode = pEvent->EventHeader.EventDescriptor.Opcode;

	if (filterPID(pid)) 	flt = true;
	else if (filterEventIdentifier(providerId, opCode))	flt = true;

	return flt;
}

//this filter function called in each "Eventxxx" class parse() function which is derived from "Event" class
bool Filter::secondFilter(Event* event) {

	int pid = event->getProcessID();
	bool flt = false;
	if (filterPID(pid)) {
		event->setValueableEvent(false);
		flt = true;
	}
	return flt;
}

bool Filter::thirdFilter(Event* event) {

	bool flt = false;

	if (!event->isValueableEvent())	flt = true;

	return flt;
}