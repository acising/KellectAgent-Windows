#include "output/output.h"
#include "process/event_parse.h"
#include <iostream>
#include <map>
#include <string>
#include "process/event.h"
#include "process/etw_config.h"
using namespace std;

Output* EventParser::op;
std::set<ULONG64> EventParser::threadParseProviders;
atomic<ULONG64> EventParser::successParse(0);
ULONG64 comingEventsNum = 0;
EventParser ETWConfiguration::eventParser;

void EventParser::eventParseThreadFunc(BaseEvent* event) {

	event = ETWConfiguration::eventParser
            .getPropertiesByParsingOffset(event,event->getRawPropertyLen(),event->getRawProperty());

    if(event->isValueableEvent()){
        event->parse();
        if (!Filter::thirdFilter(event)) {

            ++successParse;

            std::string* sJson = new std::string();
            STATUS status = event->toJsonString(sJson);

            if (status == STATUS_SUCCESS) {

                op->pushOutputQueue(sJson);
            }
        }
    }

	delete event;
}

//pEvent is original event stream structure
VOID WINAPI EventParser::ConsumeEventMain(PEVENT_RECORD pEvent) {

	if (++comingEventsNum % 1000000 == 0) {
        std::cout << "received events number: " << comingEventsNum << "; ";
        std::cout << "parsed events number:" << successParse << std::endl;
	}

	if (!Filter::firstFilter(pEvent)) {

		BaseEvent* event = ETWConfiguration::eventParser.getEventWithIdentifier(pEvent);    //simple parse

		if (event) {	//correctly parse EventIdentifier.

			if (threadParseFlag && inThreadParseProviders(event->getEventIdentifier()->getProviderID()))
			{
				event->setRawProperty(pEvent->UserDataLength, pEvent->UserData);
				parsePools->enqueueTask(eventParseThreadFunc, event);	//asynchronize

            }
			else {
                //synchronize section
				event = ETWConfiguration::eventParser
                        .getPropertiesByParsingOffset(event, pEvent->UserDataLength, pEvent->UserData);

                if(event->isValueableEvent()) {

                    event->parse();

                    if (!Filter::thirdFilter(event)) {

                        ++successParse;

                        //create string and to get Json format event
                        std::string* sJson = new std::string();
                        STATUS status = event->toJsonString(sJson);

                        if (status == STATUS_SUCCESS) {
                            op->pushOutputQueue(sJson);
                        }
                    }
                }
				delete event;
			}
		}
	}
}

VOID WINAPI EventParser::ConsumeEventSub(PEVENT_RECORD pEvent) {
	//lock the public area
	//m.lock();
    ETWConfiguration::eventParser.getPropertiesByTdh(pEvent);
	//unlock the public area
    //m.unlock();
}
