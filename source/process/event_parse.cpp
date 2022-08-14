#include "output/output.h"
#include "process/event_parse.h"
#include <iostream>
#include <map>
#include <string>
#include "tools/my_socket.h"
#include "process/event.h"
#include "process/etw_config.h"
using namespace std;

Output* EventParser::op;
std::set<ULONG64> EventParser::threadParseProviders;
atomic<ULONG64> EventParser::successParse(0);
//atomic<ULONG64> threadParseEventsNum(0);
ULONG64 comingEventsNum = 0;
EventParser ETWConfiguration::eventParser;

void EventParser::eventParseThreadFunc(BaseEvent* event) {

	event = ETWConfiguration::eventParser
            .getPropertiesByParsingOffset(event,event->getRawPropertyLen(),event->getRawProperty());

    if(event->isValueableEvent()){
        event->parse();
        if (!Filter::thirdFilter(event)) {

            if (++successParse % 50000 == 0) {
                std::cout << "parse events number:" << successParse << std::endl;
            }
            std::string* sJson = new std::string();
            STATUS status = event->toJsonString(sJson);

            if (status == STATUS_SUCCESS) {
                //	//delete sJson;
                op->pushOutputQueue(sJson);
            }
        }
    }

	delete event;
}

//pEvent is original event stream structure
VOID WINAPI EventParser::ConsumeEventMain(PEVENT_RECORD pEvent) {

//    std::cout<<"providerID:"<< pEvent->EventHeader.ProviderId.Data1<<" opCode:"<<(int)pEvent->EventHeader.EventDescriptor.Opcode<<std::endl;
	if (++comingEventsNum % 1000000 == 0) {
		std::cout << "coming events number: " << comingEventsNum << std::endl;
	}
	if (!Filter::firstFilter(pEvent)) {

		//BaseEvent* event = c.getPropertiesByTdh(pEvent);		//speed of TDH's parsing way is too low , will lead to events lost!
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

                        if (++successParse % 50000 == 0) {
                            std::cout << "parse events number:" << successParse << std::endl;
                        }

                        //create string and to get Json format event
                        std::string* sJson = new std::string();
                        STATUS status = event->toJsonString(sJson);

                        if (status == STATUS_SUCCESS) {
                            //	//delete sJson;
                            op->pushOutputQueue(sJson);
                        }
                    }
                }
				delete event;
			}
		}
		 //delete event;
	}
}

VOID WINAPI EventParser::ConsumeEventSub(PEVENT_RECORD pEvent) {
	//对公共区域进行上锁
	//m.lock();
    ETWConfiguration::eventParser.getPropertiesByTdh(pEvent);
	//m.unlock();
	//对公共区域进行解锁
}
