#include "output/output.h"
#include "process/event_parse.h"
#include <iostream>
#include <map>
#include <fstream>
#include <string>
#include "tools/my_socket.h"
#include "process/event.h"
#include <regex>

using namespace std;

EventParser c;
OutPut* EventParser::op;
std::set<ULONG64> EventParser::threadParseProviders;
atomic<ULONG64> EventParser::successParse = 0;
atomic<ULONG64> threadParseEventsNum = 0;
ULONG64 comingEventsNum = 0;

void EventParser::eventParseThreadFunc(Event* event) {

	event = c.getPropertiesByParsingOffset(event,event->getRawPropertyLen(),event->getRawProperty());
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

		//if (++threadParseEventsNum % 5000 == 0)
			//std::this_thread::sleep_for(std::chrono::nanoseconds(10));

	}
	delete event;
}

VOID WINAPI EventParser::ConsumeEventMain(PEVENT_RECORD pEvent) {

	if (++comingEventsNum % 1000000 == 0) {
		std::cout << "coming events number: " << comingEventsNum << std::endl;
	}
	if (!Filter::firstFilter(pEvent)) {

		//Event* event = c.getPropertiesByTdh(pEvent);		//parsing speed is too low , will lead to events lost!
		Event* event = c.getEventWithIdentifier(pEvent);

		if (event) {	//correctly parse EventIdentifer.
			
			if (threadParseFlag && inThreadParseProviders(event->getEventIdentifier()->getProviderID()))
			{
				event->setRawProperty(pEvent->UserDataLength, pEvent->UserData);
				parsePools->enqueueTask(eventParseThreadFunc, event);	//asynchronize
			}
			else {
				//synchronize
				event = c.getPropertiesByParsingOffset(event, pEvent->UserDataLength, pEvent->UserData);
				event->parse();

				if (!Filter::thirdFilter(event)) {
					if (++successParse % 50000 == 0) {

						std::cout << "parse events number:" << successParse << std::endl;
						//std::this_thread::sleep_for(std::chrono::nanoseconds(1));
					}
					std::string* sJson = new std::string();
					STATUS status = event->toJsonString(sJson);

					if (status == STATUS_SUCCESS) {
						//	//delete sJson;
						op->pushOutputQueue(sJson);
					}
				}

				delete event;
			}
		}
		 //delete event;
	}
}

VOID WINAPI EventParser::ConsumeEventSub(PEVENT_RECORD pEvent) {
	static nlohmann::json retJson;

	string resJsonStr;

	//对公共区域进行上锁
	//m.lock();
	c.getPropertiesByTdh(pEvent);
	//m.unlock();
	//对公共区域进行解锁

	//cout << "event from subsubsusbusbusubsub" << endl;
	//cout << "返回的jsonstr：" << resJsonStr << endl;

//mySocket.sendMsg(resJsonStr);		//socket通信
	//ParseEventStruct(pEvent, retJson);

	//待完成子消费器的分支处理函数

	cout << retJson.dump() << endl;   //输出rec

	retJson.clear();
}
