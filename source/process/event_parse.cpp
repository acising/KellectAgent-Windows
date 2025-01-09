#include "output/output.h"
#include "process/event_parse.h"
#include <iostream>
#include <map>
#include <string>
#include "tools/my_socket.h"
#include "process/event.h"
#include "process/etw_config.h"
#include "tools/json.hpp"
using namespace std;
Output* EventParser::op;
std::set<ULONG64> EventParser::threadParseProviders;
atomic<ULONG64> EventParser::successParse(0);
//atomic<ULONG64> threadParseEventsNum(0);
ULONG64 comingEventsNum = 0;
EventParser ETWConfiguration::eventParser;
json EventParser:: j;
bool EventParser::isWdm;
<<<<<<< Updated upstream
=======
int i=0;
>>>>>>> Stashed changes
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
            if(EventParser::isWdm){
                STATUS status = event->toWdmJsonString(sJson);
                if (status == STATUS_SUCCESS) {
//                    op->outputStringPointer(sJson);
<<<<<<< Updated upstream
                    op->output(*sJson);
=======
                    op->outputStringPointer(sJson);
>>>>>>> Stashed changes
//                    std::cout<<*sJson<<std::endl;
                }
                delete sJson;
            }
            else{
                STATUS status = event->toJsonString(sJson);
                if (status == STATUS_SUCCESS) {
                    op->pushOutputQueue(sJson);
                }
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
<<<<<<< Updated upstream

            if (threadParseFlag && inThreadParseProviders(event->getEventIdentifier()->getProviderID()))
            {
=======

            if (threadParseFlag && inThreadParseProviders(event->getEventIdentifier()->getProviderID()))
            {

>>>>>>> Stashed changes
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
<<<<<<< Updated upstream
                        //create string and to get Json format event
                        std::string* sJson = new std::string();
                        if(EventParser::isWdm){
                            STATUS status = event->toWdmJsonString(sJson);
                            if (status == STATUS_SUCCESS) {
                                op->output(*sJson);
//                                std::cout<<*sJson<<std::endl;
//                                op->outputStringPointer(sJson);
                            }
                            delete sJson;
                        }
                        else{
                            STATUS status = event->toJsonString(sJson);
                            if (status == STATUS_SUCCESS) {

                                 op->pushOutputQueue(sJson);
                            }
=======

                        //create string and to get Json format event

                        std::string* sJson = new std::string();
                        if(EventParser::isWdm){
                            STATUS status = event->toWdmJsonString(sJson);
                            if (status == STATUS_SUCCESS) {

                                op->outputStringPointer(sJson);
//                                std::cout<<*sJson<<std::endl;
//                                op->outputStringPointer(sJson);
                            }
                            delete sJson;
>>>>>>> Stashed changes
                        }
                        else{
                            STATUS status = event->toJsonString(sJson);
                            if (status == STATUS_SUCCESS) {

                                 op->pushOutputQueue(sJson);

                            }
                        }

                    }
                }

                delete event;
            }
        }
        //delete event;
    }
}

VOID WINAPI EventParser::ConsumeUserEvent(PEVENT_RECORD pEvent) {
    BaseEvent* event = ETWConfiguration::eventParser.getUserEventWithIdentifier(pEvent);
    DWORD status = ERROR_SUCCESS;
    PTRACE_EVENT_INFO pInfo = NULL;
    status = ETWConfiguration::eventParser.GetEventInformation4GetProperties(pEvent, pInfo);
    std::wstring wstr(reinterpret_cast<wchar_t*>(reinterpret_cast<PBYTE>(pInfo) + pInfo->ProviderNameOffset));
    std::string providerName(wstr.begin(), wstr.end());
    for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; ++i)
    {
<<<<<<< Updated upstream
        std::string* sJson = new std::string();
        bool flag = false;
        status =ETWConfiguration::eventParser.PrintProperties4GetProperties(event,pEvent, pInfo, i, NULL, 0);
=======

        std::string* sJson = new std::string();
        bool flag = false;
        status =ETWConfiguration::eventParser.PrintProperties4GetProperties(event,pEvent, pInfo, i, NULL, 0);

>>>>>>> Stashed changes
        if (ERROR_SUCCESS != status)
        {
            wprintf(L"Printing top level properties failed.\n");
        }
        event->parse();
<<<<<<< Updated upstream
        STATUS status = event->toJsonString(sJson);
        std::cout<<"out ready"<<std::endl;
        if (status == STATUS_SUCCESS) {
            op->output(*sJson);
=======

        STATUS status = event->toJsonString(sJson);

        if (status == STATUS_SUCCESS) {

            op->outputStringPointer(sJson);
>>>>>>> Stashed changes

        }
//
//        op->output(j.dump());
        delete sJson;
<<<<<<< Updated upstream
    }

=======

    }
    for (auto pty : event->getProperties()) delete pty.second;
>>>>>>> Stashed changes
    delete event;
}
VOID WINAPI EventParser::ConsumeEventSub(PEVENT_RECORD pEvent) {
    //对公共区域进行上锁
    //m.lock();
    ETWConfiguration::eventParser.getPropertiesByTdh(pEvent);
    //m.unlock();
    //对公共区域进行解锁
}
