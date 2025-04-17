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
<<<<<<< Updated upstream
=======
int i=0;
>>>>>>> Stashed changes
=======
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
<<<<<<< Updated upstream
//                    op->outputStringPointer(sJson);
<<<<<<< Updated upstream
                    op->output(*sJson);
=======
                    op->outputStringPointer(sJson);
>>>>>>> Stashed changes
//                    std::cout<<*sJson<<std::endl;
=======
                   op->output(*sJson);
>>>>>>> Stashed changes
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
                        if(EventParser::isWdm){
                            STATUS status = event->toWdmJsonString(sJson);
                            if (status == STATUS_SUCCESS) {
//                                op->output(*sJson);
                                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                                op->output(*sJson);
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
    for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; i++)
    {
        std::string* sJson = new std::string();
        bool flag = false;
        status =ETWConfiguration::eventParser.PrintProperties4GetProperties(event,pEvent, pInfo, i, NULL, 0);

        if (ERROR_SUCCESS != status)
        {
            wprintf(L"Printing top level properties failed.\n");
        }
        event->parse();

        std::string eventName = event->getEventIdentifier()->getEventName().c_str();
//    添加eventID

        sJson->append(
                "{\"Event\":\"" + providerName + "\",\"Event_ID\":" + std::to_string(pInfo->EventDescriptor.Id) +
                "\",\"PID\":" + std::to_string(event->getProcessID()) +
                ",\"PName\":\"" + event->getProcessName() +
                "\",\"PPID\":" + std::to_string(event->getParentProcessID()) +
                ",\"PPName\":\"" + event->getParentProcessName() +
                "\",\"TID\":" + std::to_string(event->getThreadID()) +
                ",\"TimeStamp\":" + std::to_string(event->getTimeStamp()) +
                ",\"Host-UUID\":" + Initializer::getUUID() +
                ",\"args\":{");
//        j["Event"]=providerName;
//        j["Event_Id"]=pInfo->EventDescriptor.Id;
//        j["PID"]=std::to_string(event->getProcessID());
//        j["PName"]=event->getProcessName();
//        j["PPID"]=std::to_string(event->getParentProcessID());
//        j["PPName"]=event->getParentProcessName();
//        j["TID"]=std::to_string(event->getThreadID());
//        j["TimeStamp"]=std::to_string(event->getTimeStamp());
//        j["Host-UUID"]=Initializer::getUUID();
//        j["args"]=argsJson;
        for (auto pty : event->getProperties()) {

            if (pty.second) {

                if (flag) {
                    sJson->append(",");
                }

                flag = true;
                if (pty.second->getIsString()) {
                    std::string argValue = pty.second->getString();
                    sJson->append("\"" + pty.first + "\":\"" +
                                  argValue + "\"");
                }
                else {
                    sJson->append("\"" + pty.first + "\":" +
                                  std::to_string(pty.second->getULONG64()));
                }
            }

            //delete properies
        }

        event->setPropertiesDeleted(true);
        sJson->append("}}");
        op->output(*sJson);

    }
    delete event;
}
VOID WINAPI EventParser::ConsumeEventSub(PEVENT_RECORD pEvent) {
    //对公共区域进行上锁
    //m.lock();
    ETWConfiguration::eventParser.getPropertiesByTdh(pEvent);
    //m.unlock();
    //对公共区域进行解锁
}
