#include <windows.h>
#include <initguid.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <time.h>
#include <tdh.h> //PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
#include <strsafe.h>
#include <fstream>
#include <iostream>
#include <evntrace.h>
#include <cstdlib>
#include "process/etw_config.h"
#include "process/event_parse.h"
#include "process/multithread_configuration.h"

ETWConfiguration& ETWConfiguration::operator=(const ETWConfiguration& config) {

    if (this == &config)
    {
        return *this;
    }
    enable_flag = config.enable_flag;
    logfile_path = config.logfile_path;

    return *this;
}

PEVENT_TRACE_PROPERTIES ETWConfiguration::allocateTraceProperties(
    _In_opt_ PWSTR LoggerName,
    _In_opt_ PWSTR LogFileName,
    _In_opt_ BOOLEAN isSysLogger,
    _In_opt_ BOOLEAN isRealTimeSession){

    PEVENT_TRACE_PROPERTIES TraceProperties = nullptr;
    ULONG BufferSize;

    // Allocate memory for the session properties. The memory must
    // be large enough to include the log file name and session name,
    // which get appended to the end of the session properties structure.
    BufferSize = sizeof(EVENT_TRACE_PROPERTIES) +
        (MAXIMUM_SESSION_NAME + MAX_PATH) * sizeof(WCHAR);

    TraceProperties = (PEVENT_TRACE_PROPERTIES)malloc(BufferSize);
    if (TraceProperties == nullptr) {
        wprintf(L"Unable to allocate %d bytes for properties structure.\n", BufferSize);
        goto Exit;
    }

    //
    // Set the session properties.
    //

    ZeroMemory(TraceProperties, BufferSize);
    TraceProperties->Wnode.BufferSize = BufferSize;
    TraceProperties->Wnode.ClientContext = 2; // //QPC clock resolution=1; systemtime=2 low accuracy,but can been translate to standard time 
    TraceProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;  //indicate that the structure contains event tracing information.

    /*
    EnableFlags is only valid for system loggers;the identifier of the system loggers are as follow
    trace sessions that are started using the EVENT_TRACE_SYSTEM_LOGGER_MODE logger mode flag,
    the KERNEL_LOGGER_NAME session name, the SystemTraceControlGuid session GUID, or the GlobalLoggerGuid session GUID.
    */
    if (isSysLogger) {
        TraceProperties->Wnode.Guid = SystemTraceControlGuid;
        TraceProperties->EnableFlags = this->enable_flag;
    }

    TraceProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    TraceProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) +
        (MAXIMUM_SESSION_NAME * sizeof(WCHAR));

    // Set the session properties. You only append the log file name
    // to the properties structure; the StartTrace function appends
    // the session name for you.
    if (isRealTimeSession) {
        TraceProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    }
    else {
        TraceProperties->LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL | EVENT_TRACE_SYSTEM_LOGGER_MODE;
        //StringCbCopy((LPWSTR)((char*)TraceProperties + TraceProperties->LogFileNameOffset), (logfile_path.length() + 1) * 2, logfile_path.c_str());
    }

    TraceProperties->MaximumFileSize = 100; // Limit file size to 100MB max
    TraceProperties->BufferSize = 1024; // Use 1024KB trace buffer
//    TraceProperties->MinimumBuffers = 32;
    TraceProperties->MaximumBuffers = 1024;

    if (LoggerName != nullptr) {
        StringCchCopyW((LPWSTR)((PCHAR)TraceProperties + TraceProperties->LoggerNameOffset),
            MAXIMUM_SESSION_NAME,
            LoggerName);
    }

    if (LogFileName != nullptr) {
        StringCchCopyW((LPWSTR)((PCHAR)TraceProperties + TraceProperties->LogFileNameOffset),
            MAX_PATH,
            LogFileName);
    }

Exit:
    return TraceProperties;
}

int ETWConfiguration::mainSessionConfig(bool real_time_switch) {
start:
    ULONG status = ERROR_SUCCESS;
    TRACEHANDLE SessionHandle = 0;
    EVENT_TRACE_PROPERTIES* mainSessionProperties = nullptr;
    //PWSTR LoggerName = (PWSTR)L"MyTrace";

    mainSessionProperties = allocateTraceProperties(NULL, NULL,true);

    // Create the trace session.
    status = StartTrace(&SessionHandle, KERNEL_LOGGER_NAME, mainSessionProperties);

    if (ERROR_SUCCESS != status)
    {
        if (ERROR_ALREADY_EXISTS == status)
        {
            status = ControlTrace(SessionHandle, KERNEL_LOGGER_NAME, mainSessionProperties, EVENT_TRACE_CONTROL_STOP);
            wprintf(L"The Kernel Session is already in use.\n");
            //wprintf(L"The NT Kernel Logger session is already in use and will be finished.\n");
            wprintf(L"restart the NT Kernel Logger automaticly... .\n");
            goto start;
        }

        wprintf(L"EnableTrace() failed with %lu\n", status);
        goto cleanup;
    }

    wprintf(L"Press any key to end trace session..\n\n ");
    if (real_time_switch) {
        //enable callstack trace
        if (Initializer::getListenCallStack())
            EventCallstack::initCallStackTracing(SessionHandle);

    SetupEventConsumer((LPWSTR)KERNEL_LOGGER_NAME,TRUE);
//        std::thread tt(&ETWConfiguration::SetupEventConsumer, this, (LPWSTR) KERNEL_LOGGER_NAME, TRUE);
//        tt.detach();

        // for test events lost
//
//        while (1) {
//
//            std::this_thread::sleep_for(std::chrono::microseconds(1000000));
//            status = ControlTrace(SessionHandle, KERNEL_LOGGER_NAME, mainSessionProperties, EVENT_TRACE_CONTROL_QUERY);
//            if (ERROR_SUCCESS == status) {
//                std::this_thread::sleep_for(std::chrono::microseconds(20000000));
//                std::cout <<
//                          "  BuffersWritten:" << mainSessionProperties->BuffersWritten <<
//                          "  FreeBuffers:" << mainSessionProperties->FreeBuffers <<
//                          "  NumberOfBuffers:" << mainSessionProperties->NumberOfBuffers <<
//                          "  EventsLost:" << mainSessionProperties->EventsLost
//                          << std::endl;
//
//                if (mainSessionProperties->EventsLost > 0)
//                    int a = 0;
//            }
//        }
    }else {
        getchar();
    }

cleanup:

    if (SessionHandle)
    {
        status = ControlTrace(SessionHandle, KERNEL_LOGGER_NAME, mainSessionProperties, EVENT_TRACE_CONTROL_STOP);

        if (ERROR_SUCCESS != status)
        {
            wprintf(L"ControlTrace(stop) failed with %lu\n", status);
        }
    }

    if (mainSessionProperties)
        free(mainSessionProperties);

    return 0;

}

int ETWConfiguration::subSessionConfig(bool real_time_switch,GUID providerGUID,ULONG matchAnyKeywords, PWSTR privateLoggerName) {

start:
    ULONG status = ERROR_SUCCESS;
    TRACEHANDLE SessionHandle = 0;
    EVENT_TRACE_PROPERTIES* subSessionProperties = nullptr;
    ULONG BufferSize = 0;
    //PWSTR LoggerName = (PWSTR)L"subSession";
    subSessionProperties = allocateTraceProperties(privateLoggerName, NULL, FALSE);

    // Create the trace session.
    status = StartTraceW((PTRACEHANDLE)&SessionHandle, privateLoggerName, subSessionProperties);


    if (ERROR_SUCCESS != status)
    {
        wprintf(L"GetProcAddress failed with %lu.\n", status = GetLastError());

        if (ERROR_ALREADY_EXISTS == status)
        {

            status = ControlTraceA(SessionHandle, (LPCSTR)privateLoggerName, subSessionProperties, EVENT_TRACE_CONTROL_STOP);
            //wprintf(L"The NT Kernel Logger session is already in use.\n");
            wprintf(L"The Logger session is already in use and will be finished.\n");
            wprintf(L"restart the Logger automaticly... .\n");

            goto start;
        }
        else
        {
            wprintf(L"EnableTrace() failed with %lu\n", status);
            goto cleanup;
        }
    }

//    status = EnableTraceEx2(SessionHandle, &SystemTraceControlGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, nullptr);
    status = EnableTraceEx2(SessionHandle, &providerGUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, matchAnyKeywords, 0, 0, nullptr);
//    status = EnableTraceEx2(SessionHandle, &providerGUID, EVENT_CONTROL_CODE_CAPTURE_STATE, TRACE_LEVEL_INFORMATION, matchAnyKeywords, 0, 0, nullptr);

    //wprintf(L"Press any key to end trace session ");
    // _getch();


    if (real_time_switch) {
        SetupEventConsumer(privateLoggerName,FALSE);
        goto cleanup;
    }
    else {
        getchar();
    }

cleanup:

    if (SessionHandle)
    {
        status = ControlTrace(SessionHandle, NULL, subSessionProperties, EVENT_TRACE_CONTROL_STOP);
        status = EnableTraceEx2(SessionHandle, &providerGUID, EVENT_CONTROL_CODE_DISABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, nullptr);

        if (ERROR_SUCCESS != status)
        {
            wprintf(L"ControlTrace(stop) failed with %lu\n", status);
            wprintf(L"cleanup SubSession Config failed with %lu.\n", status = GetLastError());

        }
    }

    if (subSessionProperties)
        free(subSessionProperties);

    return 0;
}

void ETWConfiguration::allocateTraceLogFile(
    _In_opt_ PWSTR LoggerName,
    EVENT_TRACE_LOGFILE& event_logfile,
    BOOLEAN mainConsumer,
    _In_opt_ BOOLEAN isRealTimeSession) {
    
    //event_logfile = (PEVENT_TRACE_LOGFILE)malloc(sizeof(EVENT_TRACE_LOGFILE));
    ZeroMemory(&event_logfile, sizeof(EVENT_TRACE_LOGFILE));
//    event_logfile.LoggerName =  (char*)Tools::WString2String(LoggerName).c_str();
    event_logfile.LoggerName = reinterpret_cast<LPSTR>((LPWSTR) LoggerName);
    event_logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;

    if(isRealTimeSession)
        event_logfile.ProcessTraceMode |= PROCESS_TRACE_MODE_REAL_TIME;

    // ConsumeEventMain&ConsumeEventSub is the callback function. should be specified here.
    if(mainConsumer)
        event_logfile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(eventParser.ConsumeEventMain);
    else
        event_logfile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(eventParser.ConsumeEventSub);

}

void ETWConfiguration::SetupEventConsumer(LPWSTR loggerName,BOOLEAN isMainSession) {

    EVENT_TRACE_LOGFILE event_logfile;
    TRACEHANDLE event_logfile_handle;
    BOOL event_usermode = FALSE;
    DOUBLE timeStampScale;
    TRACE_LOGFILE_HEADER* event_logfile_header;
    ULONG status = ERROR_SUCCESS;
    TDHSTATUS temp_status;

    event_logfile_header = &(event_logfile.LogfileHeader);
    allocateTraceLogFile(loggerName, event_logfile,isMainSession);

    event_logfile_handle = OpenTrace(&event_logfile);

    if (INVALID_PROCESSTRACE_HANDLE == event_logfile_handle) {
        wprintf(L"OpenTrace failed with %lu\n", GetLastError());
        goto cleanup;
    }
    
    event_usermode = event_logfile_header->LogFileMode & EVENT_TRACE_PRIVATE_LOGGER_MODE;

    if (event_logfile_header->PointerSize != sizeof(PVOID)) {
        event_logfile_header = (PTRACE_LOGFILE_HEADER)((PUCHAR)event_logfile_header +
            2 * (event_logfile_header->PointerSize - sizeof(PVOID)));
    }

    // If everything go well, the program will be block here.
    // to perform the callback function defined in EventRecordCallback property
    temp_status = ProcessTrace(&event_logfile_handle, 1, 0, 0);  

    if (temp_status != ERROR_SUCCESS && temp_status != ERROR_CANCELLED) {
        wprintf(L"ProcessTrace failed with %lu\n", temp_status);
        goto cleanup;
    }

cleanup:
    if (INVALID_PROCESSTRACE_HANDLE != event_logfile_handle) {
        temp_status = CloseTrace(event_logfile_handle);
    }
}


int ETWConfiguration::ETWSessionConfig(bool real_time_switch)
{

    //bool succ1 = SubSessionConfig4MOFProvider(real_time_switch, EVENT_TRACE_FLAG_PROCESS,(LPWSTR)L"MyTrace1");
    
    //ETWConfiguration etwConfiguration;
    //this->callback = callback;

    //std::thread th2(&ETWConfiguration::MainSessionConfig, real_time_switch);
    //std::thread th2(&ETWConfiguration::my_print);

    //std::thread t1 = etwConfiguration.execThread();
    //std::thread th1(&ETWConfiguration::SubSessionConfig4XMLProvider, &etwConfiguration, real_time_switch, Kernel_Process, 0x10, (LPWSTR)L"MyTrace1");
    //std::thread th2 = etwConfiguration.startThread4MainSessionConfig(real_time_switch);
    
    //th1.join();
    //th2.join();
  
    //MainSessionConfig.
    MainSessionConfigThread  t1(*this,real_time_switch);
    t1.startThread();
    t1.wait();
    //XMLSubSessionConfigThread t1(real_time_switch, (LPWSTR)L"MyTrace1", Kernel_Process, 0x10);
    //t1.startThread();
    //t1.wait();

    //bool succ2 = MainSessionConfig(real_time_switch);

    //bool succ1 = SubSessionConfig4XMLProvider(real_time_switch, Kernel_Process, 0x10, (LPWSTR)L"MyTrace1");


    std::cout << "I am the main Thread" << std::endl;
    return 1;
}
