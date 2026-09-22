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
#define MAXIMUM_SESSION_NAME 1024
extern VOID WINAPI GetPropertiesByTdh(PEVENT_RECORD pEvent);

namespace {
// Stop a session by logger name with a self-contained properties buffer
// (ControlTrace accepts sessionHandle=0 when the logger name is given).
void stopSessionByName(const char* loggerName) {
    const size_t size = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(WCHAR);
    EVENT_TRACE_PROPERTIES* props = (EVENT_TRACE_PROPERTIES*)calloc(size, 1);
    if (!props) return;
    props->Wnode.BufferSize = (ULONG)size;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    ControlTraceA((TRACEHANDLE)0, loggerName, props, EVENT_TRACE_CONTROL_STOP);
    free(props);
}

// Console Ctrl+C/Break handler (registered for GUI-hosted runs): stopping the
// session unblocks ProcessTrace, so the normal cleanup path (ControlTrace stop
// + properties free in mainSessionConfig/subSessionConfig) runs and the
// process exits naturally. Without this, killing the process leaves the NT
// Kernel Logger active and the next start fights over it (StartTrace 183).
BOOL WINAPI consoleCtrlHandler(DWORD ctrlType) {
    switch (ctrlType) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            stopSessionByName(KERNEL_LOGGER_NAME);
            stopSessionByName("MyTrace");
            return TRUE;    // handled: let the consumer thread unwind and exit
        default:
            return FALSE;
    }
}
} // namespace

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
    TraceProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + (MAXIMUM_SESSION_NAME * sizeof(WCHAR));

    // Set the session properties. You only append the log file name
    // to the properties structure; the StartTrace function appends the session name for you.

    if (isRealTimeSession) {
        TraceProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    }
    else {
        TraceProperties->LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL | EVENT_TRACE_SYSTEM_LOGGER_MODE;
        //StringCbCopy((LPWSTR)((char*)TraceProperties + TraceProperties->LogFileNameOffset), (logfile_path.length() + 1) * 2, logfile_path.c_str());
    }

    TraceProperties->MinimumBuffers = 100;   // 预留 100 个缓冲(内存下限)
    TraceProperties->BufferSize = 1024;      // 每缓冲 1MB
    TraceProperties->MaximumBuffers = 1024;  // 缓冲数上限
    TraceProperties->FlushTimer = 1;         // 最长 1 秒强制刷给实时消费者(与系统默认一致,显式自文档)

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

    std::cout << "Step 1: Allocating trace properties..." << std::endl;
    mainSessionProperties = allocateTraceProperties(NULL, NULL,true);
    if (mainSessionProperties == nullptr) {
        std::cerr << "Failed to allocate trace properties" << std::endl;
        return 1;
    }

    std::cout << "Step 2: Starting trace session..." << std::endl;
    // Create the trace session.
    status = StartTrace(&SessionHandle, KERNEL_LOGGER_NAME, mainSessionProperties);

    if (ERROR_SUCCESS != status)
    {
        std::cerr << "StartTrace failed with error: " << status << std::endl;
        if (ERROR_ALREADY_EXISTS == status)
        {
            std::cout << "Kernel session already exists, stopping it..." << std::endl;
            status = ControlTrace(SessionHandle, KERNEL_LOGGER_NAME, mainSessionProperties, EVENT_TRACE_CONTROL_STOP);
            std::cout << "Restarting the NT Kernel Logger..." << std::endl;
            goto start;
        }

        std::cerr << "StartTrace failed with %lu" << status << std::endl;
        goto cleanup;
    }

    std::cout << "Step 3: Trace session started successfully!" << std::endl;
    std::cout << "Press any key to end trace session..\n\n " << std::endl;
    if (real_time_switch) {
        //enable callstack trace
        if (Initializer::getListenCallStack()) {
            std::cout << "Step 4: Initializing callstack tracing..." << std::endl;
            EventCallstack::initCallStackTracing(SessionHandle);
        }

        std::cout << "Step 5: Setting up event consumer..." << std::endl;
        SetupEventConsumer((LPWSTR)KERNEL_LOGGER_NAME,TRUE);

    }else {
        std::cout << "Step 4: Waiting for user input..." << std::endl;
        getchar();
    }

cleanup:

    std::cout << "Step 6: Cleaning up resources..." << std::endl;
    if (SessionHandle)
    {
        status = ControlTrace(SessionHandle, KERNEL_LOGGER_NAME, mainSessionProperties, EVENT_TRACE_CONTROL_STOP);

        // 4201(ERROR_WMI_INSTANCE_NOT_FOUND)/4200(ERROR_WMI_GUID_NOT_FOUND):
        // 会话已被控制台处理器先行停掉(优雅停止的正常双停),不算失败。
        // 两码别记反:4201 是 INSTANCE、4200 是 GUID(SDK winerror.h 实测)
        if (ERROR_SUCCESS != status &&
            status != ERROR_WMI_INSTANCE_NOT_FOUND &&
            status != ERROR_WMI_GUID_NOT_FOUND)
        {
            std::cerr << "ControlTrace(stop) failed with " << status << std::endl;
        }
    }

    if (mainSessionProperties) {
        free(mainSessionProperties);
        std::cout << "Step 7: Trace properties freed" << std::endl;
    }

    std::cout << "mainSessionConfig completed" << std::endl;
    return 0;

}
PEVENT_TRACE_PROPERTIES AllocateTraceProperties(
        _In_opt_ PSTR LoggerName,
        _In_opt_ PSTR LogFileName
){
    PEVENT_TRACE_PROPERTIES TraceProperties = NULL;
    ULONG BufferSize;
    BufferSize = sizeof(EVENT_TRACE_PROPERTIES) +
                 (MAXIMUM_SESSION_NAME + MAX_PATH) * sizeof(WCHAR);
    TraceProperties = (PEVENT_TRACE_PROPERTIES)malloc(BufferSize);
    if (TraceProperties == NULL) {
        wprintf(L"Unable to allocate %d bytes for properties structure.\n", BufferSize);
        goto Exit;
    }
    ZeroMemory(TraceProperties, BufferSize);

    TraceProperties->Wnode.BufferSize = BufferSize;
    TraceProperties->Wnode.ClientContext = 1; // Use QueryPerformanceCounter for time stamps
    TraceProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    TraceProperties->FlushTimer = 1;          // 最长 1 秒强制刷
    TraceProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    TraceProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) +
                                         (MAXIMUM_SESSION_NAME * sizeof(WCHAR));
    TraceProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    TraceProperties->MaximumFileSize = 1; // 单文件上限 1MB(仅文件模式生效)
    TraceProperties->BufferSize = 5120; // 每缓冲 5MB
    TraceProperties->MinimumBuffers = 128; // 预留 128 个缓冲
    TraceProperties->MaximumBuffers = 512;
    if (LoggerName != NULL) {
        StringCchCopy((LPSTR)((PCHAR)TraceProperties + TraceProperties->LoggerNameOffset),
                      MAXIMUM_SESSION_NAME,
                      LoggerName);
    }

    if (LogFileName != NULL) {
        StringCchCopy((LPSTR)((PCHAR)TraceProperties + TraceProperties->LogFileNameOffset),
                      MAX_PATH,
                      LogFileName);
    }

    Exit:
    return TraceProperties;
}
int __CLRCALL_PURE_OR_STDCALL ETWConfiguration::ConsumeUserEventMain(PEVENT_RECORD pEvent) {
    eventParser.ConsumeUserEvent(pEvent);
    auto nOpCode = pEvent->EventHeader.EventDescriptor.Opcode;
    if (nOpCode != 32) return 0;

    if (pEvent->ExtendedData && pEvent->ExtendedDataCount) {
        //never touch here
        std::cout << "maybe I got stack info in CSwitch Event" << std::endl;
    }
    return 0;
}
int ETWConfiguration:: SetupUserEventConsumer( PSTR LoggerName) {

    EVENT_TRACE_LOGFILE event_logfile;
    TRACEHANDLE event_logfile_handle;
    BOOL event_usermode = FALSE;
    DOUBLE timeStampScale;
    TRACE_LOGFILE_HEADER* event_logfile_header;
    event_logfile_header = &event_logfile.LogfileHeader;
    ZeroMemory(&event_logfile, sizeof(EVENT_TRACE_LOGFILE));
    event_logfile.LoggerName = LoggerName; //指定消费事件的来源——自定义会话
    ETWConfiguration etwConfiguration ;
    event_logfile.EventRecordCallback =(PEVENT_RECORD_CALLBACK)ConsumeUserEventMain;
    event_logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD| PROCESS_TRACE_MODE_REAL_TIME;
    event_logfile_handle = OpenTrace(&event_logfile);
    if (INVALID_PROCESSTRACE_HANDLE == event_logfile_handle) {
        wprintf(L"OpenTrace failed with %lu\n", GetLastError());
    }
    event_usermode = event_logfile_header->LogFileMode & EVENT_TRACE_PRIVATE_LOGGER_MODE;
    if (event_logfile_header->PointerSize != sizeof(PVOID)) {
        event_logfile_header = (PTRACE_LOGFILE_HEADER)((PUCHAR)event_logfile_header +
                                                       2 * (event_logfile_header->PointerSize - sizeof(PVOID)));
    }

    TDHSTATUS temp_status = ProcessTrace(&event_logfile_handle, 1, 0, 0);
    if (temp_status != ERROR_SUCCESS && temp_status != ERROR_CANCELLED) {
        wprintf(L"ProcessTrace failed with %lu\n", temp_status);
        goto cleanup;
    }
    cleanup:
    if (INVALID_PROCESSTRACE_HANDLE != event_logfile_handle) {
        temp_status = CloseTrace(event_logfile_handle);
    }
    return 0;
}
int ETWConfiguration::subSessionConfig(bool real_time_switch,GUID providerGUID,ULONG matchAnyKeywords, PWSTR privateLoggerName) {

start:
    PSTR LoggerName = (PSTR)"MyTrace";
    PSTR LogsPath = (PSTR)"ASDW.etl";
    ULONG status = ERROR_SUCCESS;
    TRACEHANDLE SessionHandle = 0;
    EVENT_TRACE_PROPERTIES* subSessionProperties = nullptr;
    ULONG BufferSize = 0;
    //PWSTR LoggerName = (PWSTR)L"subSession";
    subSessionProperties = AllocateTraceProperties(LoggerName, LogsPath);
    HeapSetInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);
    // Create the trace session.
    status = StartTrace(&SessionHandle, LoggerName, subSessionProperties);


    if (ERROR_SUCCESS != status)
    {
        wprintf(L"GetProcAddress failed with %lu.\n", status = GetLastError());

        if (ERROR_ALREADY_EXISTS == status)
        {

            status = ControlTrace(SessionHandle, LoggerName, subSessionProperties, EVENT_TRACE_CONTROL_STOP);
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


    status = EnableTraceEx2(SessionHandle, &providerGUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, nullptr);
    wprintf(L"status is %lu\n", status );
    if (real_time_switch) {
        SetupUserEventConsumer(LoggerName);
        goto cleanup;
    }
    else {
        getchar();
    }

cleanup:

    if (SessionHandle)
    {
        status = ControlTrace(SessionHandle, NULL, subSessionProperties, EVENT_TRACE_CONTROL_STOP);

        // 会话已被控制台处理器停掉,属正常双停(4201=INSTANCE/4200=GUID)
        if (ERROR_SUCCESS != status &&
            status != ERROR_WMI_INSTANCE_NOT_FOUND &&
            status != ERROR_WMI_GUID_NOT_FOUND)
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
//        std::cout<<"123123"<<std::endl;
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
    SetConsoleCtrlHandler(consoleCtrlHandler, TRUE);

    GUID guid={} ;
    PWSTR LoggerName = L"MyTrace";
    ULONG matchAnyKeywords=0;
     if(enable_flag!=0 ) {
        std::cout << "kernel session start, mask = 0x" << std::hex << enable_flag << std::dec << std::endl;
        MainSessionConfigThread t1(*this, real_time_switch);
        t1.startThread();
        t1.wait();
    }
     else  if(ProviderId != guid) {
         std::cout<<"user start"<<enable_flag <<std::endl;
        SubSessionConfigThread t2(*this, real_time_switch, LoggerName, ProviderId, matchAnyKeywords);
        t2.startThread();
        t2.wait();
    }


    return 1;
}
