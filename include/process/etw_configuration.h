#pragma once
#include <winsock2.h>
#include <windows.h>
#include <evntrace.h>
#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <cstdlib>

//#include "multithread_configuration.h">
//
// Guid definitions from "NT Kernel Logger Constants" section on MSDN.
//
struct __declspec(uuid("{802ec45a-1e99-4b83-9920-87c98277ba9d}")) DXGKRNL_PROVIDER_GUID_HOLDER;
static const auto DXGKRNL_PROVIDER_GUID = __uuidof(DXGKRNL_PROVIDER_GUID_HOLDER);

struct __declspec(uuid("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}")) Kernel_Process_GUID_HOLDER;
static const auto Kernel_Process = __uuidof(Kernel_Process_GUID_HOLDER);

struct __declspec(uuid("{7dd42a49-5329-4832-8dfd-43d979153a88}")) KERNEL_NETWORK_GUID_HOLDER;
static const auto Kernel_Network = __uuidof(KERNEL_NETWORK_GUID_HOLDER);

struct __declspec(uuid("{edd08927-9cc4-4e65-b970-c2560fb5c289}")) KERNEL_FILE_GUID_HOLDER;
static const auto Kernel_File = __uuidof(KERNEL_FILE_GUID_HOLDER);

class ETWConfiguration
{
public:

	//friend class BaseThread;
	//friend class MainSessionConfigThread;
	//friend class XMLSubSessionConfigThread;
	//friend class MOFSubSessionConfigThread;

	CONST INT MAXIMUM_SESSION_NAME = 1024;

	ETWConfiguration(ULONG64 enabledFalg);
	ETWConfiguration() { enable_flag = 1;};

	ETWConfiguration(const ETWConfiguration& config) { 
		enable_flag = config.enable_flag;
		logfile_path = config.logfile_path;
	};

	ETWConfiguration& operator=(const ETWConfiguration& config);
	~ETWConfiguration() {};

	INT ETWSessionConfig(bool real_time_switch);
	INT MainSessionConfig(bool real_time_switch);
	INT SubSessionConfig4XMLProvider(
		bool real_time_switch, 
		GUID providerGUID, 
		ULONG matchAnyKeywords, 
		PWSTR privateLoggerName);

	INT SubSessionConfig4MOFProvider(
		bool real_time_switch,
		ULONG enabledFlags,
		PWSTR privateLoggerName);

	VOID showAllProviders();

	INT AllocateTraceLogFile(
		_In_opt_ PWSTR LoggerName, 
		EVENT_TRACE_LOGFILE& event_logfile,
		BOOLEAN isMainConsumer = TRUE,
		_In_opt_ BOOLEAN isRealTimeSession = TRUE);

	PEVENT_TRACE_PROPERTIES AllocateTraceProperties(
		_In_opt_ PWSTR LoggerName,
		_In_opt_ PWSTR LogFileName,
		 _In_opt_ BOOLEAN isSysLogger = FALSE,
		_In_opt_ BOOLEAN isRealTimeSession = TRUE);


private:
	ULONG enable_flag;
	std::wstring logfile_path;
	inline VOID Preemption() { system("logman stop \"NT Kernel Logger\" -ets"); }
	VOID SetupEventConsumer(
		LPWSTR loggerName, 
		BOOLEAN isMainConsumer = TRUE);
};