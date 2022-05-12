#pragma once
//#include "multithread_configuration.h">
#include <winsock2.h>
#include <windows.h>
#include <evntrace.h>
#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <cstdlib>
#include "event_parse.h"

class ETWConfiguration
{

public:
    static EventParser eventParser;
    CONST INT MAXIMUM_SESSION_NAME = 1024;

public:
	ETWConfiguration(ULONG64 enabledFalg){
        enable_flag = enabledFalg;
        logfile_path = L"C:\\logfile.bin";
    };
	ETWConfiguration() { enable_flag = 1;};

	ETWConfiguration(const ETWConfiguration& config) {
		enable_flag = config.enable_flag;
		logfile_path = config.logfile_path;
	};

	ETWConfiguration& operator=(const ETWConfiguration& config);
	~ETWConfiguration() {};

	INT ETWSessionConfig(bool real_time_switch);
	INT mainSessionConfig(bool real_time_switch);
	INT subSessionConfig(
		bool real_time_switch, 
		GUID providerGUID, 
		ULONG matchAnyKeywords, 
		PWSTR privateLoggerName);

	VOID showAllProviders();

	void allocateTraceLogFile(
		_In_opt_ PWSTR LoggerName, 
		EVENT_TRACE_LOGFILE& event_logfile,
		BOOLEAN isMainConsumer = TRUE,
		_In_opt_ BOOLEAN isRealTimeSession = TRUE);

	PEVENT_TRACE_PROPERTIES allocateTraceProperties(
		_In_opt_ PWSTR LoggerName,
		_In_opt_ PWSTR LogFileName,
		 _In_opt_ BOOLEAN isSysLogger = FALSE,
		_In_opt_ BOOLEAN isRealTimeSession = TRUE);


private:
	ULONG enable_flag;
	std::wstring logfile_path;
	VOID SetupEventConsumer(
		LPWSTR loggerName, 
		BOOLEAN isMainConsumer = TRUE);
};