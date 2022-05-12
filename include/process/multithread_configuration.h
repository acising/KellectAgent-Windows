#pragma once
//#include <evntrace.h>
#include <Windows.h>
#include <iostream>
#include <string>
#include <evntrace.h>
#include <thread>
#include<mutex>
#include <cstdlib>
#include "etw_config.h"

class BaseThread {

public:	
	inline VOID detach(){ th.detach(); }
	inline VOID wait() { if(th.joinable())	th.join(); }
	bool _realTime;

protected:
	std::thread th;
	PWSTR _logFileName;
	ETWConfiguration instance;
};


class MainSessionConfigThread : public BaseThread {

public:

	MainSessionConfigThread(ETWConfiguration config, bool real_time_switch=true, PWSTR logFileName = (PWSTR)L"LogFile.etl")
	{
		instance = config;
		_realTime = real_time_switch;
		if(!_realTime)
			_logFileName = logFileName;
	};
	~MainSessionConfigThread() {};

	inline VOID startThread(){ th = std::thread(&ETWConfiguration::mainSessionConfig, &instance, _realTime); };
};

class SubSessionConfigThread : public BaseThread {

public:

    SubSessionConfigThread();
    SubSessionConfigThread(bool real_time_switch,PWSTR privateLoggerName, GUID providerGUID, ULONG matchAnyKeywords, PWSTR logFileName=(PWSTR)L"LogFile.etl") :
		_privateLoggerName(privateLoggerName), _providerGUID(providerGUID), _matchAnyKeywords(matchAnyKeywords)
	{
		_realTime = real_time_switch;
		if (!_realTime)
			_logFileName = logFileName;
		
	};
	~SubSessionConfigThread() {};

	inline VOID startThread(){ th = std::thread(&ETWConfiguration::subSessionConfig,
								&instance, _realTime, _providerGUID, _matchAnyKeywords, (LPWSTR)_privateLoggerName); }

private:
	GUID _providerGUID;
	ULONG _matchAnyKeywords;
	PWSTR _privateLoggerName;
};
