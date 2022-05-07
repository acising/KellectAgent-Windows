#pragma once
//#include <string>
#include <WinSock2.h>	//do not delete
#include "easylogging++.h"

using namespace el;

enum LogLevel { TRACE, DEBUG, INFO, WARN, ERR, FATAL };

class MyLogger
{

public:

	//static el::Logger* defaultLogger;

	static void initLogger(std::string confile = "log.conf");

	static void writeLog(std::string msg);
private:

	MyLogger() {}
	~MyLogger() {}
};


