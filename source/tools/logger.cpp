#include "tools/logger.h"
#include "tools/easylogging++.h"

void MyLogger::initLogger(std::string confile) {

	//defaultLogger = Loggers::getLogger("default");

	Configurations conf(confile);
	Loggers::reconfigureAllLoggers(conf);
	el::Loggers::setDefaultConfigurations(conf);
	//LOG(ERROR) << "-----error log";
	//LOG(WARNING) << "-----warning log";
	//LOG(INFO) << "-----info log";
	//LOG(TRACE) << "-----trace log";
	//LOG(DEBUG) << "-----debug log";
}

void MyLogger::writeLog(std::string msg) {
	//LOG(DEBUG) <<msg; 
//	std::cout <<msg <<std::endl;
}