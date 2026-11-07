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
	// 热点路径(符号加载失败、无名文件事件等)逐事件调用 writeLog,同步落盘
	// 会把消费线程拖垮(实测事件量跌一个数量级)。在这些调用点清理掉之前,
	// 日志写入保持关闭。
	(void)msg;
}