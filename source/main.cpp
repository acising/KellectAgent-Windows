#pragma once  
#include "process/event_parse.h"
#include "process/event.h"
#include "initialization/initializer.h"
#include "process/etw_configuration.h"
#include "tools/tools.h"
#include "tools/logger.h"
#include "time.h"
void test() {

	ULONG64 ull = 18446735277922610791;
	std:: string ss = Tools::DecInt2HexStr(ull);

	ULONG64 res = Tools::HexStr2DecInt(ss);
}

int main(int argc, char* argv[]) {

	ULONG64 enabledFlags;
	Initializer init(argc, argv);

	enabledFlags = init.init();
	//ULONG64 enabledFlags = Initializer::init(argc, argv);
	//init();
	//consume_event_func_ptr func = init_collector->init(ETW_Collector_Flag);
	//1、采集内核初始化
	//2、采集工作开始

	//test();

	////EventPerfInfo::initSystemCallMap();
	//ETWConfiguration etwConfiguration = ETWConfiguration ();
	ETWConfiguration etwConfiguration (enabledFlags);

	//etwConfiguration.ETWSessionConfig(true);	//thread task
	etwConfiguration.MainSessionConfig(true);
	//etwConfiguration.showAllProviders();
}
