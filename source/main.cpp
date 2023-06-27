#pragma once
#include "process/event.h"
#include "initialization/initializer.h"
#include "process/etw_config.h"

int main(int argc, char* argv[]) {

    ULONG64 enabledFlags;
	Initializer init(argc, argv);

	enabledFlags = init.init();

	//EventPerfInfo::initSystemCallMap();
	ETWConfiguration etwConfiguration (enabledFlags);

	etwConfiguration.ETWSessionConfig(true);	//thread task
	etwConfiguration.mainSessionConfig(true);
	//etwConfiguration.showAllProviders();
}
