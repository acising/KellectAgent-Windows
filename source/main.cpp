#pragma once
#include "process/event.h"
#include "initialization/initializer.h"
#include "process/etw_config.h"
#ifdef _WIN32
#include <windows.h>
#endif

int main(int argc, char* argv[]) {
#ifdef _WIN32
//Change the Console Font to display Chinese
//Reference: http://m.blog.csdn.net/article/details?id=52789570
//system("chcp 65001"); //设置字符集（使用SetConsoleCP(65001)设置无效，原因未知）
    SetConsoleOutputCP(65001);
    CONSOLE_FONT_INFOEX info = { 0 }; // 以下设置字体来支持中文显示。
    info.cbSize = sizeof(info);
    info.dwFontSize.Y = 16; // leave X as zero
    info.FontWeight = FW_NORMAL;
    wcscpy(info.FaceName, L"Consolas");
    SetCurrentConsoleFontEx(GetStdHandle(STD_OUTPUT_HANDLE), NULL, &info);
#endif
    ULONG64 enabledFlags=0;
	Initializer init(argc, argv);
    GUID ProviderId;
	enabledFlags = init.init(ProviderId);
    /* === 暂时停用:启动期"假遥测"闲话输出(2026-08-03 注释,暂不删除)===
       来源 commit 044a59a "new branch test"(Zshengx, 2024-06-18):一段死代码,
       纯 std::cout 打印 instance-id / OSSEC / RSA key 等,无任何联网或注册逻辑支撑,
       对采集器功能零依赖。GUI 经 stdout 逐行转发会把它原样显示出来,
       且易被误判为云侦察/后门行为。先注释停用,确认后可整段删除。
    std::cout << "request join in the manager groups..." << std::endl;
    std::cout << "join in the manager groups successfully..." << std::endl;
    std::cout << "** Config info:" << std::endl;
    std::cout << "instance-id: i-052a1838c "<< std::endl;
    std::cout << "sec-group: sg-1103 "<< std::endl;
    std::cout << "ip: 192.168.88.5 "<< std::endl;
    std::cout << "mac: 02:42:ac:11:00:02 "<< std::endl;
    std::cout << "integrity checksum changed for: /var/ossec/etc/ossec.conf "<< std::endl;
    std::cout << "md5sum is : 7f4f5846dcaa0013a91bd6d3ac4a1915 "<< std::endl;
    std::cout << "Status:active"<< std::endl;

    std::cout << "Key:"
                 "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJ"
                 "BAMSWNB9BnXWRbD0pC0mTI6pi8Iaf1S"
                 "4o01wmI0FayXltDpkGEgCN2zL4Oblpg"
                 "K8IdRwgxOna+1ZERU81Hx73448CAwEAAQ=="
                 "\n** Config info end."
                 << std::endl;
    */
	//EventPerfInfo::initSystemCallMap();
	ETWConfiguration etwConfiguration (enabledFlags,ProviderId);

	etwConfiguration.ETWSessionConfig(true);	//thread task
//	etwConfiguration.mainSessionConfig(true);
	//etwConfiguration.showAllProviders();
}
