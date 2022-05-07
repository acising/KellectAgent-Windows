#pragma once
#define _CRT_SECURE_NO_WARNINGS
#pragma comment(lib , "DbgHelp.lib")
#pragma comment(lib, "diaguids.lib")
#include <windows.h>
#include <iostream>
#include <fstream>
//#include "dia2.h"
#include "DbgHelp.h"

/*defined status code*/
#define STATUS_SUCCESS               ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)    
#define STATUS_UNSUCCESSFUL (0xC0000001L)

typedef BOOL(__stdcall* IMAGEUNLOAD)(
    __in  PLOADED_IMAGE LoadedImage
    );
typedef PLOADED_IMAGE(__stdcall* IMAGELOAD)(
    __in  PSTR DllName,
    __in  PSTR DllPath
    );

typedef struct _KERNELFUNC_ADDRESS_INFORMATION {
    ULONG ulAddress;
    CHAR FuncName[50];
}KERNELFUNC_ADDRESS_INFORMATION, * PKERNELFUNC_ADDRESS_INFORMATION;

typedef struct _WIN32KFUNCINFO {          //PNTOSFUNCINFO
    ULONG ulCount;
    KERNELFUNC_ADDRESS_INFORMATION Win32KFuncInfo[1];
} WIN32KFUNCINFO, * PWIN32KFUNCINFO;

typedef BOOL(__stdcall* SYMGETSYMBOLFILE)(
    __in_opt HANDLE hProcess,
    __in_opt PCSTR SymPath,
    __in PCSTR ImageFile,
    __in DWORD Type,
    __out_ecount(cSymbolFile) PSTR SymbolFile,
    __in size_t cSymbolFile,
    __out_ecount(cDbgFile) PSTR DbgFile,
    __in size_t cDbgFile
    );

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG  Reserved[2];
    ULONG  Base;
    ULONG  Size;
    ULONG  Flags;
    USHORT Index;
    USHORT Unknown;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR   ImageName[256];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;
//extern std::map<std::string, LL> moduleName2BaseAddr;
//extern LL moduleBaseAddr[2];
typedef struct _tagSysModuleList {
    ULONG ulCount;
    SYSTEM_MODULE_INFORMATION smi[2];
} MODULES, * PMODULES;

typedef LONG  NTSTATUS;
typedef ULONG64 LL;
typedef DWORD SYSTEM_INFORMATION_CLASS;

//extern std::map<LL, std::string> addr2FuncName;
//extern std::map<LL, std::string> addr2FuncNameUsed;

typedef NTSTATUS(__stdcall* NTQUERYSYSTEMINFORMATION)
(IN     SYSTEM_INFORMATION_CLASS,
    IN OUT PVOID,
    INT    ULONG,
    OUT    PULONG OPTION);

typedef enum _SYSTEM_MODULE_INFORMATION_CLASS
{
    SystemModuleInformation = 11,
} SYSTEM_MODULE_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    //ULONG Reserved[2];
    //PBYTE  ImageBase;
    HANDLE Section;                 // Not filled in
    PVOID MappedBase;
    PVOID  ImageBase;
    //PBYTE  ImageBase;

    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

//VOID initSysNameMap();
#define PROCESSEVENT		0x1
#define THREADEVENT			0x2
#define IMAGEEVENT			0x4
#define FILEEVENT			0x8
#define DISKEVENT			0x10
#define REGISTEREVENT		0x20
#define SYSTEMCALLEVENT		0x30
#define CALLSTACKEVENT		0x40
#define TCPIPEVENT			0x50

#define FILEOUTPUT			0x0
#define CONSOLEOUTPUT		0x1
#define SOCKETOUTPUT		0x2
//#define EVENT 0x40
//#define SIZEOFARGV 255

#define STATUS int
#define STATUS_SUCCESS             0
#define STATUS_FAIL	               1
#define STATUS_SOCKET_FORMAT_ERROR 8
#define STATUS_SHOW_MANUAL         2
#define STATUS_FILE_OPEN_FAILED	   3
#define STATUS_DUPLICATE_OUTPUT	   4
#define STATUS_SOCKET_OPEN_FAILED  5        //TODO
#define STATUS_EVENT_TYPE_ERROR    6        //TODO
#define STATUS_NO_OUTPUT_OPTION    7
//#define STATUS_SHOW_MANUAL         9

class Initializer {

public:
	Initializer(int argc, char** argV) :argc(argc), argV(argV) {}

	~Initializer() {
		char* temp;
		for (int i = 0; i < argc; i++) {
			temp = argV[i];
			delete argV[i];
		}
	}

	ULONG64 init();

	inline bool validArgLength(int i, STATUS& status);
    inline bool isOutPutOption(char* option);
    inline void initEnabledFlags();

    STATUS initEnabledEvent(ULONG64 eventType);
    //static void initPropertyNames(std::wstring confFile = L"propertyName.txt");
    static void initProcessID2ModulesMap();
    static void initImages(std::string confFile = "config/initImages.txt");
    //void initFilter();
    void initOutputThread();
    void initNeededStruct();
    void initSysNameMap();
    void showCommandList();
    void initEventPropertiesMap(std::string confFile = "config/eventStruct.txt");
    void initThreadParseProviders();

    //void initOutPut();
	//STATUS initConsoleOutPut();
	//STATUS initFileOutPut(std::string fileName);
	//STATUS initSocketOutPut(std::string sSocket);
	//void initConsoleOutPut();
	//void initParser();

private:
	int argc;
	char** argV;
	bool outputInited = false;
    ULONG64 enabledFlags = 0;
    const char* eventStructFile = "config/eventstruct.txt";
    const char* filterFileName = "config/filter.txt";
    const char* imagesFile = "config/initImages.txt";

    void initFilter();
    void initPrasePool();
    BOOLEAN InitSymHandler();
    ULONG GetKernelInfo(char* lpKernelName, ULONG* ulBase, ULONG* ulSize);
    BOOLEAN LoadSymModule(char* ImageName, DWORD ModuleBase);
    BOOLEAN EnumSyms(char* ImageName, DWORD ModuleBase, PSYM_ENUMERATESYMBOLS_CALLBACK EnumRoutine, PVOID Context);
    static BOOLEAN CALLBACK EnumSymRoutine(PSYMBOL_INFO psi, ULONG SymSize, PVOID Context);
};