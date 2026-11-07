#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <iostream>
#include <fstream>
#include <set>
#include <string>
#define PROCESSEVENT		0x1
#define THREADEVENT			0x2
#define IMAGEEVENT			0x4
#define FILEEVENT			0x8
#define DISKEVENT			0x10
#define REGISTEREVENT		0x20
#define SYSTEMCALLEVENT		0x40
#define CALLSTACKEVENT		0x40
#define TCPIPEVENT			0x80
#define ALLEVENT 0xff

//#define EVENT 0x40
//#define SIZEOFARGV 255

#define STATUS int
#define STATUS_SUCCESS             0x0
#define STATUS_FAIL	               0x1
#define STATUS_UNKNOWN_OPTION	   0xa
#define STATUS_FORMAT_ERROR        0x8
#define STATUS_SHOW_MANUAL         0x2
#define STATUS_FILE_OPEN_FAILED	   0x3
#define STATUS_SOCKET_FORMAT_ERROR  0x11
#define STATUS_SOCKET_CONNECT_ERROR 0x12
#define STATUS_DUPLICATE_OUTPUT	   0x4
#define STATUS_SOCKET_OPEN_FAILED  0x5        //TODO
#define STATUS_EVENT_TYPE_ERROR    0x6
#define STATUS_NO_OUTPUT_OPTION    0x7

class Initializer {

public:
	Initializer(int argc, char** argV) :argc(argc), argV(argV) {
        //set default "false" to listenCallStack
//        listenCallStack = false;
    }

	// NOTE: argV is the process argv owned by the CRT - it must never be
	// deleted here (the old destructor called delete on it, which is undefined
	// behaviour), and nothing in this class takes ownership of it.
	~Initializer() {
	}

    ULONG64 init(GUID &p);

    // 生成或恢复本机唯一 UUID:优先读 config/uuid,不存在则 CoCreateGuid 并持久化
    void initHostUUID();
	inline bool validArgLength(int i, STATUS& status);
    inline bool isOutPutOption(char* option);
    inline void initDefaultEnabledEvents();
    inline STATUS InitProcessMap();

    inline STATUS initThreadProcessMap();
    STATUS initEnabledEvent(ULONG64 eventType);
    void initImages(bool background);
    //void initFilter();
    void initOutputThread();
    void initNeededStruct();
    void showCommandList(bool full = false);
    void initEventPropertiesMap(std::string confFile = "config/eventStruct_win10.xml");
    void initProcessor2ThreadAndThread2Process();
    static bool getListenCallStack(){
        return listenCallStack;
    }
    static int getStatsInterval() { return statsInterval; }
    static bool getAdaptive() { return adaptiveEnabled; }
    static void setListenCallStack(bool flag){
        listenCallStack = flag;
    }
    static void setUUID(std::string in){
        uuid = in;
    }

    static std::string getUUID(){
        return uuid;
    }

    // Internal: the supervisor passes a per-child named event; the collector
    // waits on it and calls RequestStop() for a graceful shutdown (the service
    // process has no console, so CTRL_BREAK is not available).
    const std::string& getStopEventName() const { return stopEventName; }
    const std::string& getEvidenceDirectory() const { return evidenceDirectory; }
    const std::string& getProfile() const { return profile; }
    bool getKernelEtl() const { return kernelEtl; }
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
    bool enbaleFlagsInited = false;
    static bool listenCallStack;
    static int statsInterval;
    static std::set<std::string> userDroppedEventNames;   // "-x" 或 filter.txt 指定的丢弃事件名

    static std::string uuid;
    const char* filterFileName = "config/filter.txt";
    const char* imagesFile = "config/initImages.txt";
    ULONG64 opThreashold = 20;
    std::string schemaProbeFile;    // --schema-probe <file>
    bool schemaStrict = false;      // --schema-strict
    ULONG64 maxFileMB = 0;          // --max-file-mb <n>, 0 = no rotation
    bool appendMode = false;        // --append (keep appending to the -f file)

    // Probe channel (--probe): WebSocket + MessagePack to the Kellect backend.
    // Configuration comes from config/probe.ini, with per-flag overrides.
    bool probeRequested = false;
    std::string probeConfigFile = "config/probe.ini";
    std::string probeUrl;
    std::string probeId;
    std::string probeToken;
    size_t probeQueue = 0;
    size_t probeBatch = 0;
    int probeRate = -1;

    // --serialize-threads N: JSON serialisation off the ETW callback.
    // 1 (default) preserves output order; >1 trades ordering for throughput.
    size_t serializeThreads = 1;

    // --mqtt: additive SecArgus output. Does not consume the single-primary
    // slot: with -f/--probe it wraps the primary in a TeeOutput.
    // --callstack: enable API stack collection/parsing. OFF by default: the
    // collector emits kernel events only (stacks add a second event stream and
    // significant CPU).
    bool callstackRequested = false;
    std::string prewarmMode = "adaptive";
    std::string initImagesFile = "config/initImages.txt";
    bool mqttRequested = false;
    std::string mqttConfigFile = "config\\secargus.ini";
    bool mqttConfigExplicit = false;
    // --mqtt-host / --mqtt-port: override secargus.ini without editing it.
    std::string mqttHostOverride;
    int mqttPortOverride = 0;

    // --stop-event <name>: named event the supervisor sets to stop the child.
    std::string stopEventName;
    bool helpAll = false;
    bool threadEventsEnabled = false;
    static bool adaptiveEnabled;
    bool imageEventsEnabled = false;
    std::string profile;
    std::string evidenceDirectory;
    // "behavior" (key events only) or "full" (every supported event).
    std::string stackScope = "behavior";
    bool kernelEtl = false;
    ULONG extraKernelFlags = 0;

    //user specify in the argument of option "-e"
    ULONG64 userEnabledFlags;
    ULONG64 userProvider=0;
    void initFilter();
    // Applies config\remote\desired.json written by the remote command channel.
    // Read at startup only: the collector cannot hot-reload its event mask.
    void applyDesiredConfig();
    void initPrasePool();
    int initOutputThreashold(ULONG64 flags);
    void initUserGuid(ULONG64 userProvider,GUID &ProviderId);
};
