#include "output/output.h"
#include "tools/logger.h"
#include "tools/tools.h"
#include <cstdio>
#include <regex>
#include <exception> 

void FileOutPut::output(std::string outputString) {

    if (!initialized())
    {
        MyLogger::writeLog("FileOutPut is not initialized.\n");
    }

    outputStream << outputString;
    outputStream.flush();   // 进程可能在任意时刻 exit(),每批写完立即落盘

    writtenBytes += outputString.size();
    if (maxFileBytes != 0 && writtenBytes >= maxFileBytes)
        Rotate();
}

// Rename the current file to <name>.YYYYMMDD-HHMMSS and continue in a fresh
// one. A service can run for weeks; without this the event file grows without
// bound. Runs on the single output thread, so no locking is required.
void FileOutPut::Rotate() {
    outputStream.close();

    SYSTEMTIME st;
    GetLocalTime(&st);
    char suffix[40];
    snprintf(suffix, sizeof(suffix), ".%04u%02u%02u-%02u%02u%02u",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    const std::string backup = fileName + suffix;
    if (!MoveFileA(fileName.c_str(), backup.c_str())) {
        // Another file with the same second-resolution name exists: overwrite.
        DeleteFileA(backup.c_str());
        MoveFileA(fileName.c_str(), backup.c_str());
    }

    outputStream.open(fileName, mode);
    writtenBytes = 0;

    if (!outputStream.is_open())
        MyLogger::writeLog("FileOutPut rotate: reopen failed for " + fileName);
}

STATUS FileOutPut::init() {
    
    STATUS status = STATUS_SUCCESS;
    // A service/CLI may point -f at a directory that does not exist yet
    // (default %ProgramData%\Kellect\events\). Creating it here keeps a missing
    // directory from being fatal to the whole collector.
    Tools::ensureParentDirectory(fileName);
    outputStream = std::ofstream(fileName,mode);

    if (outputStream.fail())
    {
        status = STATUS_FILE_OPEN_FAILED;
        //MyLogger::writeLog(fileName + "文件打开错误!\n");
    }

    if(status == STATUS_SUCCESS) {
        // Seed the rotation counter with what is already on disk (append mode
        // after a service restart), otherwise the threshold only applies to
        // bytes written by this run.
        HANDLE existing = CreateFileA(fileName.c_str(), GENERIC_READ,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (existing != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER size = {};
            if (GetFileSizeEx(existing, &size))
                writtenBytes = static_cast<ULONG64>(size.QuadPart);
            CloseHandle(existing);
        }
        setInit(true);
    }

    return status;
}

STATUS ConsoleOutPut::init() {

    setInit(true);

    return STATUS_SUCCESS;
}
void ConsoleOutPut::output(std::string outputString) {
    if (!initialized())
    {
        MyLogger::writeLog("ConsoleOutPut is not initialized.\n");
    }
    std::cout << outputString;
};

//TODO
void SocketOutPut::output(std::string outputString) {

    //char* msg = outputString.c_str();
    if (!initialized())
    {
        MyLogger::writeLog("SocketOutPut is not initialized.\n");
    }

    int len = strlen(outputString.c_str());
    sendLen = send(socket_serv, outputString.c_str(), strlen(outputString.c_str()), 0);

    //cout << "json长度：" << len << endl;
    if (sendLen < 0) {
        std::cout << "send failed, maybe server is disconnected" << std::endl;
    }
    //outputStream << outputString << std::endl;
}

STATUS Output::parseIPAndPort() {
    
    STATUS status = STATUS_SUCCESS;
    std::regex re(":");
    std::sregex_token_iterator p;
    std::sregex_token_iterator end;

    //parse ip and port from ss
    p = std::sregex_token_iterator(ip_port.begin(), ip_port.end(), re, -1);
     
    try{
        ip = *p;
        port = Tools::String2Int(*++p);

    }
    catch (std::exception& e)
    {
        std::cout << "ip and port parse failed, Standard exception: " << e.what() << std::endl;
        status = STATUS_FORMAT_ERROR;
    }

    return status;
}

STATUS SocketOutPut::init() {

    STATUS status = this->parseIPAndPort();

    if (status == STATUS_SUCCESS) {

        WSADATA ws;
        if (WSAStartup(MAKEWORD(2, 2), &ws) != 0) {
            std::cout << "load library socket failed..." << std::endl;
            system("pause");
        }
        //create socket
        //socket_clie = socket(AF_INET, SOCK_STREAM, 0);
        socket_serv = socket(AF_INET, SOCK_STREAM, 0);

        addr_serv.sin_addr.S_un.S_addr = inet_addr(ip.c_str());  //change the format of oct addr to bin addr
        addr_serv.sin_family = AF_INET;		//set the address family to IPV4
        addr_serv.sin_port = htons(port);	//change the format of oct port to bin port

        //connect the server,return STATUS_SOCKET_ERROR  if connect failed
        if (connect(socket_serv, (SOCKADDR*)&addr_serv, sizeof(addr_serv)) == SOCKET_ERROR)
        {
            std::cout << "connect server failed" << std::endl;
            status = STATUS_SOCKET_CONNECT_ERROR;

            goto rt;
        }
        else {
            std::cout << "connect server succeed,the connection has established" << std::endl;
        }

    }
    if(status == STATUS_SUCCESS)
        setInit(true);
    else
        status = STATUS_SOCKET_FORMAT_ERROR;

    rt:
    return status;
}

void Output::outputStrings(){

    // One reusable pointer array instead of a 15k-pointer allocation per wakeup.
    std::string** sRes = new std::string*[maxDequeNumber];

    while (!stopRequested) {

        int tempCnt = 0;
        std::string resJson;
        std::unique_lock<std::mutex> ulk(m);

        // Wake on the batch threshold, on the 500 ms timer, or on stop.
        while (!stopRequested && (tempCnt = count.load()) < outputThreshold) {
            if (cv.wait_for(ulk, std::chrono::milliseconds(flushIntervalMs)) == std::cv_status::timeout)
                break;
        }

        tempCnt = count.fetch_and(0);       //reset count

        tempCnt = q.try_dequeue_bulk(sRes, maxDequeNumber);    //try to get larger items than tempCnt, return true dequeue size to tempCnt

        if (tempCnt > 0)
            resJson.reserve(static_cast<size_t>(tempCnt) * 160ull + 64ull);

        for (int i = 0; i < tempCnt; ++i) {
            resJson +=(*sRes[i])+"\n";
            delete sRes[i];
        }

        if (tempCnt > 0)
            output(resJson);
    }

    // final flush: write everything still queued before returning
    {
        count.exchange(0);
        while (const size_t got = q.try_dequeue_bulk(sRes, maxDequeNumber)) {
            std::string resJson;
            resJson.reserve(got * 160ull + 64ull);
            for (size_t i = 0; i < got; ++i) {
                resJson += (*sRes[i]) + "\n";
                delete sRes[i];
            }
            if (!resJson.empty())
                output(resJson);
        }
    }

    delete[] sRes;
}
void Output::outputStringPointer(std::string *rjson) {
    std::cout<<*rjson<<std::endl;
}
