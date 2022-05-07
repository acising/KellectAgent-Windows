#include "output/output.h"
#include "tools/logger.h"
#include "tools/tools.h"
#include <regex>
#include <exception> 

void FileOutPut::output(std::string outputString) {

    if (!initialized())
    {
        MyLogger::writeLog("FileOutPut is not initialized.\n");
    }

    outputStream << outputString;
}

STATUS FileOutPut::init() {
    
    STATUS status = STATUS_SUCCESS;
    outputStream = std::ofstream(fileName,mode);

    if (outputStream.fail())
    {
        status = STATUS_FILE_OPEN_FAILED;
        //MyLogger::writeLog(fileName + "文件打开错误!\n");
    }

    if(status == STATUS_SUCCESS)
        setInit(true);

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

STATUS SocketOutPut::parseIPAndPort() {
    
    STATUS status = STATUS_SUCCESS;
    std::regex re(":");
    std::sregex_token_iterator p;
    std::sregex_token_iterator end;

    //parse ip and port from ss
    p = std::sregex_token_iterator(ss.begin(), ss.end(), re, -1);
     
    try{
        ip = *p;
        port = Tools::String2Int(*++p);

    }
    catch (std::exception& e)
    {
        std::cout << "ip and port parse failed, Standard exception: " << e.what() << std::endl;
        status = STATUS_SOCKET_FORMAT_ERROR;
    }

    return status;
}

STATUS SocketOutPut::init() {

    STATUS status = parseIPAndPort();

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
            status = STATUS_SOCKET_ERROR;
        }
        else {
            std::cout << "connect server succeed,the connection has established" << std::endl;
        }

    }
    if(status == STATUS_SUCCESS)
        setInit(true);

    return status;
}

void OutPut::outputStrings(){

    while (true) {

        int tempCnt = 0;
        std::string resJson;
        std::unique_lock<std::mutex> ulk(m);

        while ((tempCnt = count.load()) < outputThreshold) {

            cv.wait(ulk);
            //std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            //output("输出队列未满，继续等待\n");
        }
        tempCnt = count.fetch_and(0);       //reset count

        std::string** sRes = new std::string*[maxDequeNumber];
        tempCnt = q.try_dequeue_bulk(sRes, maxDequeNumber);    //try to get larger items than tempCnt, return true dequeue size to tempCnt

        for (int i = 0; i < tempCnt; ++i) {
            resJson +=(*sRes[i])+"\n";
            //if ((*sRes[i]).size() < 10)
            //    int a = 0;
            //output(*sRes[i]);
            delete sRes[i];
        }
        delete[] sRes;

        output(resJson);
    }
}