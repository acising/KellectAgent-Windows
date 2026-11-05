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
    outputStream.flush();   // 进程可能在任意时刻 exit(),每批写完立即落盘
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

    while (!stopRequested) {

        int tempCnt = 0;
        std::string resJson;
        std::unique_lock<std::mutex> ulk(m);

        // 攒够阈值 OR 500ms 超时 OR 收到停止信号,都走出等待。
        // 定时 flush 保证低流量时事件最迟 500ms 到达输出端;
        // requestStop() 通过 notify_all 唤醒此处并因 stopRequested 退出循环。
        while (!stopRequested && (tempCnt = count.load()) < outputThreshold) {
            if (cv.wait_for(ulk, std::chrono::milliseconds(flushIntervalMs)) == std::cv_status::timeout)
                break;
        }

        tempCnt = count.fetch_and(0);       //reset count

        std::string** sRes = new std::string*[maxDequeNumber];
        tempCnt = q.try_dequeue_bulk(sRes, maxDequeNumber);    //try to get larger items than tempCnt, return true dequeue size to tempCnt

        for (int i = 0; i < tempCnt; ++i) {
            resJson +=(*sRes[i])+"\n";
            delete sRes[i];
        }
        delete[] sRes;

        if (tempCnt > 0)
            output(resJson);
    }

    // final flush: 停止信号到达后,把队列里剩余的事件全部写出再返回
    {
        int remaining = static_cast<int>(count.exchange(0));
        if (remaining > 0 || q.size_approx() > 0) {
            std::string resJson;
            std::string** sRes = new std::string*[maxDequeNumber];
            size_t got = q.try_dequeue_bulk(sRes, maxDequeNumber);
            for (size_t i = 0; i < got; ++i) {
                resJson += (*sRes[i]) + "\n";
                delete sRes[i];
            }
            delete[] sRes;
            if (!resJson.empty())
                output(resJson);
        }
    }
}
void Output::outputStringPointer(std::string *rjson) {
    std::cout<<*rjson<<std::endl;
}