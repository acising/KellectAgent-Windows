#pragma once
#include <WinSock2.h>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include "initialization/initializer.h"
#include "tools/ConcurrentQueue.h"

#pragma comment(lib,"ws2_32.lib")

using namespace moodycamel;
#define STATUS int
#define STATUS_FAILED -1
//#define STATUS_SUCCESS 0

class Output {

private:
	ConcurrentQueue<std::string*> q;
	std::atomic<ULONG64> count;
    ULONG outputThreshold;	//max number of events output to the destination
    std::atomic<bool> stopRequested{false};

    //const int outputThreshold = 5000;
	std::mutex m;
	std::condition_variable cv;
	const int maxDequeNumber = 15000;
    static constexpr int flushIntervalMs = 500;

protected:
	std::string ip;
	unsigned short port;
	std::string ip_port;

	bool ini = false;;
public:
	Output() :count(0) {};
	~Output() {};

	virtual STATUS init() { return STATUS_SUCCESS; };
	bool initialized() { return ini; };
	void setInit(bool i) { ini = i; };

    // 通知输出线程做 final flush 后退出(由采集停止路径调用)
    void requestStop() {
        stopRequested = true;
        cv.notify_all();
    }
    bool isStopRequested() const { return stopRequested; }

	STATUS parseIPAndPort();
    void setOutputThreashold(int threashold){
        outputThreshold = threashold;
    };

    ULONG getOutputThreashold(){
        return outputThreshold;
    }

	void pushOutputQueue(std::string* res) {
		q.enqueue(res);

		if (count.fetch_add(1) >= outputThreshold){
            cv.notify_one();
        }
	}
	void outputStrings();
 void outputStringPointer(std::string *rjson);
virtual void output(std::string outputString) {}
};

class FileOutPut : public Output {

private:
	std::string fileName;
	std::ofstream outputStream;
	std::ios_base::openmode mode;
public:
	
	FileOutPut(std::string fileName = "userout.txt", std::ios_base::openmode mode = std::ios::trunc) :
		fileName(fileName), mode(mode) {};

	~FileOutPut() { outputStream.close(); };

	virtual void output(std::string outputString) override;
	virtual STATUS init() override;
};

class ConsoleOutPut : public Output {

public:
	virtual void output(std::string outputString) override;
	virtual STATUS init() override;
};

class SocketOutPut : public Output {
public:
	SocketOutPut(std::string ip_port) {
		this->ip_port = ip_port;
	};
	//~SocketOutPut() { outputStream.close(); };

//	STATUS parseIPAndPort();
	virtual void output(std::string outputString) override;
	virtual STATUS init() override;

private:
	SOCKET socket_serv = { 0 };
	SOCKADDR_IN addr_serv = { 0 };
	//SOCKADDR_IN addr_clie = { 0 };

	int sendLen;
};

