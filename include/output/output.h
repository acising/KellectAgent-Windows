#pragma once
#include <WinSock2.h>
#include "initialization/initializer.h"
#include "tools/ConcurrentQueue.h"

#pragma comment(lib,"ws2_32.lib")

using namespace moodycamel;
#define output2console 0x0
#define output2file	   0x1
#define output2kafka   0x2
#define output2socket   0x4
#define STATUS int
#define STATUS_FAILED -1
#define STATUS_SUCCESS 0
#define STATUS_SOCKET_ERROR -2

class OutPut {

private:
	ConcurrentQueue<std::string*> q;
	std::atomic<int> count;
	const int outputThreshold = 10000;	//max number of events output to the destination
	//const int outputThreshold = 5000;
	std::mutex m;
	std::condition_variable cv;
	const int maxDequeNumber = 15000;

protected:
	bool ini = false;
	//boost::lockfree::queue<std::string, boost::lockfree::fixed_sized<false> > queue(5000);
	virtual void output(std::string outputString) {};
public:
	OutPut() :count(0) {};
	~OutPut() {};

	virtual STATUS init() { return STATUS_SUCCESS; };
	bool initialized() { return ini; };
	void setInit(bool i) { ini = i; };

	void pushOutputQueue(std::string* res) {
		q.enqueue(res);
		//count++;
		if (count.fetch_add(1) > outputThreshold)	cv.notify_one();
	}
	void outputStrings();
};

class FileOutPut : public OutPut {

private:
	std::string fileName;
	std::ofstream outputStream;
	std::ios_base::openmode mode;
public:
	
	FileOutPut(std::string fileName = "fileOutPut.txt", std::ios_base::openmode mode = std::ios::trunc) :
		fileName(fileName), mode(mode) {};

	~FileOutPut() { outputStream.close(); };

	virtual void output(std::string outputString) override;
	virtual STATUS init() override;
};

class ConsoleOutPut : public OutPut {

public:
	virtual void output(std::string outputString) override;
	virtual STATUS init() override;
};

class KafkaOutPut : public OutPut {

public:
	virtual void output(std::string outputString) override;
	virtual STATUS init() override;
};

class SocketOutPut : public OutPut {
public:
	SocketOutPut(std::string ss) :ss(ss) {};
	//~SocketOutPut() { outputStream.close(); };

	STATUS parseIPAndPort();
	virtual void output(std::string outputString) override;
	virtual STATUS init() override;

private:
	SOCKET socket_serv = { 0 };
	SOCKADDR_IN addr_serv = { 0 };
	//SOCKADDR_IN addr_clie = { 0 };

	std::string ip;
	int port;
	int sendLen;

	std::string ss;
};

