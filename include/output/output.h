#pragma once
#include <WinSock2.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <mutex>
#include "initialization/initializer.h"
#include "tools/stats.h"
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
    // Backlog cap. Beyond this the producer blocks instead of dropping: the
    // stall propagates back through the serializer/parse pools to the ETW
    // callback, where the session buffers absorb the burst. Unbounded growth
    // would risk an OOM, which loses everything.
    static constexpr size_t maxQueuedEvents = 500000;

protected:
	std::string ip;
	unsigned short port;
	std::string ip_port;

	bool ini = false;;
public:
	Output() :count(0) {};
	// Virtual so the collector's single `Output* op` can be a console/file/
	// socket/probe sink (and be destroyed through the base pointer).
	virtual ~Output() {};

	// Current output backlog (diagnostics only: size_approx is a snapshot).
	size_t queuedEvents() const { return q.size_approx(); }

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
    // Called once after requestStop(): sinks that buffer internally (probe
    // channel) use it to finish draining before the process exits.
    virtual void waitFlushed(int /*timeoutMs*/) {}
    // File output only: rotate once the current file exceeds `bytes`
    // (0 = never). Ignored by the other outputs.
    virtual void setMaxFileBytes(ULONG64 bytes) { (void)bytes; }

    ULONG getOutputThreashold(){
        return outputThreshold;
    }

	void pushOutputQueue(std::string* res) {
        // Only lock when the backlog is already deep; the normal path stays
        // lock-free. `stopRequested` makes shutdown immune to a stuck writer.
        if (q.size_approx() > maxQueuedEvents) {
            std::unique_lock<std::mutex> lock(m);
            while (q.size_approx() > maxQueuedEvents && !stopRequested.load()) {
                kellect::stats::Bump(kellect::stats::outputWaits);
                cv.wait_for(lock, std::chrono::milliseconds(2));
            }
        }

		q.enqueue(res);
        kellect::stats::Bump(kellect::stats::eventsQueued);

        // Notify once per batch (exactly at the threshold) instead of on every
        // event: at 10^5 events/s the per-event notify is measurable overhead.
        // The writer's 500 ms timed wait covers any missed crossing.
		if (count.fetch_add(1) == outputThreshold){
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
	ULONG64 maxFileBytes = 0;    // 0 = no rotation
	ULONG64 writtenBytes = 0;

	void Rotate();
public:
	
	FileOutPut(std::string fileName = "userout.txt", std::ios_base::openmode mode = std::ios::trunc) :
		fileName(fileName), mode(mode) {};

	~FileOutPut() { outputStream.close(); };

	virtual void output(std::string outputString) override;
	virtual STATUS init() override;
	virtual void setMaxFileBytes(ULONG64 bytes) override { maxFileBytes = bytes; }
	// Switch to append mode. Must be called before init(); the service uses it
	// so restarting does not truncate the events already collected.
	void setAppend(bool on) { if (on) mode = std::ios::app; }
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

