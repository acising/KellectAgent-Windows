#pragma once
//
// Output fan-out: one batch blob is delivered to every sink independently.
//
// EventParser::op owns one sink. Use the tee to add MQTT alongside that sink.
// Each sink gets its own bounded queue and worker thread, so
// a slow/broken sink (MQTT broker down) cannot stall the
// others or the ETW pipeline. Sinks that must not lose data (console, file,
// socket) block the tee when their queue is full; lossy-by-policy sinks (MQTT
// has its own spool) drop the oldest blob and count it.
//
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "output/output.h"

class TeeOutput : public Output {
public:
    TeeOutput();
    ~TeeOutput() override;

    // Ownership of `sink` moves into the tee. blockWhenFull=false makes the
    // channel drop the oldest blob instead of blocking the tee.
    void addSink(std::unique_ptr<Output> sink, const std::string& name, bool blockWhenFull);

    STATUS init() override;
    void output(std::string outputString) override;
    void waitFlushed(int timeoutMs) override;

private:
    struct Channel {
        std::unique_ptr<Output> sink;
        std::string name;
        bool blockWhenFull = true;
        std::deque<std::string> queue;
        std::mutex mutex;
        std::condition_variable cv;
        std::thread worker;
        std::atomic<bool> stop{ false };
        std::atomic<unsigned long long> dropped{ 0 };
        static constexpr size_t kMaxBlobs = 512;
    };

    void runChannel(Channel* channel);
    std::vector<std::unique_ptr<Channel>> channels_;
};
