#include "output/tee_output.h"

#include <chrono>
#include <utility>

#include "tools/logger.h"

TeeOutput::TeeOutput() = default;

TeeOutput::~TeeOutput() {
    // Ask every channel to stop and drain, then join.
    for (auto& channel : channels_) {
        channel->stop.store(true);
        channel->cv.notify_all();
    }
    for (auto& channel : channels_) {
        if (channel->worker.joinable())
            channel->worker.join();
    }
}

void TeeOutput::addSink(std::unique_ptr<Output> sink, const std::string& name,
                        bool blockWhenFull) {
    if (!sink)
        return;

    std::unique_ptr<Channel> channel(new Channel());
    channel->sink = std::move(sink);
    channel->name = name;
    channel->blockWhenFull = blockWhenFull;
    channel->worker = std::thread(&TeeOutput::runChannel, this, channel.get());
    channels_.push_back(std::move(channel));
}

STATUS TeeOutput::init() {
    // A failing sink disables only itself: e.g. MQTT broker unreachable must not
    // stop the file output.
    bool anyReady = false;
    for (auto& channel : channels_) {
        const STATUS status = channel->sink->init();
        if (status != STATUS_SUCCESS) {
            MyLogger::writeLog("tee sink init failed: " + channel->name +
                               " status=" + std::to_string(status));
            continue;
        }
        anyReady = true;
    }
    setInit(anyReady);
    return STATUS_SUCCESS;
}

void TeeOutput::output(std::string outputString) {
    for (auto& channel : channels_) {
        std::unique_lock<std::mutex> lock(channel->mutex);
        if (channel->stop.load())
            continue;

        if (channel->queue.size() >= Channel::kMaxBlobs) {
            if (channel->blockWhenFull) {
                // Local sinks must not lose data: wait for their worker.
                channel->cv.wait_for(lock, std::chrono::milliseconds(200), [&channel] {
                    return channel->queue.size() < Channel::kMaxBlobs ||
                           channel->stop.load();
                });
            }
            while (channel->queue.size() >= Channel::kMaxBlobs) {
                channel->queue.pop_front();
                channel->dropped.fetch_add(1);
            }
        }

        channel->queue.push_back(outputString);   // one copy per sink (batch level)
        channel->cv.notify_one();
    }
}

void TeeOutput::runChannel(Channel* channel) {
    for (;;) {
        std::string blob;
        {
            std::unique_lock<std::mutex> lock(channel->mutex);
            channel->cv.wait(lock, [channel] {
                return channel->stop.load() || !channel->queue.empty();
            });

            if (channel->queue.empty()) {
                if (channel->stop.load())
                    return;
                continue;
            }
            blob = std::move(channel->queue.front());
            channel->queue.pop_front();
            channel->cv.notify_all();   // wake a blocked producer
        }

        if (!channel->sink->initialized()) {
            // Sink init failed (e.g. spool directory unavailable): drop and
            // count instead of feeding an unusable sink.
            channel->dropped.fetch_add(1);
            continue;
        }

        channel->sink->output(blob);
    }
}
void TeeOutput::waitFlushed(int timeoutMs) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeoutMs);

    for (auto& channel : channels_) {
        for (;;) {
            size_t pending = 0;
            {
                std::lock_guard<std::mutex> lock(channel->mutex);
                pending = channel->queue.size();
            }
            if (pending == 0 || std::chrono::steady_clock::now() >= deadline)
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        channel->sink->waitFlushed(
            static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count()));
    }

    for (auto& channel : channels_) {
        channel->stop.store(true);
        channel->cv.notify_all();
    }
}
