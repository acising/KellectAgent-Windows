#include "tools/threadpool.h"

#include <chrono>

ThreadPool::ThreadPool(size_t size, size_t tasksLimitSize, size_t maxWorkers)
    : limit_(tasksLimitSize == 0 ? 200000 : tasksLimitSize) {
    if (size == 0) size = 1;
    if (maxWorkers < size) maxWorkers = size;
    target_.store(size);
    workers_.reserve(maxWorkers);
    for (size_t i = 0; i < maxWorkers; ++i)
        workers_.push_back(std::thread(&ThreadPool::workerLoop, this, i));
}

void ThreadPool::SetTargetWorkers(size_t count) {
    if (workers_.empty()) return;
    if (count < 1) count = 1;
    if (count > workers_.size()) count = workers_.size();
    target_.store(count);
    gateCv_.notify_all();
    cv_.notify_all();
}

ThreadPool::~ThreadPool() {
    done_.store(true);
    cv_.notify_all();
    gateCv_.notify_all();
    for (std::thread& worker : workers_) {
        if (worker.joinable())
            worker.join();
    }
}

bool ThreadPool::enqueueTask(threadParseEvent f, BaseEvent* event) {
    // Reserve before publication. A worker can dequeue as soon as enqueue
    // publishes the item, so counting afterward can underflow pending_.
    const auto previous = pending_.fetch_add(1, std::memory_order_relaxed);
    if (previous >= limit_ || !queue_.enqueue(Item{f, event})) {
        pending_.fetch_sub(1, std::memory_order_relaxed);
        return false;
    }

    if (previous == 0) {
        // Wake every idle worker once; afterwards they drain without further
        // notifications (they re-check the queue before sleeping).
        cv_.notify_all();
    }
    return true;
}

void ThreadPool::workerLoop(size_t index) {
    for (;;) {
        // Park workers above the current dynamic budget. They wake on
        // SetTargetWorkers() or shutdown.
        {
            std::unique_lock<std::mutex> gate(gateMutex_);
            gateCv_.wait(gate, [this, index] {
                return done_.load(std::memory_order_relaxed) ||
                       index < target_.load(std::memory_order_relaxed);
            });
            if (done_.load(std::memory_order_relaxed))
                return;
        }

        Item item;
        if (queue_.try_dequeue(item)) {
            pending_.fetch_sub(1, std::memory_order_relaxed);
            item.parse(item.event);
            continue;
        }

        // Empty: sleep until work arrives or the pool stops. The predicate is
        // re-evaluated under the lock, so a notify that lands between the
        // failed dequeue and the wait cannot be lost.
        std::unique_lock<std::mutex> lock(waitMutex_);
        cv_.wait_for(lock, std::chrono::milliseconds(50), [this] {
            return done_.load(std::memory_order_relaxed) ||
                   pending_.load(std::memory_order_relaxed) > 0;
        });

        if (done_.load(std::memory_order_relaxed) &&
            pending_.load(std::memory_order_relaxed) == 0)
            return;
    }
}
