#pragma once
//
// Bounded worker pool for the event pipeline.
//
// Two things matter here more than API elegance:
//   1. The ETW callback enqueues from one thread at 10^5-10^6 events/s, so the
//      producer must not take a mutex per event (the previous implementation
//      wrapped every task in shared_ptr<packaged_task> + std::function +
//      std::list node, and locked; allocator + lock traffic dominated).
//   2. enqueueTask() returns false when the backlog is full. The caller
//      retains ownership and applies its stage's overload policy.
//
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <thread>
#include <vector>

#include "process/event.h"
#include "tools/ConcurrentQueue.h"

typedef void (*threadParseEvent)(BaseEvent* event);

class ThreadPool {
public:
    ThreadPool(size_t size, size_t tasksLimitSize, size_t maxWorkers = 0);
    ~ThreadPool();

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    bool enqueueTask(threadParseEvent f, BaseEvent* event);

    // Backlog snapshot for diagnostics (relaxed, approximate under concurrency).
    size_t pending() const { return pending_.load(std::memory_order_relaxed); }
    // Dynamic worker budget: workers above the target park at the gate.
    void SetTargetWorkers(size_t count);
    size_t TargetWorkers() const { return target_.load(std::memory_order_relaxed); }

private:
    struct Item {
        threadParseEvent parse = nullptr;
        BaseEvent* event = nullptr;
    };

    void workerLoop(size_t index);

    moodycamel::ConcurrentQueue<Item> queue_;
    std::atomic<size_t> pending_{ 0 };
    std::atomic<size_t> target_{ 1 };
    std::mutex gateMutex_;
    std::condition_variable gateCv_;
    std::atomic<bool> done_{ false };
    std::mutex waitMutex_;
    std::condition_variable cv_;
    size_t limit_ = 0;
    std::vector<std::thread> workers_;
};
