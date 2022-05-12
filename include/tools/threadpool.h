#pragma once
#include <thread>
#include <mutex>
#include <future>
#include <condition_variable>
#include <functional>
#include <queue>
#include "process/event.h"

typedef std::function<void()> Task;
typedef void (*threadParseEvent)(BaseEvent* event);
typedef void (*threadParsePeventRecord)(PEVENT_RECORD pEvent);
typedef void (*beginThreadParseFunc)();

class ThreadPool {
private:
	static const int MaxThreadSize = 65535;

public:
	size_t poolSize = 0;
	size_t tasksLimitSize = 0;
	std::vector <std::thread> threadPool;
	std::list<Task> tasks;
	//std::queue<Task> tasks;
	bool isDone;
	bool isEmpty;
	bool isFull;
	//static std::atomic<int> threadCounts[MaxThreadSize];

	std::mutex m;
	std::condition_variable cv;

	inline ThreadPool() {};
	inline ThreadPool(size_t size,size_t tasksLimitSize) :isDone(false), isEmpty(true), isFull(false), poolSize(size), tasksLimitSize(tasksLimitSize){
		for (int i = 0; i < size; i++) {
			//添加线程
			threadPool.push_back(std::thread(&ThreadPool::addThread, this));
		}
	};

	inline ~ThreadPool();
	//void addTask(const Task& task);

	//template<class F, class... Args> 
	//auto enqueueTask(F&& f, Args&&... args)->std::future<decltype(f(args...))>;

	void enqueueTask(threadParseEvent f,BaseEvent* event);
	void enqueueTask(beginThreadParseFunc f);
	//void enqueueTask(threadParsePeventRecord f, PEVENT_RECORD pEvent);

	void addThread();
};
