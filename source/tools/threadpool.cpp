#include "tools/threadpool.h"

inline ThreadPool::~ThreadPool() {

	{
		std::unique_lock<std::mutex> lock(m);
		isDone = true;
	}
	cv.notify_all();
	for (std::thread& worker : threadPool)
		worker.join();
}

void ThreadPool::addThread() {

	while (!isDone) {

		Task t;
		{
			std::unique_lock<std::mutex> ulk(m);

			while (isEmpty) {
				cv.wait(ulk);
			}

			if (this->isDone && this->tasks.empty())
				return;

			//t = std::move(tasks.front());
			t = std::move(tasks.front());
			//tasks.pop();
			tasks.pop_front();

			if (tasks.empty())	isEmpty = true;
			isFull = false;

			cv.notify_one();
		}

		t();
		
		//try to reduce cpu usage
		Sleep(0);
	}
}

void ThreadPool::enqueueTask(beginThreadParseFunc f) {

	using return_type = void;
	auto task = std::make_shared< std::packaged_task<return_type()> >(std::forward<beginThreadParseFunc>(f));

	{
		std::unique_lock<std::mutex> ulk(m);

		while (isFull) {
			cv.wait(ulk);
		}

		// don't allow enqueueing after stopping the pool
		if (isDone)
			throw std::runtime_error("enqueue on stopped ThreadPool");

		tasks.push_back([task]() { (*task)(); });
		//tasks.emplace([task]() { (*task)(); });
		isEmpty = false;
	}
	cv.notify_one();
}

void ThreadPool::enqueueTask(threadParseEvent f, BaseEvent* event)
{
	using return_type = void;

	auto task = std::make_shared< std::packaged_task<return_type()> >(
		std::bind(std::forward<threadParseEvent>(f), std::forward<BaseEvent*>(event))
		);
	//std::future<return_type> res = task->get_future();

	{
		std::unique_lock<std::mutex> ulk(m);

		while (isFull) {
			cv.wait(ulk);
		}

		// don't allow enqueueing after stopping the pool
		if (isDone)
			throw std::runtime_error("enqueue on stopped ThreadPool");

		tasks.push_back([task]() { (*task)(); });
		//tasks.emplace([task]() { (*task)(); });

		//if(tasks.size() % 1000 == 0)
			//std::cout << "                                            "<<tasks.size() << std::endl;

		//if (tasks.size() == tasksLimitSize) {
			//isFull = true;
			//std::cout << "                                    " << tasksLimitSize << std::endl;
		//}
		isEmpty = false;
	}
	cv.notify_one();
	//return res;
}

/*
void ThreadPool::enqueueTask(threadParsePeventRecord f, PEVENT_RECORD pEvent)
{
	using return_type = void;

	auto task = std::make_shared< std::packaged_task<return_type()> >(
		std::bind(std::forward<threadParsePeventRecord>(f), std::forward<PEVENT_RECORD>(pEvent))
		);
	//std::future<return_type> res = task->get_future();

	{
		std::unique_lock<std::mutex> ulk(m);

		while (isFull) {
			//std::cout << std::this_thread::get_id() << "????????" << std::endl;
			cv.wait(ulk);		//???????????????????????notify
		}

		// don't allow enqueueing after stopping the pool
		if (isDone)
			throw std::runtime_error("enqueue on stopped ThreadPool");

		tasks.push_back([task]() { (*task)(); });
		//tasks.emplace([task]() { (*task)(); });

		if (tasks.size() == tasksLimitSize)	isFull = true;

		isEmpty = false;
	}
	cv.notify_one();
	//return res;
}
*/