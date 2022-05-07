#include "tools/rw_lock.h"
#include<iostream>

void RWLock::readLock()
{
    std::unique_lock<std::mutex> ulk(mtx);

    while (stat < 0)
        cond.wait(ulk);
    ++stat;
}

void RWLock::readUnLock()
{
    std::unique_lock<std::mutex> ulk(mtx);

    if (--stat == 0) {       // release writeMtx when no readers
        cond.notify_one();
    }
}
void RWLock::writeLock()
{
    std::unique_lock<std::mutex> ulk(mtx);

    while (stat != 0)
        cond.wait(ulk);
    stat = -1;
}
void RWLock::writeUnLock()
{
    std::unique_lock<std::mutex> ulk(mtx);

    stat = 0;
    cond.notify_all();
}