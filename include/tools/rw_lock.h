#pragma once
#include<mutex>
#include<condition_variable>

class RWLock {
private:
    //std::mutex readMtx;
    //std::mutex writeMtx;
    std::condition_variable cond;
    std::mutex mtx;

    //int readCnt;           // reader cnt
    int stat;           // reader cnt
public:
    RWLock() : stat(0) {}

    void readLock();
    void readUnLock();
    void writeLock();
    void writeUnLock();
};