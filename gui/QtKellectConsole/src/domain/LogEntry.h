// src/domain/LogEntry.h
#pragma once
#include <QDateTime>
#include <QString>

struct LogEntry {
    QDateTime time;
    QString text;          // 原始整行
    int decodeErrors = 0;
    bool marked = false;
    // 由 parseKellectLine 填充的分列字段(调用方负责解析)
    QString event;         // JSON 的 "Event" 值
    QString pid;           // 归一化 ID(PID > ProcessId > TTID > TThreadId)
    QString pname;         // JSON 的 "PName" 值(进程名)
    QString detail;        // 剩余键的 key=value 拼接
};
