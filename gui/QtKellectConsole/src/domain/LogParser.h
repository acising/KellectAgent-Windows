// src/domain/LogParser.h
#pragma once
#include <QString>

// 解析单行 kellect JSON 日志为列对齐所需字段(纯逻辑,无 Qt 依赖之外的副作用)。
// 容错策略:event/pid/pname 始终用正则抽取(即便 JSON 非法也能对齐前几列);
// detail 仅在整行可解析时由键值拼接,否则整行回退。
struct ParsedLine {
    QString event;   // JSON 的 "Event" 值;正则抽取,非 JSON 行为空
    QString pid;     // 正则抽取:"PID" > "ProcessId" > "TTID" > "TThreadId"(首个匹配)
    QString pname;   // JSON 的 "PName" 值;正则抽取
    QString detail;  // 优先级排序的 key=value 拼接;解析失败时为整行原文
};

ParsedLine parseKellectLine(const QString& raw);
