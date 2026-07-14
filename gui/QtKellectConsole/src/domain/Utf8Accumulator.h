// src/domain/Utf8Accumulator.h
#pragma once
#include <QByteArray>
#include <QString>

class Utf8Accumulator {
public:
    void feed(const QByteArray& bytes);
    bool takeLine(QString& out); // 弹出一个完整解码行;无完整行返回 false
    int errorCount() const { return errors_; }
private:
    QByteArray buf_;     // 未切行的累积字节(含跨行残余多字节)
    int errors_ = 0;
    bool bomChecked_ = false;
};
