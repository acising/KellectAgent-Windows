// src/domain/Utf8Accumulator.cpp
#include "Utf8Accumulator.h"

void Utf8Accumulator::feed(const QByteArray& bytes) {
    buf_ += bytes;
    if (!bomChecked_) {
        bomChecked_ = true;
        if (buf_.size() >= 3 &&
            (unsigned char)buf_[0] == 0xEF &&
            (unsigned char)buf_[1] == 0xBB &&
            (unsigned char)buf_[2] == 0xBF) {
            buf_.remove(0, 3);
        }
    }
}

bool Utf8Accumulator::takeLine(QString& out) {
    int idx = buf_.indexOf('\n');
    if (idx < 0) return false;
    QByteArray raw = buf_.left(idx);
    buf_.remove(0, idx + 1);
    // 非法序列由 QString::fromUtf8 以 U+FFFD 替换(逐序列粒度,
    // 早先手写解码器为逐字节,仅计数时代有区别,显示效果相同)
    out = QString::fromUtf8(raw);
    // 去 \r 与行内 BOM 残余
    if (out.endsWith('\r')) out.chop(1);
    out.remove(QChar(0xFEFF));
    return true;
}
