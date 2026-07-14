// src/domain/Utf8Accumulator.cpp
#include "Utf8Accumulator.h"

// 把一段 UTF-8 字节解码为 QString,非法字节替换为 U+FFFD 并计数。
static QString decodeUtf8(const QByteArray& bytes, int& errors) {
    const unsigned char* p = reinterpret_cast<const unsigned char*>(bytes.constData());
    int n = bytes.size();
    QString out;
    out.reserve(n);
    int i = 0;
    while (i < n) {
        unsigned char b = p[i];
        int need = 0;
        uint32_t cp = 0;
        if (b < 0x80)               { need = 1; cp = b; }
        else if ((b & 0xE0) == 0xC0){ need = 2; cp = b & 0x1F; }
        else if ((b & 0xF0) == 0xE0){ need = 3; cp = b & 0x0F; }
        else if ((b & 0xF8) == 0xF0){ need = 4; cp = b & 0x07; }
        else { ++errors; out.append(QChar(0xFFFD)); ++i; continue; }

        if (i + need > n) { // 行内末尾字节不足(buf_ 已保证切到 \n,raw 完整)→ 非法
            ++errors; out.append(QChar(0xFFFD)); ++i; continue;
        }
        bool ok = true;
        for (int j = 1; j < need; ++j) {
            unsigned char c = p[i + j];
            if ((c & 0xC0) != 0x80) { ok = false; break; }
            cp = (cp << 6) | (c & 0x3F);
        }
        if (!ok) { ++errors; out.append(QChar(0xFFFD)); ++i; continue; }
        out.append(QString::fromUcs4(&cp, 1));
        i += need;
    }
    return out;
}

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
    out = decodeUtf8(raw, errors_);
    // 去 \r 与行首 BOM 残余
    if (out.endsWith('\r')) out.chop(1);
    out.remove(QChar(0xFEFF));
    return true;
}
