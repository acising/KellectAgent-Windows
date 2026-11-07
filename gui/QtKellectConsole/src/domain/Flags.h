// src/domain/Flags.h
#pragma once
#include <QtGlobal>
#include <QVector>
#include <QString>
#include <QStringList>

namespace kellect {

enum class EventFlag : quint8 {
    Process  = 0x01,
    Thread   = 0x02,
    Image    = 0x04,
    File     = 0x08,
    Disk     = 0x10,
    Registry = 0x20,
    CallStack= 0x40,
    TcpIp    = 0x80,
};

// 位运算符:enum class 不内置 |,需显式提供(Flags 域的天然配套 API)
inline EventFlag operator|(EventFlag a, EventFlag b) {
    return static_cast<EventFlag>(static_cast<quint8>(a) | static_cast<quint8>(b));
}

inline quint8 buildMask(const QVector<EventFlag>& flags) {
    quint8 m = 0;
    for (auto f : flags) m |= static_cast<quint8>(f);
    return m;
}

inline QString maskToHex(quint8 mask) {
    return "0x" + QString::number(mask, 16).toUpper().rightJustified(2, '0');
}

inline QStringList buildKellectArgs(quint8 mask) {
    return QStringList{ "-e", maskToHex(mask), "-c" };
}

} // namespace kellect
