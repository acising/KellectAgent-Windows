// src/ui/EventColor.h
#pragma once
#include <QString>
#include <QColor>

enum class EventDomain {
    Process, Thread, Image, File, Disk, Registry, CallStack, TcpIp, None
};

// 解析 kellect JSON 的 "Event" 字段值 → 域(按前缀)。完整前缀表 plan 期可扩。
EventDomain domainOfEvent(const QString& eventName);
// 文字色:decodeError 优先红,否则域色。
QColor textColor(EventDomain d, bool decodeError);
// 书签行背景色。
QColor markBackground();
