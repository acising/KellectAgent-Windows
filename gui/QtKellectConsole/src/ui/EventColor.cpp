// src/ui/EventColor.cpp
#include "EventColor.h"

EventDomain domainOfEvent(const QString& e) {
    if (e.startsWith("Process"))  return EventDomain::Process;
    if (e.startsWith("Thread"))   return EventDomain::Thread;
    if (e.startsWith("Image"))    return EventDomain::Image;
    if (e.startsWith("FileIO"))   return EventDomain::File;
    if (e.startsWith("DiskIO"))   return EventDomain::Disk;
    if (e.startsWith("Registry")) return EventDomain::Registry;
    if (e.startsWith("TcpIp") || e.startsWith("Tcp") || e.startsWith("Udp"))
                                 return EventDomain::TcpIp;
    if (e.startsWith("CallStack")) return EventDomain::CallStack;
    return EventDomain::None;
}

QColor textColor(EventDomain d) {
    switch (d) {
        case EventDomain::Process:  return QColor("#9CDCFE"); // 浅蓝
        case EventDomain::Thread:   return QColor("#C586C0"); // 紫
        case EventDomain::Image:    return QColor("#CE9178"); // 棕
        case EventDomain::File:     return QColor("#DCDCAA"); // 黄
        case EventDomain::Disk:     return QColor("#B5CEA8"); // 浅绿
        case EventDomain::Registry: return QColor("#4EC9B0"); // 青
        case EventDomain::CallStack:return QColor("#D7BA7D"); // 金
        case EventDomain::TcpIp:    return QColor("#F44747"); // 红(网络)
        case EventDomain::None:     return QColor("#D4D4D4"); // 默认灰
    }
    return QColor("#D4D4D4");
}

QColor markBackground() { return QColor(255, 213, 79, 60); } // 半透明琥珀
