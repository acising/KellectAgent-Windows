// src/domain/Preset.cpp
#include "Preset.h"

using namespace kellect; // 局部 using,安全(不污染其他 TU)

QVector<Preset> defaultPresets() {
    return {
        { QStringLiteral("全部"), { EventFlag::Process, EventFlag::Thread, EventFlag::Image,
            EventFlag::File, EventFlag::Disk, EventFlag::Registry,
            EventFlag::CallStack, EventFlag::TcpIp } },
        { QStringLiteral("精简"), { EventFlag::Process, EventFlag::File } },
        { QStringLiteral("IO"),   { EventFlag::File, EventFlag::Disk, EventFlag::Registry } },
        { QStringLiteral("网络"), { EventFlag::TcpIp } },
    };
}
