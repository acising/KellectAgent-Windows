// src/domain/Preset.h
#pragma once
#include <QString>
#include <QVector>
#include "Flags.h"

struct Preset {
    QString name;
    QVector<kellect::EventFlag> flags; // 头文件全限定,保持头干净(不引入 using namespace)
};

QVector<Preset> defaultPresets();
