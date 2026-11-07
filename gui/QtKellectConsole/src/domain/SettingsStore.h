// src/domain/SettingsStore.h
#pragma once
#include <QString>
#include <QtGlobal>

class SettingsStore {
public:
    struct Settings {
        QString kellectExePath;
        quint8 lastMask = 0;
        bool autoScroll = true;
        QString filterKeyword;
        // 输出目标(本特性新增)
        int outputMode = 0;           // 0=Console, 1=File, 2=Socket
        QString outputFile;           // File 模式路径
        QString socketHost;           // Socket 模式 host
        quint16 socketPort = 0;       // Socket 模式 port
    };
    explicit SettingsStore(QString path) : path_(std::move(path)) {}
    Settings load() const;
    void save(const Settings& s) const;
private:
    QString path_;
};
