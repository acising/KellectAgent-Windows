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
    };
    explicit SettingsStore(QString path) : path_(std::move(path)) {}
    Settings load() const;
    void save(const Settings& s) const;
private:
    QString path_;
};
