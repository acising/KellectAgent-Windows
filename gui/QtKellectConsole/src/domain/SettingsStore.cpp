// src/domain/SettingsStore.cpp
#include "SettingsStore.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>

SettingsStore::Settings SettingsStore::load() const {
    Settings d; // defaults
    QFile f(path_);
    if (!f.open(QIODevice::ReadOnly)) return d;
    QJsonParseError err;
    auto doc = QJsonDocument::fromJson(f.readAll(), &err);
    f.close();
    if (err.error != QJsonParseError::NoError || !doc.isObject()) return d;
    auto o = doc.object();
    d.kellectExePath = o.value("kellectExePath").toString();
    d.lastMask        = static_cast<quint8>(o.value("lastMask").toInt(0));
    d.autoScroll      = o.value("autoScroll").toBool(true);
    d.filterKeyword   = o.value("filterKeyword").toString();
    return d;
}

void SettingsStore::save(const Settings& s) const {
    QJsonObject o;
    o["kellectExePath"] = s.kellectExePath;
    o["lastMask"]       = s.lastMask;
    o["autoScroll"]     = s.autoScroll;
    o["filterKeyword"]  = s.filterKeyword;
    QFile f(path_);
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        f.write(QJsonDocument(o).toJson(QJsonDocument::Indented));
}
