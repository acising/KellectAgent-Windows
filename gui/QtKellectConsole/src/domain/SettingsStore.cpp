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
    d.outputMode  = o.value("outputMode").toInt(0);
    d.outputFile  = o.value("outputFile").toString();
    d.socketHost  = o.value("socketHost").toString();
    d.socketPort  = static_cast<quint16>(o.value("socketPort").toInt(0));
    d.kafkaBroker = o.value("kafkaBroker").toString();
    d.kafkaTopic  = o.value("kafkaTopic").toString();
    d.runAsService = o.value("runAsService").toBool(false);
    d.serviceName  = o.value("serviceName").toString(QStringLiteral("KellectService"));
    return d;
}

void SettingsStore::save(const Settings& s) const {
    QJsonObject o;
    o["kellectExePath"] = s.kellectExePath;
    o["lastMask"]       = s.lastMask;
    o["autoScroll"]     = s.autoScroll;
    o["filterKeyword"]  = s.filterKeyword;
    o["outputMode"]  = s.outputMode;
    o["outputFile"]  = s.outputFile;
    o["socketHost"]  = s.socketHost;
    o["socketPort"]  = s.socketPort;
    o["kafkaBroker"] = s.kafkaBroker;
    o["kafkaTopic"]  = s.kafkaTopic;
    o["runAsService"] = s.runAsService;
    o["serviceName"]  = s.serviceName;
    QFile f(path_);
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        f.write(QJsonDocument(o).toJson(QJsonDocument::Indented));
}
