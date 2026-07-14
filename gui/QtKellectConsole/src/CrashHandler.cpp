// src/CrashHandler.cpp
#include "CrashHandler.h"
#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QTextStream>
#include <QDateTime>
#include <QMessageLogContext>
#include <QtGlobal>
#include <exception>
#include <cstdlib>
#include <windows.h>

static void messageHandler(QtMsgType type, const QMessageLogContext& ctx, const QString& msg) {
    const char* tag = "qInfo";
    switch (type) {
        case QtDebugMsg:    tag = "qDebug"; break;
        case QtInfoMsg:     tag = "qInfo";  break;
        case QtWarningMsg:  tag = "qWarning"; break;
        case QtCriticalMsg: tag = "qCritical"; break;
        case QtFatalMsg:    tag = "qFatal"; break;
    }
    CrashHandler::write(tag, msg.toUtf8().constData());
    if (type == QtFatalMsg) std::abort();
    (void)ctx;
}

static void terminateHandler() {
    try { if (auto ep = std::current_exception()) std::rethrow_exception(ep); }
    catch (const std::exception& e) { CrashHandler::write("std::terminate", e.what()); }
    catch (...) { CrashHandler::write("std::terminate", "unknown exception"); }
    std::abort();
}

namespace CrashHandler {
void write(const char* source, const char* msg) {
    // applicationDirPath() 在 QCoreApplication 构造前(install 早于 run)为空,
    // 用 GetModuleFileNameW 兜底解析到 exe 同目录,再不行用相对路径。
    QString dir = QCoreApplication::applicationDirPath();
    if (dir.isEmpty()) {
        wchar_t buf[MAX_PATH] = {0};
        if (GetModuleFileNameW(nullptr, buf, MAX_PATH) > 0)
            dir = QFileInfo(QString::fromWCharArray(buf)).absolutePath();
    }
    QString path = dir.isEmpty() ? QStringLiteral("crash.log")
                                 : dir + QStringLiteral("/crash.log");
    QFile f(path);
    if (!f.open(QIODevice::Append | QIODevice::Text)) return;
    QTextStream s(&f);
    s << QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss.zzz")
      << " [" << source << "] " << msg << "\n";
    s.flush();
}

void install() {
    qInstallMessageHandler(messageHandler);
    std::set_terminate(terminateHandler);
}
}
