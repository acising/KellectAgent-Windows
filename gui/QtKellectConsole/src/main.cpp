// src/main.cpp
#include <QApplication>
#include <QFile>
#include <QtPlugin>
#include "ui/MainWindow.h"
#include "domain/SettingsStore.h"
#include "CrashHandler.h"
#include <QStandardPaths>
#include <windows.h>

Q_IMPORT_PLUGIN(QWindowsIntegrationPlugin)

static int run(int argc, char* argv[]) {
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
    QApplication app(argc, argv);

    QFile qss(":/dark.qss");
    if (qss.open(QIODevice::ReadOnly)) app.setStyleSheet(QString::fromUtf8(qss.readAll()));

    QString settingsPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                           + "/KellectConsole/settings.json";
    SettingsStore store(settingsPath);

    MainWindow w(&store);
    w.show();
    return app.exec();
}

int main(int argc, char* argv[]) {
    CrashHandler::install();
    __try {
        return run(argc, argv);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        CrashHandler::write("SEH", "unstructured exception (access violation etc.)");
        return 1;
    }
}
