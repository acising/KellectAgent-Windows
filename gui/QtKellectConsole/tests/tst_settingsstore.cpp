#include <QtTest>
#include <QTemporaryFile>
#include "domain/SettingsStore.h"

class TestSettings : public QObject { Q_OBJECT
private slots:
    void missingFileReturnsDefaults();
    void roundTrip();
    void corruptedFileReturnsDefaults();
    void removedOutputModeFallsBackToConsole();
};

void TestSettings::missingFileReturnsDefaults() {
    SettingsStore s(QDir::tempPath() + "/kellect_no_exist.json");
    auto d = s.load();
    QCOMPARE(d.autoScroll, true);
    QCOMPARE(d.lastMask, quint8(0));
    QCOMPARE(d.outputMode, 0);
    QCOMPARE(d.socketPort, quint16(0));
    QVERIFY(d.outputFile.isEmpty());
}
void TestSettings::roundTrip() {
    QString path = QDir::tempPath() + "/kellect_rt.json";
    QFile::remove(path);
    SettingsStore s(path);
    SettingsStore::Settings in;
    in.kellectExePath = "C:/kellect.exe";
    in.lastMask = 0x1F;
    in.autoScroll = false;
    in.filterKeyword = "FileIO";
    in.outputMode  = 2;
    in.outputFile  = "C:/out.log";
    in.socketHost  = "127.0.0.1";
    in.socketPort  = 6500;
    s.save(in);
    auto out = s.load();
    QCOMPARE(out.kellectExePath, in.kellectExePath);
    QCOMPARE(out.lastMask, in.lastMask);
    QCOMPARE(out.autoScroll, in.autoScroll);
    QCOMPARE(out.filterKeyword, in.filterKeyword);
    QCOMPARE(out.outputMode, in.outputMode);
    QCOMPARE(out.outputFile, in.outputFile);
    QCOMPARE(out.socketHost, in.socketHost);
    QCOMPARE(out.socketPort, in.socketPort);
}
void TestSettings::corruptedFileReturnsDefaults() {
    QString path = QDir::tempPath() + "/kellect_bad.json";
    QFile f(path); f.open(QIODevice::WriteOnly); f.write("{ not json"); f.close();
    SettingsStore s(path);
    auto d = s.load();
    QCOMPARE(d.autoScroll, true); // 默认,不崩
}

void TestSettings::removedOutputModeFallsBackToConsole() {
    QTemporaryFile file;
    QVERIFY(file.open());
    QCOMPARE(file.write("{\"outputMode\":3}"), qint64(16));
    QVERIFY(file.flush());
    SettingsStore store(file.fileName());
    QCOMPARE(store.load().outputMode, 0);
}

QTEST_GUILESS_MAIN(TestSettings)
#include "tst_settingsstore.moc"
