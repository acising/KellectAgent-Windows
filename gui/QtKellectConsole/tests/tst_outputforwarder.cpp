#include <QtTest>
#include <QSignalSpy>
#include <QFile>
#include <QDir>
#include <QTcpServer>
#include <QTcpSocket>
#include <QHostAddress>
#include "process/OutputForwarder.h"

class TestOutputForwarder : public QObject { Q_OBJECT
private slots:
    void noneModeIsNoop();
    void fileModeWritesLines();
    void fileOpenFailEmitsErrorAndReverts();
    void setModeFileToNoneFlushes();
    void socketModeForwardsLines();
};

void TestOutputForwarder::noneModeIsNoop() {
    OutputForwarder f;
    f.setMode(OutputForwarder::Mode::None);
    f.writeLine("anything");   // 不崩、不建文件
    QCOMPARE(f.mode(), OutputForwarder::Mode::None);
}

void TestOutputForwarder::fileModeWritesLines() {
    const QString path = QDir::tempPath() + "/kellect_fwd.txt";
    QFile::remove(path);
    OutputForwarder f;
    f.setFile(path);
    f.setMode(OutputForwarder::Mode::File);
    f.writeLine("line1");
    f.writeLine("line2");
    f.close();
    QFile rf(path);
    QVERIFY(rf.open(QIODevice::ReadOnly | QIODevice::Text));
    QCOMPARE(QString::fromUtf8(rf.readAll()), QStringLiteral("line1\nline2\n"));
}

void TestOutputForwarder::fileOpenFailEmitsErrorAndReverts() {
    // 父目录不存在 → QFile::open 必失败(不创建目录),跨机器可靠
    const QString badPath = QDir::tempPath() + "/__nope_nested__/out.log";
    OutputForwarder f;
    QSignalSpy spy(&f, &OutputForwarder::error);
    f.setFile(badPath);
    f.setMode(OutputForwarder::Mode::File);
    QCOMPARE(spy.count(), 1);                          // 报错一次
    QCOMPARE(f.mode(), OutputForwarder::Mode::None);   // 回退 None
}

void TestOutputForwarder::setModeFileToNoneFlushes() {
    const QString path = QDir::tempPath() + "/kellect_flush.txt";
    QFile::remove(path);
    OutputForwarder f;
    f.setFile(path);
    f.setMode(OutputForwarder::Mode::File);
    f.writeLine("keep");
    f.setMode(OutputForwarder::Mode::None);   // 切换触发 close → flush
    QFile rf(path);
    QVERIFY(rf.open(QIODevice::ReadOnly | QIODevice::Text));
    QCOMPARE(QString::fromUtf8(rf.readAll()), QStringLiteral("keep\n"));
}

void TestOutputForwarder::socketModeForwardsLines() {
    QTcpServer server;
    QVERIFY(server.listen(QHostAddress::LocalHost, 0));   // 任意空闲端口
    const quint16 port = server.serverPort();

    OutputForwarder f;
    f.setSocket("127.0.0.1", port);
    f.setMode(OutputForwarder::Mode::Socket);

    QSignalSpy newConn(&server, &QTcpServer::newConnection);
    QVERIFY(newConn.wait(3000));               // 等 forwarder 连上
    QTcpSocket* client = server.nextPendingConnection();

    f.writeLine("hello");
    f.writeLine("world");

    // 两个 writeLine 可能分多个 readyRead 到达,循环读到完整 12 字节("hello\nworld\n")
    QByteArray got;
    QSignalSpy ready(client, &QIODevice::readyRead);
    while (got.size() < 12) {
        QVERIFY2(ready.wait(3000), "timeout waiting for forwarded bytes");
        got += client->readAll();
    }
    f.close();
    QCOMPARE(QString::fromUtf8(got), QStringLiteral("hello\nworld\n"));
}

QTEST_GUILESS_MAIN(TestOutputForwarder)
#include "tst_outputforwarder.moc"
