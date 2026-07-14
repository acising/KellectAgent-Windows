#include <QtTest>
#include <QSignalSpy>
#include "process/KellectProcessService.h"

Q_DECLARE_METATYPE(ProcessState);

class TestProc : public QObject { Q_OBJECT
private slots:
    void initTestCase();
    void startEmitsLineAndRunning();
    void nonexistentExeFails();
    void stopReturnsToIdle();
};

void TestProc::initTestCase() {
    qRegisterMetaType<ProcessState>("ProcessState");
}

void TestProc::startEmitsLineAndRunning() {
    KellectProcessService svc;
    QSignalSpy lineSpy(&svc, &KellectProcessService::outputLine);
    QSignalSpy stateSpy(&svc, &KellectProcessService::stateChanged);
    // cmd.exe /c echo hello —— 通用、Win7/10/11 自带
    svc.start("cmd.exe", {"/c", "echo", "hello"});
    QVERIFY(lineSpy.wait(5000));
    QVERIFY(!lineSpy.isEmpty());
    QCOMPARE(svc.state(), ProcessState::Running);
    svc.stop();
    QCOMPARE(svc.state(), ProcessState::Idle);
}
void TestProc::nonexistentExeFails() {
    KellectProcessService svc;
    QSignalSpy failSpy(&svc, &KellectProcessService::startFailed);
    svc.start("C:/nonexistent_xyz_exe.exe", {});
    // startFailed 在 start() 内 waitForStarted false 时同步 emit，
    // 可能早于 wait() 入口；count>0 即说明已同步入 spy，否则 wait 兜底。
    QVERIFY(failSpy.count() > 0 || failSpy.wait(5000));
    QCOMPARE(svc.state(), ProcessState::Idle);
}
void TestProc::stopReturnsToIdle() {
    KellectProcessService svc;
    // stateSpy 必须在 start() 之前建：Starting/Running 在 start() 内同步 emit。
    QSignalSpy stateSpy(&svc, &KellectProcessService::stateChanged);
    svc.start("cmd.exe", {"/c", "ping", "-n", "30", "127.0.0.1"}); // 长任务
    QVERIFY(stateSpy.count() > 0 || stateSpy.wait(3000)); // Running
    svc.stop();
    QCOMPARE(svc.state(), ProcessState::Idle);
}

QTEST_GUILESS_MAIN(TestProc)
#include "tst_processservice.moc"
