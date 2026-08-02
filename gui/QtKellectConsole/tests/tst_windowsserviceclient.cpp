// Tests for WindowsServiceClient's pure SCM-polling control flow (P4).
// - mapDwordState / pollStates are driven directly with scripted state
//   sequences (no real SCM, no admin). pause()'s no-abort timeout fallback
//   (Plan 1) is locked by pollStatesNoAbortTimesOutToLastState.
// - nonexistentServiceIsNotInstalled hits the real SCM query path for a
//   guaranteed-absent name (SC_MANAGER_CONNECT + SERVICE_QUERY_STATUS are
//   non-elevated), asserting the NotInstalled contract the GUI relies on.
#include <QtTest>
#include <deque>
#include <functional>

// windows.h after Qt headers (guarded) for the SERVICE_* DWORD constants.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "process/WindowsServiceClient.h"

class TestWindowsServiceClient : public QObject {
    Q_OBJECT
private slots:
    void mapDwordStateMapsAllStates();
    void pollStatesReachesTarget();
    void pollStatesAbortsOnAbortState();
    void pollStatesNoAbortTimesOutToLastState();
    void nonexistentServiceIsNotInstalled();
};

void TestWindowsServiceClient::mapDwordStateMapsAllStates() {
    using W = kellect::WindowsServiceClient;
    QCOMPARE(W::mapDwordState(SERVICE_STOPPED),          W::State::Stopped);
    QCOMPARE(W::mapDwordState(SERVICE_START_PENDING),    W::State::StartPending);
    QCOMPARE(W::mapDwordState(SERVICE_RUNNING),          W::State::Running);
    QCOMPARE(W::mapDwordState(SERVICE_PAUSE_PENDING),    W::State::PausePending);
    QCOMPARE(W::mapDwordState(SERVICE_PAUSED),           W::State::Paused);
    QCOMPARE(W::mapDwordState(SERVICE_CONTINUE_PENDING), W::State::ContinuePending);
    QCOMPARE(W::mapDwordState(SERVICE_STOP_PENDING),     W::State::StopPending);
    QCOMPARE(W::mapDwordState(999999u),                  W::State::Unknown);
}

void TestWindowsServiceClient::pollStatesReachesTarget() {
    using W = kellect::WindowsServiceClient;
    std::deque<DWORD> seq{SERVICE_START_PENDING, SERVICE_START_PENDING, SERVICE_RUNNING};
    const W::State s = W::pollStates(
        [&]() -> DWORD {
            const DWORD v = seq.front();
            if (seq.size() > 1) seq.pop_front();   // 末帧保留,耗尽后恒返回末值
            return v;
        },
        SERVICE_RUNNING, SERVICE_STOPPED, 1000, 0);
    QCOMPARE(s, W::State::Running);
}

void TestWindowsServiceClient::pollStatesAbortsOnAbortState() {
    using W = kellect::WindowsServiceClient;
    // start() 场景:target=Running、abort=Stopped;服务起不来→回落 Stopped。
    std::deque<DWORD> seq{SERVICE_START_PENDING, SERVICE_STOPPED};
    const W::State s = W::pollStates(
        [&]() -> DWORD {
            const DWORD v = seq.front();
            if (seq.size() > 1) seq.pop_front();
            return v;
        },
        SERVICE_RUNNING, SERVICE_STOPPED, 1000, 0);
    QCOMPARE(s, W::State::Stopped);
}

void TestWindowsServiceClient::pollStatesNoAbortTimesOutToLastState() {
    using W = kellect::WindowsServiceClient;
    // pause() 场景:target=Paused、abort=0(无 abort);服务拒绝暂停,恒 Running。
    // 超时应回退到真实态 Running(计划1 pause 的 no-abort 设计)。
    const W::State s = W::pollStates(
        []() -> DWORD { return SERVICE_RUNNING; },
        SERVICE_PAUSED, 0, 60, 0);
    QCOMPARE(s, W::State::Running);
}

void TestWindowsServiceClient::nonexistentServiceIsNotInstalled() {
    using namespace kellect;
    WindowsServiceClient c(QStringLiteral("Kellect_test_nonexistent_xyz"));
    QCOMPARE(c.state(), WindowsServiceClient::State::NotInstalled);
    QVERIFY(!c.isInstalled());
}

QTEST_GUILESS_MAIN(TestWindowsServiceClient)
#include "tst_windowsserviceclient.moc"
