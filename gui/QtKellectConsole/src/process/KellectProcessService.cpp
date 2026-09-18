// src/process/KellectProcessService.cpp
#include "KellectProcessService.h"
#include <windows.h>

KellectProcessService::KellectProcessService(QObject* parent) : QObject(parent) {
    proc_.setProcessChannelMode(QProcess::MergedChannels);
    // 独立进程组(组号=子进程 PID):stop() 才能把 CTRL_BREAK 精确发给这一组,
    // 而不是广播整个控制台——0 号广播会波及共享控制台的所有进程,包括刚
    // Attach 进去的 GUI 自己(吞信号处理器也挡不住,实测 Win10 仍闪退)。
    proc_.setCreateProcessArgumentsModifier(
        [](QProcess::CreateProcessArguments* args) {
            args->flags |= CREATE_NEW_PROCESS_GROUP;
        });
    connect(&proc_, &QProcess::readyReadStandardOutput, this, &KellectProcessService::onStdout);
    connect(&proc_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
            this, [this](int, QProcess::ExitStatus){ setState(ProcessState::Idle); });
    connect(&proc_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError){
        // 启动失败由 start() 的 waitForStarted 分支统一 emit startFailed,
        // 此处只处理运行中的意外错误,避免双发。
        if (state_ == ProcessState::Running) setState(ProcessState::Idle);
    });
}

void KellectProcessService::setState(ProcessState s) {
    if (state_ == s) return;
    state_ = s;
    emit stateChanged(s);
}

void KellectProcessService::start(const QString& exe, const QStringList& args) {
    if (state_ != ProcessState::Idle) return;
    setState(ProcessState::Starting);
    acc_ = Utf8Accumulator{};
    proc_.start(exe, args);
    if (proc_.waitForStarted(5000)) {
        setState(ProcessState::Running);
    } else {
        emit startFailed(proc_.errorString());
        setState(ProcessState::Idle);
    }
}

// 显式吞掉控制台事件(SetConsoleCtrlHandler(nullptr,TRUE) 屏蔽不了 CTRL_BREAK,
// 共享控制台发信号会把自己打死);TRUE=已处理,不再走默认终止。
namespace {
BOOL WINAPI swallowConsoleCtrl(DWORD) { return TRUE; }
}

void KellectProcessService::stop() {
    if (state_ == ProcessState::Idle) return;
    // 优雅优先:附加到子进程的隐藏控制台,把 CTRL_BREAK 只发给它的进程组
    // (构造时 CREATE_NEW_PROCESS_GROUP,组号=PID),kellect 的控制台处理器
    // 会先停掉 NT Kernel Logger 再自然退出——不留残留会话,下次启动无需 183
    // 抢回。GUI 不在该组,信号与它无关。仅当自身没有控制台时才附加:
    // 控制台宿主(终端里启动的 GUI/测试进程)退回 kill() 兜底,避免信号
    // 波及同控制台的无关进程(Shell、测试运行器)。
    const qint64 pid = proc_.processId();
    if (pid > 0 && GetConsoleWindow() == nullptr) {
        // 保险带:万一仍有信号波及(GUI 曾短暂 Attach 进子控制台),吞掉
        // 它,TRUE=已处理不走默认终止。只装一次、永不卸载——控制台事件分发
        // 是异步的,发送后立刻卸载会与分发线程竞争,处理器被提前移除时本
        // 进程直接终止。GUI 平时无控制台,常驻 handler 不拦截任何东西。
        static const bool swallowInstalled =
            SetConsoleCtrlHandler(swallowConsoleCtrl, TRUE) != FALSE;
        if (swallowInstalled && AttachConsole(static_cast<DWORD>(pid))) {
            GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, static_cast<DWORD>(pid));
            FreeConsole();
        }
    }
    if (proc_.state() != QProcess::NotRunning && !proc_.waitForFinished(3000)) {
        proc_.kill();    // 子进程不响应信号:硬杀兜底(残留会话由 183 抢回路径善后)
        proc_.waitForFinished(1000);
    }
    setState(ProcessState::Idle);
}

void KellectProcessService::onStdout() {
    acc_.feed(proc_.readAllStandardOutput());
    pumpLines();
}

void KellectProcessService::pumpLines() {
    QString line;
    while (acc_.takeLine(line)) {
        emit outputLine(line);
    }
}
