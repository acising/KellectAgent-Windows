// src/process/KellectProcessService.cpp
#include "KellectProcessService.h"

KellectProcessService::KellectProcessService(QObject* parent) : QObject(parent) {
    proc_.setProcessChannelMode(QProcess::MergedChannels);
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
    prevErrors_ = 0;
    proc_.start(exe, args);
    if (proc_.waitForStarted(5000)) {
        setState(ProcessState::Running);
    } else {
        emit startFailed(proc_.errorString());
        setState(ProcessState::Idle);
    }
}

void KellectProcessService::stop() {
    if (state_ == ProcessState::Idle) return;
    proc_.kill();
    proc_.waitForFinished(3000);
    setState(ProcessState::Idle);
}

void KellectProcessService::onStdout() {
    acc_.feed(proc_.readAllStandardOutput());
    pumpLines();
}

void KellectProcessService::pumpLines() {
    QString line;
    while (acc_.takeLine(line)) {
        const int after = acc_.errorCount();
        const int delta = after - prevErrors_;
        prevErrors_ = after;
        emit outputLine(line, delta);
        if (delta > 0) emit decodeErrorCountChanged(after);
    }
}
