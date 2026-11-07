// src/process/KellectProcessService.h
#pragma once
#include <QObject>
#include <QProcess>
#include <QStringList>
#include "ProcessState.h"
#include "../domain/Utf8Accumulator.h"

class KellectProcessService : public QObject {
    Q_OBJECT
public:
    explicit KellectProcessService(QObject* parent = nullptr);
    ProcessState state() const { return state_; }
public slots:
    void start(const QString& exe, const QStringList& args);
    void stop();
signals:
    void stateChanged(ProcessState s);
    void outputLine(const QString& line);
    void startFailed(const QString& reason);
private:
    void setState(ProcessState s);
    void onStdout();
    void pumpLines();

    QProcess proc_;
    Utf8Accumulator acc_;
    ProcessState state_ = ProcessState::Idle;
};
