// src/process/OutputForwarder.cpp
#include "OutputForwarder.h"
#include <QFile>
#include <QTcpSocket>
#include <QAbstractSocket>
#include <QTimer>

OutputForwarder::OutputForwarder(QObject* parent) : QObject(parent) {}
OutputForwarder::~OutputForwarder() { close(); }

void OutputForwarder::setFile(const QString& path)   { filePath_ = path; }
void OutputForwarder::setSocket(const QString& host, quint16 port) {
    socketHost_ = host; socketPort_ = port;   // Task 3 才真正用
}

void OutputForwarder::setMode(Mode m) {
    close();   // 先关旧 sink(flush 已写)
    mode_ = m;
    if (mode_ == Mode::File)         openFile();
    else if (mode_ == Mode::Socket)  openSocket();   // Task 3
}

void OutputForwarder::openFile() {
    file_ = new QFile(filePath_, this);
    if (!file_->open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        emit error(tr("无法写文件:%1").arg(filePath_));
        delete file_; file_ = nullptr;
        mode_ = Mode::None;        // 回退,不阻断运行
        return;
    }
    emit stateChanged(tr("文件:%1").arg(filePath_));
}

void OutputForwarder::openSocket() {
    if (!sock_) {
        sock_ = new QTcpSocket(this);
        connect(sock_, &QTcpSocket::disconnected, this, &OutputForwarder::scheduleReconnect);
        connect(sock_,
                QOverload<QAbstractSocket::SocketError>::of(&QAbstractSocket::error),
                this, [this](QAbstractSocket::SocketError){
            if (mode_ == Mode::Socket)
                emit error(tr("socket 连接失败:%1:%2").arg(socketHost_).arg(socketPort_));
        });
    }
    sock_->connectToHost(socketHost_, socketPort_);
    emit stateChanged(tr("连接中 %1:%2").arg(socketHost_).arg(socketPort_));
    // 连接建立前 writeLine 入队的数据由 Qt 内部缓冲,连上后发出
}

void OutputForwarder::scheduleReconnect() {
    if (mode_ != Mode::Socket || reconnectScheduled_) return;
    reconnectScheduled_ = true;
    const quint64 gen = ++reconnectGen_;        // 本轮重连的代
    emit stateChanged(tr("重连中 %1:%2").arg(socketHost_).arg(socketPort_));
    QTimer::singleShot(2000, this, [this, gen]{
        reconnectScheduled_ = false;
        if (gen != reconnectGen_) return;       // close()/重启已使本定时器过期
        if (mode_ == Mode::Socket && sock_) { sock_->abort(); openSocket(); }
    });
}

void OutputForwarder::writeLine(const QString& line) {
    const QByteArray bytes = (line + '\n').toUtf8();
    if (mode_ == Mode::File && file_) {
        file_->write(bytes);
        file_->flush();
    } else if (mode_ == Mode::Socket && sock_) {
        sock_->write(bytes);
    }
}

void OutputForwarder::close() {
    if (file_) { file_->flush(); file_->close(); delete file_; file_ = nullptr; }
    if (sock_) { sock_->abort(); delete sock_; sock_ = nullptr; }
    reconnectScheduled_ = false;
    ++reconnectGen_;   // 使任何挂起的 singleShot 失效
}
