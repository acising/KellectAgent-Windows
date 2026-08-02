// src/process/OutputForwarder.cpp
#include "OutputForwarder.h"
#include <QFile>
#include <QTcpSocket>
#include <QAbstractSocket>
#include <QTimer>

namespace {
// 文件输出周期 flush 间隔(P1):避免每行一次 flush syscall(ETW 高频时瓶颈)。
// 数据丢失风险上限 ≈ 此间隔;close()/模式切换/析构均会立即 flush。
constexpr int kFlushIntervalMs = 200;
} // namespace

OutputForwarder::OutputForwarder(QObject* parent) : QObject(parent) {
    connect(&flushTimer_, &QTimer::timeout, this, [this] {
        if (file_) file_->flush();   // 周期 flush;close() 已停定时器时不再触发
    });
}
OutputForwarder::~OutputForwarder() { close(); }

void OutputForwarder::setFile(const QString& path)   { filePath_ = path; }
void OutputForwarder::setSocket(const QString& host, quint16 port) {
    socketHost_ = host; socketPort_ = port;   // 存目标;openSocket 时用
}

void OutputForwarder::setMode(Mode m) {
    close();   // 先关旧 sink(flush 已写)
    mode_ = m;
    if (mode_ == Mode::File)         openFile();
    else if (mode_ == Mode::Socket)  openSocket();
}

void OutputForwarder::openFile() {
    file_ = new QFile(filePath_, this);
    if (!file_->open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        emit error(tr("无法写文件:%1").arg(filePath_));
        delete file_; file_ = nullptr;
        mode_ = Mode::None;        // 回退,不阻断运行
        return;
    }
    flushTimer_.start(kFlushIntervalMs);   // 周期 flush 开启;close() 停
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
        file_->write(bytes);   // flush 交由周期定时器(P1),避免每行一次 syscall
    } else if (mode_ == Mode::Socket && sock_) {
        sock_->write(bytes);
    }
}

void OutputForwarder::close() {
    flushTimer_.stop();   // 先停周期 flush
    if (file_) { file_->flush(); file_->close(); delete file_; file_ = nullptr; }
    if (sock_) { sock_->abort(); delete sock_; sock_ = nullptr; }
    reconnectScheduled_ = false;
    ++reconnectGen_;   // 使任何挂起的 singleShot 失效
}
