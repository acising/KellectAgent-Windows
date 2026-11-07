// src/process/OutputForwarder.h
// 把 stdout 收到的行按当前模式转发:None=不转发 / File=写文件 / Socket=QTcpSocket。
#pragma once
#include <QObject>
#include <QString>
#include <QTimer>

class QFile;
class QTcpSocket;   // Socket 模式的 sink(实现见 .cpp)

class OutputForwarder : public QObject {
    Q_OBJECT
public:
    enum class Mode { None, File, Socket };
    explicit OutputForwarder(QObject* parent = nullptr);
    ~OutputForwarder() override;

    void setFile(const QString& path);
    void setSocket(const QString& host, quint16 port);  // 存连接目标;连接在 setMode→openSocket 发起
    void setMode(Mode m);     // 切换前先 close 旧 sink;新 sink 立即尝试打开
    Mode mode() const { return mode_; }

    void writeLine(const QString& line);   // None=noop
    void close();                          // flush 文件 + 关 socket

signals:
    void error(const QString& msg);        // 文件打不开 / socket 连不上或断线
    void stateChanged(const QString& s);   // 给状态栏:连接中/已连/重连中/出错

private:
    void openFile();
    void openSocket();        // 创建 socket 并 connectToHost
    void scheduleReconnect(); // 断线后延迟重连(代计数防过期)
    Mode mode_ = Mode::None;
    QString filePath_, socketHost_;
    quint16 socketPort_ = 0;
    QFile* file_ = nullptr;
    QTimer flushTimer_;                     // 周期 flush 文件(P1:避免每行一次 syscall)
    QTcpSocket* sock_ = nullptr;            // Socket 模式连接对象
    bool reconnectScheduled_ = false;       // 是否已挂起重连(防重复 singleShot)
    quint64 reconnectGen_ = 0;              // 重连代:close()/重启使挂起的 singleShot 失效
};
