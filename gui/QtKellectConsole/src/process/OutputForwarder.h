// src/process/OutputForwarder.h
// 把 stdout 收到的行按当前模式转发:None=不转发 / File=写文件 / Socket=QTcpSocket。
// Kafka 模式不经 forwarder(由 MainWindow::onStart 的 -k 参数让 kellect 直传),forwarder 保持 None。
#pragma once
#include <QObject>
#include <QString>

class QFile;
class QTcpSocket;   // Socket 模式用(Task 3)

class OutputForwarder : public QObject {
    Q_OBJECT
public:
    enum class Mode { None, File, Socket };
    explicit OutputForwarder(QObject* parent = nullptr);
    ~OutputForwarder() override;

    void setFile(const QString& path);
    void setSocket(const QString& host, quint16 port);  // Task 3 用,本任务只存值
    void setMode(Mode m);     // 切换前先 close 旧 sink;新 sink 立即尝试打开
    Mode mode() const { return mode_; }

    void writeLine(const QString& line);   // None=noop
    void close();                          // flush 文件 + 关 socket

signals:
    void error(const QString& msg);        // 文件打不开 / socket 连不上或断线
    void stateChanged(const QString& s);   // 给状态栏:连接中/已连/重连中/出错

private:
    void openFile();
    void openSocket();        // Task 3 实现
    void scheduleReconnect(); // Task 3 实现
    Mode mode_ = Mode::None;
    QString filePath_, socketHost_;
    quint16 socketPort_ = 0;
    QFile* file_ = nullptr;
    QTcpSocket* sock_ = nullptr;            // Task 3 用
    bool reconnectScheduled_ = false;       // Task 3 用
    quint64 reconnectGen_ = 0;              // 重连代:close()/重启使挂起的 singleShot 失效
};
