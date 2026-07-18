# KellectConsole 输出转发 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 给 KellectConsole GUI 补齐四种输出目标(控制台/文件/socket/kafka):file/socket 由 GUI 在 stdout 上 tee(显示在线),kafka 由 kellect `-k` 直传(GUI 显示关)。

**Architecture:** 新增 `OutputForwarder`(QObject)做 file/socket tee。`MainWindow::onStart` 按 outputMode 分支:Kafka → `{"-e",hex,"-k",broker/topic}` + forwarder 空闲;其余 → `buildKellectArgs(mask)`(`{"-e",hex,"-c"}`)+ forwarder 开(File/Socket/None)。`onOutputLine` 无条件 `model_.append` + `forwarder.writeLine`。`SettingsStore` 扩 6 字段。新增 `Qt5::Network`(socket tee 必需,Qt 自带)。

**Tech Stack:** Qt 5.15 LTS(Widgets + Network),MSVC `/MT` 静态,QtTest,CMake/Ninja。

**Spec:** `docs/superpowers/specs/2026-07-19-qt-output-forwarding-design.md`

## Global Constraints

(摘自 spec §10 + 父 spec §1/§10,每个任务的需求都隐含本节)

- **不改 C++ 采集器**(kellect 源码零改动;GUI 只读 stdout + 自己 tee)
- **绝不 push**(仅本地 commit)
- **最小依赖**:本特性放宽父 spec「只链 Widgets」一条 —— 允许 `Qt5::Network`(Qt 自带,无外部依赖、几乎不增体积),因 socket tee 必需。**不引入任何第三方库。**
- **兼容性**:Win7 SP1 / 10 / 11;socket/file 转发为用户态 I/O,三平台一致
- **编译器/Qt**:`/MT`(`MultiThreaded$<$<CONFIG:Debug>:Debug>`),静态 Qt 前缀 `D:/Code/Qt/5.15.2-static`
- **源码 UTF-8**:中文注释,CMake 已 `add_compile_options(/utf-8)`
- **构建命令**:`cmd //c scripts\build.bat test`(Ninja + vcvars 14.29 / SDK 19041;configure+build+ctest 全跑)

---

## File Structure

| 文件 | 动作 | 职责 |
|---|---|---|
| `src/process/OutputForwarder.h/.cpp` | Create | tee 转发器:None/File/Socket 三态,writeLine/close,error/stateChanged 信号 |
| `tests/tst_outputforwarder.cpp` | Create | OutputForwarder 纯逻辑测试(None/File/Socket) |
| `src/domain/SettingsStore.h/.cpp` | Modify | Settings 加 6 输出字段 + JSON round-trip |
| `tests/tst_settingsstore.cpp` | Modify | 新字段 round-trip + 默认值 |
| `CMakeLists.txt` | Modify | `find_package` 加 `Network`;SOURCES 加 `OutputForwarder.cpp`;主 exe 链 `Qt5::Network` |
| `tests/CMakeLists.txt` | Modify | 注册 `tst_outputforwarder`,链 `Qt5::Network` |
| `src/ui/MainWindow.h/.cpp` | Modify | outputMode 状态、onStart 分支、onOutputLine tee、onStop/closeEvent、设置对话框输出分组、状态栏 |
| `src/domain/Flags.h` | **不改** | `buildKellectArgs(mask)` 保持 `{"-e",hex,"-c"}`;MainWindow 直接用 `kellect::maskToHex(mask)` 拼 `-k` |

---

## Task 1: SettingsStore 扩展输出字段

**Files:**
- Modify: `src/domain/SettingsStore.h`(Settings 结构)
- Modify: `src/domain/SettingsStore.cpp`(load/save)
- Test: `tests/tst_settingsstore.cpp`

**Interfaces:**
- Produces: `SettingsStore::Settings` 新增 `outputMode(int)`/`outputFile(QString)`/`socketHost(QString)`/`socketPort(quint16)`/`kafkaBroker(QString)`/`kafkaTopic(QString)`;Task 4/5 的 MainWindow load/save 依赖这些字段名。

- [ ] **Step 1: 扩测试(先红)**

在 `tests/tst_settingsstore.cpp` 的 `roundTrip()` 里,`in.filterKeyword = "FileIO";` 之后追加:

```cpp
    in.outputMode  = 3;
    in.outputFile  = "C:/out.log";
    in.socketHost  = "127.0.0.1";
    in.socketPort  = 6500;
    in.kafkaBroker = "10.0.0.1:9092";
    in.kafkaTopic  = "kellect";
```

同函数末尾的 `QCOMPARE` 块之后追加:

```cpp
    QCOMPARE(out.outputMode, in.outputMode);
    QCOMPARE(out.outputFile, in.outputFile);
    QCOMPARE(out.socketHost, in.socketHost);
    QCOMPARE(out.socketPort, in.socketPort);
    QCOMPARE(out.kafkaBroker, in.kafkaBroker);
    QCOMPARE(out.kafkaTopic, in.kafkaTopic);
```

在 `missingFileReturnsDefaults()` 末尾追加:

```cpp
    QCOMPARE(d.outputMode, 0);
    QCOMPARE(d.socketPort, quint16(0));
    QVERIFY(d.outputFile.isEmpty());
```

- [ ] **Step 2: 构建,确认红(字段不存在,编译失败)**

Run: `cmd //c scripts\build.bat test`
Expected: FAIL —— `error C2039: "outputMode" 不是 "SettingsStore::Settings" 的成员`(字段还没加)。

- [ ] **Step 3: 加字段**

`src/domain/SettingsStore.h` 把 `Settings` 结构改成:

```cpp
    struct Settings {
        QString kellectExePath;
        quint8 lastMask = 0;
        bool autoScroll = true;
        QString filterKeyword;
        // 输出目标(本特性新增)
        int outputMode = 0;           // 0=Console, 1=File, 2=Socket, 3=Kafka
        QString outputFile;           // File 模式路径
        QString socketHost;           // Socket 模式 host
        quint16 socketPort = 0;       // Socket 模式 port
        QString kafkaBroker;          // Kafka 模式 "ip:port"
        QString kafkaTopic;           // Kafka 模式 topic(拼 -k 用 broker+"/"+topic)
    };
```

- [ ] **Step 4: load/save 加字段**

`src/domain/SettingsStore.cpp` 的 `load()` 里,`d.filterKeyword = ...;` 之后追加:

```cpp
    d.outputMode  = o.value("outputMode").toInt(0);
    d.outputFile  = o.value("outputFile").toString();
    d.socketHost  = o.value("socketHost").toString();
    d.socketPort  = static_cast<quint16>(o.value("socketPort").toInt(0));
    d.kafkaBroker = o.value("kafkaBroker").toString();
    d.kafkaTopic  = o.value("kafkaTopic").toString();
```

`save()` 里,`o["filterKeyword"] = s.filterKeyword;` 之后追加:

```cpp
    o["outputMode"]  = s.outputMode;
    o["outputFile"]  = s.outputFile;
    o["socketHost"]  = s.socketHost;
    o["socketPort"]  = s.socketPort;
    o["kafkaBroker"] = s.kafkaBroker;
    o["kafkaTopic"]  = s.kafkaTopic;
```

- [ ] **Step 5: 构建+测试,确认绿**

Run: `cmd //c scripts\build.bat test`
Expected: PASS —— `tst_settingsstore` 三个用例全过(含新字段 round-trip + 默认值)。

- [ ] **Step 6: Commit**

```bash
git add src/domain/SettingsStore.h src/domain/SettingsStore.cpp tests/tst_settingsstore.cpp
git commit -m "feat(qt-gui): settings — output target fields (console/file/socket/kafka)"
```

---

## Task 2: OutputForwarder — None + File

**Files:**
- Create: `src/process/OutputForwarder.h`
- Create: `src/process/OutputForwarder.cpp`
- Create: `tests/tst_outputforwarder.cpp`
- Modify: `CMakeLists.txt`(SOURCES 加 `OutputForwarder.cpp`)
- Modify: `tests/CMakeLists.txt`(注册 `tst_outputforwarder`)

**Interfaces:**
- Produces: `class OutputForwarder : public QObject`,`enum class Mode { None, File, Socket }`;`setFile(QString)`、`setSocket(host,port)`(Task 3 实现)、`setMode(Mode)`、`writeLine(QString)`、`close()`;信号 `error(QString)`、`stateChanged(QString)`。Task 4 的 MainWindow 依赖此接口。

> 本任务只实现 None + File(Socket 在 Task 3)。头里前向声明 `QTcpSocket`、声明 `sock_`/`openSocket()`/`scheduleReconnect()` 但 .cpp 暂不定义 —— 未被调用,链接器不报错;Task 3 补全。

- [ ] **Step 1: 写失败测试**

`tests/tst_outputforwarder.cpp`:

```cpp
#include <QtTest>
#include <QSignalSpy>
#include <QFile>
#include <QDir>
#include "process/OutputForwarder.h"

class TestOutputForwarder : public QObject { Q_OBJECT
private slots:
    void noneModeIsNoop();
    void fileModeWritesLines();
    void fileOpenFailEmitsErrorAndReverts();
    void setModeFileToNoneFlushes();
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

QTEST_GUILESS_MAIN(TestOutputForwarder)
#include "tst_outputforwarder.moc"
```

- [ ] **Step 2: 注册测试 + 把新源加入主 exe**

`tests/CMakeLists.txt` 末尾追加(Task 2 阶段只链 Qt5::Test —— File 用 QFile,无需 Network):

```cmake
add_executable(tst_outputforwarder tst_outputforwarder.cpp)
target_link_libraries(tst_outputforwarder PRIVATE Qt5::Test)
target_include_directories(tst_outputforwarder PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_sources(tst_outputforwarder PRIVATE ${CMAKE_SOURCE_DIR}/src/process/OutputForwarder.cpp)
add_test(NAME tst_outputforwarder COMMAND tst_outputforwarder)
```

`CMakeLists.txt` 的 `set(SOURCES ...)` 里,`src/process/KellectProcessService.cpp` 之后加一行:

```cmake
    src/process/OutputForwarder.cpp
```

- [ ] **Step 3: 构建,确认红(头不存在)**

Run: `cmd //c scripts\build.bat test`
Expected: FAIL —— `cannot open source file "process/OutputForwarder.h"`。

- [ ] **Step 4: 写 `OutputForwarder.h`**

```cpp
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
};
```

- [ ] **Step 5: 写 `OutputForwarder.cpp`(None + File)**

```cpp
// src/process/OutputForwarder.cpp
#include "OutputForwarder.h"
#include <QFile>

OutputForwarder::OutputForwarder(QObject* parent) : QObject(parent) {}
OutputForwarder::~OutputForwarder() { close(); }

void OutputForwarder::setFile(const QString& path)   { filePath_ = path; }
void OutputForwarder::setSocket(const QString& host, quint16 port) {
    socketHost_ = host; socketPort_ = port;   // Task 3 才真正用
}

void OutputForwarder::setMode(Mode m) {
    if (m == mode_) return;
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

void OutputForwarder::openSocket()    { /* Task 3 */ }
void OutputForwarder::scheduleReconnect() { /* Task 3 */ }

void OutputForwarder::writeLine(const QString& line) {
    if (mode_ == Mode::File && file_) {
        file_->write((line + '\n').toUtf8());
        file_->flush();
    }
    // Socket 分支 Task 3;None=noop
}

void OutputForwarder::close() {
    if (file_) { file_->flush(); file_->close(); delete file_; file_ = nullptr; }
    // socket Task 3
}
```

- [ ] **Step 6: 构建+测试,确认绿**

Run: `cmd //c scripts\build.bat test`
Expected: PASS —— `tst_outputforwarder` 4 用例全过;其余测试不回归。

- [ ] **Step 7: Commit**

```bash
git add src/process/OutputForwarder.h src/process/OutputForwarder.cpp tests/tst_outputforwarder.cpp CMakeLists.txt tests/CMakeLists.txt
git commit -m "feat(qt-gui): output forwarder — none/file tee modes"
```

---

## Task 3: OutputForwarder — Socket + CMake Qt5::Network

**Files:**
- Modify: `CMakeLists.txt`(`find_package` 加 `Network`,主 exe 链 `Qt5::Network`)
- Modify: `tests/CMakeLists.txt`(`tst_outputforwarder` 链 `Qt5::Network`)
- Modify: `src/process/OutputForwarder.cpp`(实现 openSocket/scheduleReconnect/writeLine socket 分支/close socket)
- Test: `tests/tst_outputforwarder.cpp`(加 socket 回环用例)

**Interfaces:**
- Consumes: Task 2 的 `OutputForwarder` 骨架 + `setSocket`/`sock_`/`openSocket`/`scheduleReconnect`。
- Produces: `Mode::Socket` 真正生效;`writeLine` 在 Socket 模式经 `QTcpSocket` 发出;断线自动重连。

- [ ] **Step 1: CMake 加 Network**

`CMakeLists.txt` 的 find_package 改为(加 `Network`):

```cmake
find_package(Qt5 COMPONENTS Widgets Network Test REQUIRED)
```

主 exe 的 `target_link_libraries` 追加 `Qt5::Network`:

```cmake
target_link_libraries(KellectConsole PRIVATE
    Qt5::Widgets
    Qt5::Network
    Qt5::QWindowsIntegrationPlugin  # 静态 Qt 必需:平台插件静态链入
)
```

`tests/CMakeLists.txt` 里 Task 2 加的 `tst_outputforwarder` 块,链接行改为(加 `Qt5::Network`):

```cmake
target_link_libraries(tst_outputforwarder PRIVATE Qt5::Test Qt5::Network)
```

- [ ] **Step 2: 加 socket 测试**

`tests/tst_outputforwarder.cpp` 顶部 includes 区追加:

```cpp
#include <QTcpServer>
#include <QHostAddress>
```

类里 `private slots:` 追加声明:

```cpp
    void socketModeForwardsLines();
```

文件末尾(`QTEST_GUILESS_MAIN` 之前)追加实现:

```cpp
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

    QSignalSpy ready(client, &QIODevice::readyRead);
    QVERIFY(ready.wait(3000));                 // 等数据到
    const QString got = QString::fromUtf8(client->readAll());
    f.close();
    QCOMPARE(got, QStringLiteral("hello\nworld\n"));
}
```

- [ ] **Step 3: 实现 socket 分支**

`src/process/OutputForwarder.cpp` 顶部 includes 区,`#include <QFile>` 之后追加:

```cpp
#include <QTcpSocket>
#include <QAbstractSocket>
#include <QTimer>
```

把 `openSocket()`、`scheduleReconnect()`、`writeLine()`、`close()` 四个函数体替换为:

```cpp
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
    emit stateChanged(tr("重连中 %1:%2").arg(socketHost_).arg(socketPort_));
    QTimer::singleShot(2000, this, [this]{
        reconnectScheduled_ = false;
        if (mode_ == Mode::Socket) { sock_->abort(); openSocket(); }
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
}
```

- [ ] **Step 4: 重新 configure(因 find_package 变了)+ 构建+测试**

Run: `cmd //c scripts\build.bat test`
Expected: PASS —— `tst_outputforwarder` 5 用例全过(含 socket 回环);其余不回归。
> `build.bat` 每次 reconfigure,`Qt5::Network` 会被检出。若报 `Could not find a package configuration file provided by "Qt5Network"`,核对静态 Qt 前缀 `D:/Code/Qt/5.15.2-static` 编译时含 Network 模块(默认 everywere 包含)。

- [ ] **Step 5: Commit**

```bash
git add CMakeLists.txt tests/CMakeLists.txt src/process/OutputForwarder.cpp tests/tst_outputforwarder.cpp
git commit -m "feat(qt-gui): output forwarder — socket tee mode + Qt5::Network"
```

---

## Task 4: MainWindow — 输出状态 + args 分支 + forwarder 接线

**Files:**
- Modify: `src/ui/MainWindow.h`
- Modify: `src/ui/MainWindow.cpp`

**Interfaces:**
- Consumes: Task 1 `Settings` 新字段、Task 2/3 `OutputForwarder`、`kellect::maskToHex`(已可见,见 `MainWindow.cpp:30` `using namespace kellect;`)。
- Produces: 端到端 —— 选 Kafka 时 kellect 收 `-k`、forwarder 空闲;选 File/Socket 时 kellect 收 `-c`、forwarder tee;`onOutputLine` 转发原始行。

> 无单元测试(沿用父 plan Task 10 MainWindow 先例:UI 接线靠构建+手测 e2e 验证)。逻辑风险已由 Task 1–3 的单测覆盖。

- [ ] **Step 1: `MainWindow.h` 加状态**

顶部 includes 区,`#include "../process/KellectProcessService.h"` 之后追加:

```cpp
#include "../process/OutputForwarder.h"
```

类里 `private:` 区(`KellectProcessService proc_;` 之后)追加成员:

```cpp
    enum class OutputMode { Console = 0, File = 1, Socket = 2, Kafka = 3 };
    OutputForwarder forwarder_;
    int outputMode_ = 0;
    QString outputFile_, socketHost_, kafkaBroker_, kafkaTopic_;
    quint16 socketPort_ = 0;
    QLabel* outputLabel_ = nullptr;
```

(文件末尾 forward 声明区已有 `class QLabel;`,无需再加。)

`private:` 函数区(`void updatePathLabel();` 旁)追加:

```cpp
    void updateOutputStatus();
```

- [ ] **Step 2: 构造函数加状态标签 + 接信号**

`MainWindow.cpp` 的构造函数里,状态区(`statusLay->addWidget(pathLabel_);` 之后,`root->addLayout(statusLay);` 之前)插入:

```cpp
    outputLabel_ = new QLabel;
    statusLay->addWidget(outputLabel_);
```

信号槽区(自动滚动节流 `connect(...)` 之前)追加:

```cpp
    // forwarder 状态/错误 → 状态栏
    connect(&forwarder_, &OutputForwarder::error, this, [this](const QString& m){
        outputLabel_->setStyleSheet("color:#E07070;");
        outputLabel_->setText(m);
    });
    connect(&forwarder_, &OutputForwarder::stateChanged, this, [this](const QString&){
        updateOutputStatus();   // 用规范文案刷新(覆盖"连接中/重连中"等瞬态)
    });
```

构造函数末尾(`loadSettings();` 之前)追加 `updateOutputStatus();`(此时 outputMode_ 等已是默认值,loadSettings 后再刷一次)。

- [ ] **Step 3: `onStart` 分支**

把现有 `onStart()` 整体替换为:

```cpp
void MainWindow::onStart() {
    if (kellectExePath_.trimmed().isEmpty()) {
        statusLabel_->setText(tr("请先在设置中选择 kellect.exe"));
        return;
    }
    const quint8 mask = currentMask();
    QStringList args;
    if (static_cast<OutputMode>(outputMode_) == OutputMode::Kafka) {
        if (kafkaBroker_.isEmpty() || kafkaTopic_.isEmpty()) {
            statusLabel_->setText(tr("请先在设置中填 Kafka broker/topic"));
            return;
        }
        args = QStringList{ "-e", maskToHex(mask),
                            "-k", kafkaBroker_ + "/" + kafkaTopic_ };
        forwarder_.setMode(OutputForwarder::Mode::None);   // kellect 直传,不 tee
    } else {
        args = buildKellectArgs(mask);                     // {"-e", hex, "-c"}
        forwarder_.setFile(outputFile_);
        forwarder_.setSocket(socketHost_, socketPort_);
        forwarder_.setMode(static_cast<OutputMode>(outputMode_) == OutputMode::File   ? OutputForwarder::Mode::File   :
                           static_cast<OutputMode>(outputMode_) == OutputMode::Socket ? OutputForwarder::Mode::Socket :
                                                                                       OutputForwarder::Mode::None);
    }
    proc_.start(kellectExePath_.trimmed(), args);
    updateOutputStatus();
}
```

- [ ] **Step 4: `onOutputLine` tee + `onStop`/`closeEvent` 关**

`onOutputLine()` 末尾(`logDirty_ = true;` 之后)追加:

```cpp
    forwarder_.writeLine(line);   // tee 原始行;None/Kafka 模式自动 noop
```

`onStop()` 替换为:

```cpp
void MainWindow::onStop() { proc_.stop(); forwarder_.close(); }
```

`closeEvent()` 在 `proc_.stop();` 之后、`saveSettings();` 之前插入:

```cpp
    forwarder_.close();
```

- [ ] **Step 5: load/save 新字段**

`loadSettings()` 里,`updatePathLabel();` 之前追加:

```cpp
    outputMode_  = s.outputMode;
    outputFile_  = s.outputFile;
    socketHost_  = s.socketHost;
    socketPort_  = s.socketPort;
    kafkaBroker_ = s.kafkaBroker;
    kafkaTopic_  = s.kafkaTopic;
    updateOutputStatus();
```

`saveSettings()` 里,`s.filterKeyword = filterEdit_->text();` 之后追加:

```cpp
    s.outputMode  = outputMode_;
    s.outputFile  = outputFile_;
    s.socketHost  = socketHost_;
    s.socketPort  = socketPort_;
    s.kafkaBroker = kafkaBroker_;
    s.kafkaTopic  = kafkaTopic_;
```

- [ ] **Step 6: `updateOutputStatus()` 实现**

`MainWindow.cpp` 末尾(`closeEvent` 之后)追加:

```cpp
void MainWindow::updateOutputStatus() {
    QString t;
    switch (static_cast<OutputMode>(outputMode_)) {
        case OutputMode::Console: t = tr("输出: 控制台"); break;
        case OutputMode::File:    t = tr("输出: 文件 %1").arg(QFileInfo(outputFile_).fileName()); break;
        case OutputMode::Socket:  t = tr("输出: socket %1:%2").arg(socketHost_).arg(socketPort_); break;
        case OutputMode::Kafka:   t = tr("输出: kafka %1/%2(直传,显示关)").arg(kafkaBroker_).arg(kafkaTopic_); break;
    }
    outputLabel_->setStyleSheet(QString());   // 清红
    outputLabel_->setText(t);
}
```

(`QFileInfo` 已在 `MainWindow.cpp` 顶部 include。)

- [ ] **Step 7: 构建,确认通过**

Run: `cmd //c scripts\build.bat test`
Expected: 主 exe 链接通过(`KellectConsole.exe` 产出);所有测试不回归。手测 e2e(管理员):选各模式启动/停止,看状态栏文案;File 模式跑完查日志文件有行;Socket 模式起本地 `nc -l -p 6666` 收到行;Kafka 模式状态栏显示"(直传,显示关)"且无 stdout 事件流(仅 kellect 横幅)。

- [ ] **Step 8: Commit**

```bash
git add src/ui/MainWindow.h src/ui/MainWindow.cpp
git commit -m "feat(qt-gui): wire output forwarding — kafka passthrough + file/socket tee"
```

---

## Task 5: 设置对话框 输出分组 + 状态栏接线

**Files:**
- Modify: `src/ui/MainWindow.cpp`(顶部 includes + `openSettingsDialog()`)

**Interfaces:**
- Consumes: Task 4 的 `outputMode_`/`outputFile_`/`socketHost_`/`socketPort_`/`kafkaBroker_`/`kafkaTopic_` + `OutputMode` enum + `updateOutputStatus()`。
- Produces: 设置对话框里的 4 radio + 条件字段;OK 后回写状态并刷新状态栏。

> 无单元测试(UI,沿用父 plan 先例,构建+手测验证)。

- [ ] **Step 1: 加 includes**

`MainWindow.cpp` 顶部 includes 区(`#include <QComboBox>` 附近)追加:

```cpp
#include <QRadioButton>
#include <QSpinBox>
```

- [ ] **Step 2: 重写 `openSettingsDialog()`**

把现有 `openSettingsDialog()` 整体替换为(在原 exe 路径行下方插入"输出"分组):

```cpp
void MainWindow::openSettingsDialog() {
    QDialog dlg(this);
    dlg.setWindowTitle(tr("设置"));
    auto* lay = new QVBoxLayout(&dlg);

    // —— kellect.exe 路径(原有)——
    auto* row = new QHBoxLayout;
    row->addWidget(new QLabel(tr("kellect.exe 路径:")));
    auto* pathEdit = new QLineEdit(kellectExePath_, &dlg);
    row->addWidget(pathEdit, 1);
    auto* browseBtn = new QPushButton(tr("浏览…"), &dlg);
    row->addWidget(browseBtn);
    lay->addLayout(row);

    // —— 输出分组(本特性)——
    auto* outBox = new QGroupBox(tr("输出"), &dlg);
    auto* outLay = new QVBoxLayout(outBox);

    auto* rConsole = new QRadioButton(tr("控制台"), outBox);
    auto* rFile    = new QRadioButton(tr("文件"), outBox);
    auto* rSocket  = new QRadioButton(tr("Socket"), outBox);
    auto* rKafka   = new QRadioButton(tr("Kafka(kellect 直传,本地显示关)"), outBox);
    rConsole->setChecked(static_cast<OutputMode>(outputMode_) == OutputMode::Console);
    rFile->setChecked   (static_cast<OutputMode>(outputMode_) == OutputMode::File);
    rSocket->setChecked (static_cast<OutputMode>(outputMode_) == OutputMode::Socket);
    rKafka->setChecked  (static_cast<OutputMode>(outputMode_) == OutputMode::Kafka);
    outLay->addWidget(rConsole);
    outLay->addWidget(rFile);
    outLay->addWidget(rSocket);
    outLay->addWidget(rKafka);

    // File 条件字段
    auto* fileRow = new QHBoxLayout;
    fileRow->addWidget(new QLabel(tr("路径:")));
    auto* fileEdit = new QLineEdit(outputFile_, outBox);
    fileEdit->setPlaceholderText(tr("C:\\out.log"));
    fileRow->addWidget(fileEdit, 1);
    auto* fileBrowse = new QPushButton(tr("浏览…"), outBox);
    fileRow->addWidget(fileBrowse);
    outLay->addLayout(fileRow);

    // Socket 条件字段
    auto* sockRow = new QHBoxLayout;
    sockRow->addWidget(new QLabel(tr("host:")));
    auto* hostEdit = new QLineEdit(socketHost_, outBox);
    hostEdit->setPlaceholderText(tr("192.168.1.2"));
    sockRow->addWidget(hostEdit);
    sockRow->addWidget(new QLabel(tr("port:")));
    auto* portSpin = new QSpinBox(outBox);
    portSpin->setRange(0, 65535);
    portSpin->setValue(socketPort_);
    sockRow->addWidget(portSpin);
    outLay->addLayout(sockRow);

    // Kafka 条件字段
    auto* kafkaRow = new QHBoxLayout;
    kafkaRow->addWidget(new QLabel(tr("broker:")));
    auto* brokerEdit = new QLineEdit(kafkaBroker_, outBox);
    brokerEdit->setPlaceholderText(tr("192.168.1.2:9092"));
    kafkaRow->addWidget(brokerEdit);
    kafkaRow->addWidget(new QLabel(tr("topic:")));
    auto* topicEdit = new QLineEdit(kafkaTopic_, outBox);
    topicEdit->setPlaceholderText(tr("kellect"));
    kafkaRow->addWidget(topicEdit);
    outLay->addLayout(kafkaRow);

    lay->addWidget(outBox);

    auto* btns = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    lay->addWidget(btns);

    // 浏览按钮
    connect(browseBtn, &QPushButton::clicked, this, [this, pathEdit]{
        const QString cur = pathEdit->text().isEmpty()
            ? QCoreApplication::applicationDirPath() : pathEdit->text();
        const auto path = QFileDialog::getOpenFileName(this, tr("选择 kellect.exe"), cur,
                                                       tr("可执行文件 (*.exe)"));
        if (!path.isEmpty()) pathEdit->setText(path);
    });
    connect(fileBrowse, &QPushButton::clicked, this, [this, fileEdit]{
        const QString cur = fileEdit->text().isEmpty()
            ? QCoreApplication::applicationDirPath() : fileEdit->text();
        const auto path = QFileDialog::getSaveFileName(this, tr("选择输出文件"), cur,
                                                       tr("日志文件 (*.log *.txt);;所有文件 (*.*)"));
        if (!path.isEmpty()) fileEdit->setText(path);
    });
    connect(btns, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(btns, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    if (dlg.exec() == QDialog::Accepted) {
        kellectExePath_ = pathEdit->text();
        if (rKafka->isChecked())        outputMode_ = static_cast<int>(OutputMode::Kafka);
        else if (rSocket->isChecked())  outputMode_ = static_cast<int>(OutputMode::Socket);
        else if (rFile->isChecked())    outputMode_ = static_cast<int>(OutputMode::File);
        else                            outputMode_ = static_cast<int>(OutputMode::Console);
        outputFile_  = fileEdit->text();
        socketHost_  = hostEdit->text();
        socketPort_  = static_cast<quint16>(portSpin->value());
        kafkaBroker_ = brokerEdit->text();
        kafkaTopic_  = topicEdit->text();
        updatePathLabel();
        updateOutputStatus();
    }
}
```

- [ ] **Step 3: 构建,确认通过**

Run: `cmd //c scripts\build.bat test`
Expected: 构建通过,所有测试不回归。手测:开设置 → 切 4 个 radio,条件字段显隐合理;改 File 路径/socket host:port/Kafka broker+topic → OK → 状态栏文案随之变 → 关窗重开,设置持久(走 Task 1 的 SettingsStore)。

- [ ] **Step 4: Commit**

```bash
git add src/ui/MainWindow.cpp
git commit -m "feat(qt-gui): settings dialog — output target group (4 modes)"
```

---

## 自审(对照 spec)

**1. Spec coverage:**
- §1 目标(四输出目标)→ Task 1–5 全覆盖 ✓
- §2 核心决策(tee vs 直传)→ Global Constraints + Task 4(Kafka 分支)+ Task 2/3(File/Socket tee)✓
- §3 数据流(onStart 分支 / onOutputLine tee)→ Task 4 Step 3/4 ✓
- §4 OutputForwarder(组件 + 行为细则)→ Task 2(None/File)+ Task 3(Socket/重连)✓
- §5 SettingsStore(6 字段 round-trip/缺省)→ Task 1 ✓
- §6 MainWindow(onStart/onOutputLine/onStop/closeEvent/maskToHex)→ Task 4 ✓
- §7 UI(设置对话框输出分组 + 状态栏)→ Task 5 ✓
- §8 错误处理(文件打不开回退 / socket 断线重连 / closeEvent flush)→ Task 2 Step 5(file 回退)+ Task 3 Step 3(重连)+ Task 4 Step 4(closeEvent)✓
- §9 测试(tst_outputforwarder + 扩 tst_settingsstore + tst_flags 不破)→ Task 1/2/3 ✓
- §10 约束(不改 kellect/Flags、最小依赖放宽 Network、CMake 改动)→ Global Constraints + Task 3 Step 1 + File Structure(Flags.h 不改)✓

**2. Placeholder scan:** 无 TBD/TODO。Task 2 的 `openSocket`/`scheduleReconnect`/socket 成员为"声明占位、Task 3 补全",已在任务正文显式标注(非未决项)。`build.bat` reconfigure 的 Network 检出有排错提示。

**3. Type consistency:**
- `OutputForwarder::Mode { None, File, Socket }` 跨 Task 2/3/4 一致 ✓
- `setFile/setSocket/setMode/writeLine/close` 签名跨任务一致 ✓
- `MainWindow::OutputMode { Console=0, File=1, Socket=2, Kafka=3 }` 与 `SettingsStore::Settings::outputMode` 的 0/1/2/3 数值一致(Task 4 `static_cast` 互转)✓
- `Settings` 新字段名(outputMode/outputFile/socketHost/socketPort/kafkaBroker/kafkaTopic)在 Task 1(定义)、Task 4(load/save)、Task 5(对话框回写)三处一致 ✓
- `maskToHex` 直接用(不改 Flags.h),与 `buildKellectArgs` 内部一致 ✓

无类型/命名漂移。

---

## Execution Handoff

Plan 完成并保存至 `docs/superpowers/plans/2026-07-19-qt-output-forwarding.md`。
