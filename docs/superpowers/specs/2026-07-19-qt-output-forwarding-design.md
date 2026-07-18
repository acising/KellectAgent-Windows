# KellectConsole(Qt GUI)输出转发设计

- 日期:2026-07-19
- 状态:已批准(待实现计划)
- 分支:feature/kellect-gui-console
- 关联:父设计 [`2026-07-12-kellect-gui-qt-design.md`](./2026-07-12-kellect-gui-qt-design.md)、实现 plan [`docs/superpowers/plans/2026-07-12-kellect-gui-qt.md`](../plans/2026-07-12-kellect-gui-qt.md)、记忆 `kellect-gui-qt-rewrite`
- 作用范围:GUI **功能补齐**的输出目标部分。视觉美化(父 spec §9 阶段②:主题精修/斑马纹/无边框标题栏等)**不在本 spec 范围**,功能全部完成后再做。

---

## 1. 背景与目标

kellect 采集器(`source/initialization/initializer.cpp`,`showCommandList()` L535 / 解析器 L627)支持四种输出:`-c`(控制台)、`-f`(文件)、`-s`(socket)、`-k`(Kafka),四者**互斥**(`outputInited` 守卫)。

KellectConsole GUI 现状:`Flags.h:36` `buildKellectArgs(quint8 mask)` 硬编码返回 `{"-e", "0xXX", "-c"}` —— 只用到控制台一种,其余三种 CLI 能力 GUI 未暴露。

**用户要求**:

- GUI 补齐输出目标能力,功能优先(视觉美化推迟)。
- Windows GUI 定位是**可视化软件**:kellect 负责采集,GUI 负责看日志 + 配置输出。
- 输出归三类 + Kafka:控制台、文件、socket 三类由 GUI 配置;Kafka 因 Windows kellect 已自带(`source/dlls/` 的 librdkafka 等),也纳入 GUI 设置。
- 重活/边角能力靠直接跑 bin,GUI 不背。

**硬约束**(沿用父 spec §1/§10,本 spec 不放宽):

- **不改 C++ 采集器**(kellect 源码零改动)
- **绝不 push**(仅本地 commit)
- **简洁,不引入过多依赖**(Qt Widgets 静态,只链 Widgets 模块)
- **兼容性强**(Win7 SP1 / 10 / 11)

**目标**:GUI 设置可选四种输出;**文件/socket** 由 GUI 在 stdout 上 tee(显示永远在线),**Kafka** 由 kellect 直传(GUI 显示关闭)。

---

## 2. 核心决策

关键判断:**tee 还是直传,取决于"在 GUI 内转发该输出"的依赖成本**。

| 输出 | 在 GUI 内 tee 的成本 | 决策 | 显示 |
|---|---|---|---|
| 控制台 | 无(GUI 本就读 stdout) | 显示即可,不转发 | ✅ 在线 |
| 文件 | 零(`QFile` 在 Qt 里) | **GUI tee** | ✅ 在线 |
| Socket | 零(`QTcpSocket` 在 Qt 里) | **GUI tee** | ✅ 在线 |
| Kafka | **重**(要往静态 exe 链 librdkafka 一套,违背"最小依赖/单 exe"硬约束) | **kellect 直传 `-k`** | ❌ 关 |

**为何 Kafka 特殊**:GUI 内嵌 Kafka producer 会直接违反父 spec 硬约束「只链 Widgets 模块、静态单 exe ~15–25MB」。而 kellect 已自带 Kafka(librdkafka.dll 等随 `source/dlls/` 发行),通过 `-k ip:port/topic` 即可让 kellect 自己投递,GUI 零新依赖。

**为何 file/socket tee**:QFile/QTcpSocket 是 Qt 自带、零成本;且 GUI 的本职就是可视化,选了输出就变瞎与定位矛盾。tee 让显示始终在线。

**一致性表述**:不是"所有输出都 tee",而是"**tee 当它便宜(因为显示有价值)**"。Kafka tee 昂贵,故作为例外由 kellect 直传;GUI 仍承担配置职责(免得用户记 `-k` 参数),并在状态栏明确标注"直传、显示关"。

| 决策点 | 选择 | 理由 |
|---|---|---|
| 文件/socket | GUI tee(`-c` + GUI 转发) | 零依赖,显示在线 |
| Kafka | kellect 直传(`-k`) | 零新依赖,守硬约束;kafka 属重活,归"kellect 自带能力" |
| Kafka 模式显示 | 关(仅 kellect 启动横幅) | `-k` 下事件不经 stdout;横幅仍显示让用户知道 kellect 已起 |
| Socket 断线 | 自动重连(2s 退避) | 网络抖动常见,自动恢复优于手动 |
| 模式切换入口 | 设置对话框 | 工具栏保持简洁;状态栏常驻可见当前目标 |
| 转发行内容 | 解码后的原始 JSON 行 | 经 Utf8Accumulator 已 U+FFFD 修复;无效字节行的边角差异可接受 |
| `buildKellectArgs` | **不改** | 保留 `{-e,0xXX,-c}` 与现有 `tst_flags`;Kafka 的 `-k` 分支放 `MainWindow::onStart` |

---

## 3. 架构与数据流

kellect 侧不变(仍只读 stdout);转发/直传的差异全在 GUI 侧。

```
MainWindow::onStart(exePath, mask, outputCfg):
  ┌─ outputMode == Kafka ──────────────────────────────┐
  │  args = {"-e", hex(mask), "-k", broker+"/"+topic}   │
  │  forwarder.setMode(None)        // 不转发            │
  │  statusLabel ← "kafka …(直传,显示关)"               │
  └─────────────────────────────────────────────────────┘
  ┌─ 其他(Console/File/Socket)────────────────────────┐
  │  args = buildKellectArgs(mask) = {"-e",hex(mask),"-c"}│
  │  forwarder.setMode(File|Socket|None) + 配置          │
  │  statusLabel ← "控制台 / 文件 … / socket …"           │
  └─────────────────────────────────────────────────────┘
  proc_.start(exePath, args)

KellectProcessService: stdout → Utf8Accumulator → emit outputLine(line, decodeErrors)
MainWindow::onOutputLine(line, decodeErrors):   // -k 模式下基本只到 kellect 启动横幅
  parseKellectLine → LogEntry → model_.append(e)   // 永远显示(横幅也显示)
  forwarder.writeLine(line)                         // None=noop;File/Socket=tee
```

> `-k` 模式下 kellect 仍把启动横幅(`main.cpp` 的 `std::cout << "request join…"` 等,发生在 session 配置之前)打到 stdout,故 GUI 会显示横幅随后无事件 —— 正好让用户确认 kellect 已起、事件正投往 Kafka。

---

## 4. 组件:OutputForwarder

**位置**:`src/process/OutputForwarder.{h,cpp}`(与 `KellectProcessService` 同列,均为运行期 I/O 组件;非 UI,可独立测试)。

**职责**:对 stdout 收到的行,按当前模式转发到文件或 socket;Console/Kafka 模式下不转发(Kafka 由 `onStart` 的 `-k` 参数处理,forwarder 保持 `None`)。

```cpp
// src/process/OutputForwarder.h
#pragma once
#include <QObject>
#include <QString>
class QFile;
class QTcpSocket;

class OutputForwarder : public QObject {
    Q_OBJECT
public:
    enum class Mode { None, File, Socket };   // Kafka 不经 forwarder
    explicit OutputForwarder(QObject* parent = nullptr);
    ~OutputForwarder();

    void setFile(const QString& path);
    void setSocket(const QString& host, quint16 port);
    void setMode(Mode m);       // 切换前先 close 旧 sink;新 sink 立即尝试打开
    Mode mode() const { return mode_; }

    void writeLine(const QString& line);   // None=noop
    void close();                          // flush 文件 + 关 socket

signals:
    void error(const QString& msg);        // 文件打不开 / socket 连不上或断线
    void stateChanged(const QString& s);   // 给状态栏:连接中/已连/重连中/出错

private:
    void openFile();
    void openSocket();
    void scheduleReconnect();
    Mode mode_ = Mode::None;
    QString filePath_, socketHost_;
    quint16 socketPort_ = 0;
    QFile* file_ = nullptr;
    QTcpSocket* sock_ = nullptr;
    bool reconnectScheduled_ = false;
};
```

**行为细则:**

- **File**:`WriteOnly | Append | Text`,写 `line + '\n'`;每 N 行或 `close()` 时 flush;打开失败 → `emit error`,回退 `None`。
- **Socket**:`QTcpSocket::connectToHost`;连前写入的行由 Qt 内部缓冲,连接建立后发(连不上则丢失,可接受);断线(`disconnected`)→ 2s 退避自动重连,`stateChanged` 标"重连中";最终连不上 → `emit error`,状态栏标红;重连成功恢复。
- **None**:writeLine 空操作。
- **`setMode`**:先 `close()` 旧 sink,再按新模式打开(切换不丢已写数据 —— 旧 sink close 前 flush)。

---

## 5. SettingsStore 扩展

`Settings` 结构新增输出配置;JSON round-trip;缺省回退 Console(`outputMode=0`)。

```cpp
struct Settings {
    QString kellectExePath;
    quint8 lastMask = 0;
    bool autoScroll = true;
    QString filterKeyword;
    // 新增(本 spec):
    int outputMode = 0;           // 0=Console, 1=File, 2=Socket, 3=Kafka
    QString outputFile;           // File 模式路径
    QString socketHost;           // Socket 模式 host
    quint16 socketPort = 0;       // Socket 模式 port
    QString kafkaBroker;          // Kafka 模式 "ip:port"
    QString kafkaTopic;           // Kafka 模式 topic(拼 -k 用 broker+"/"+topic)
};
```

JSON 键:`outputMode` / `outputFile` / `socketHost` / `socketPort` / `kafkaBroker` / `kafkaTopic`。读时缺字段按上述默认值回退(与现有 `lastMask`/`autoScroll` 一致)。

---

## 6. MainWindow 改动

**`onStart`**(替换现有 `proc_.start(exePath, buildKellectArgs(currentMask()))`):

```cpp
const quint8 mask = currentMask();
QStringList args;
if (outputMode_ == OutputMode::Kafka) {
    args = {"-e", kellect::maskToHex(mask), "-k",
            kafkaBroker_ + "/" + kafkaTopic_};
    forwarder_.setMode(OutputForwarder::Mode::None);
} else {
    args = kellect::buildKellectArgs(mask);   // {"-e", hex, "-c"}
    forwarder_.setFile(outputFile_);
    forwarder_.setSocket(socketHost_, socketPort_);
    forwarder_.setMode(outputMode_ == OutputMode::File   ? OutputForwarder::Mode::File   :
                       outputMode_ == OutputMode::Socket ? OutputForwarder::Mode::Socket :
                                                            OutputForwarder::Mode::None);
}
proc_.start(exePath, args);
updateOutputStatus();   // 状态栏
```

> `maskToHex` 已是 `Flags.h` 中 `namespace kellect` 的 inline 函数,`MainWindow.cpp:30` 现有 `using namespace kellect;` 已可见,直接复用,**无需改 `Flags.h`**。

**`onOutputLine`**:在现有 `model_.append(e)` 后追加 `forwarder_.writeLine(line);`(None 模式自动 noop,故无条件调用)。

**`onStop` / `closeEvent`**:追加 `forwarder_.close();`(flush + 关 socket)。

**`updateOutputStatus()`**:据 `outputMode_` 刷新状态栏文本(见 §7);订阅 `forwarder_::error`/`stateChanged` → socket/kafka 异常时标红。

---

## 7. UI

**设置对话框加"输出"分组**(在现有 kellect.exe 路径行下方):

- 4 个 radio:**控制台 / 文件 / Socket / Kafka**
- 条件字段(按选中 radio 显示/隐藏):
  - 文件 → 路径 `QLineEdit` + `浏览…`(`QFileDialog::getSaveFileName`)
  - Socket → host `QLineEdit` + port `QSpinBox`(0–65535)
  - Kafka → broker `QLineEdit`(placeholder `ip:port`)+ topic `QLineEdit`
- Kafka radio 下方注:`kellect 直传,本地显示关闭`
- OK 时写回 `Settings`,刷新状态栏

**状态栏常驻**(现有 `statusLabel_` 旁加 `outputLabel_`,或复用):

| 模式 | 文本 |
|---|---|
| Console | `输出: 控制台` |
| File | `输出: 文件 kellect.log` |
| Socket | `输出: socket 1.2.3.4:66` |
| Kafka | `输出: kafka 1.2.3.4:9092/topic(直传,显示关)` |

socket/kafka 出错时该段标红(接 `forwarder_::error`;Kafka 错误由 `KellectProcessService::startFailed`/`stateChanged` 体现,因 kellect 直连)。

工具栏**不动**(模式切换走设置对话框,避免条件控件挤占工具栏;状态栏常驻可见当前目标)。

---

## 8. 错误处理

| 场景 | 处理 |
|---|---|
| File 打不开(路径非法/无权限) | `forwarder_::error` → 状态栏报错,回退 `None`(只显示,不转发);不阻断运行 |
| Socket 连不上 | 状态栏标红"连接失败";2s 退避自动重连;期间行入 Qt 缓冲,连上后补发 |
| Socket 运行中断线 | `disconnected` → 标"重连中" → 自动重连;成功恢复 |
| Kafka(kellect `-k` 格式错/连不上 broker) | 由 kellect 自身处理;`KellectProcessService::startFailed`/意外退出 → 状态栏报错,转 Idle(GUI 不解析 kafka 协议) |
| `closeEvent` | `forwarder_.close()` 保证文件 flush、socket 关闭 |

---

## 9. 测试

**新增 `tests/tst_outputforwarder.cpp`(纯逻辑,`QTEST_GUILESS_MAIN`):**

- `None` 模式 `writeLine` 无副作用(不建文件、无连接)
- `File` 模式:`writeLine` 后文件含该行 + `\n`;多次写累积正确
- `File` 打开失败(非法路径):emit `error`,mode 回退 `None`
- `setMode(File→None)`:旧文件 flush 关闭,已写内容不丢
- `Socket` 模式:本地 `QTcpServer` 回环,`writeLine` 后 server 端收到行
- (可选/手测)Socket 断线自动重连

**扩 `tests/tst_settingsstore.cpp`:**

- 4 模式 + 各字段(outputFile/socketHost/socketPort/kafkaBroker/kafkaTopic)JSON round-trip
- 缺字段时默认值回退(`outputMode=0`、`socketPort=0`、空串)

**注册到 `tests/CMakeLists.txt`**:`tst_outputforwarder` 链 `Qt5::Network`(QTcpSocket/QTcpServer)+ `Qt5::Test`,源含 `OutputForwarder.cpp`。

> 现有 `tst_flags`(断言 `buildKellectArgs(0x1F)=={"-e","0x1F","-c"}`)**不破** —— `buildKellectArgs` 签名不变。

---

## 10. 约束与不改

- **不改** kellect 源码、`Flags.h::buildKellectArgs`(签名/行为)、现有"保存"按钮(导出已显示行,与 tee 独立,保留)、日志委托/着色(视觉阶段)。
- **绝不 push**(本地 commit)。
- **最小依赖**:本 spec 不新增第三方库。File/Socket 用 Qt 自带 `QFile`/`QTcpSocket`;只需 GUI 工程链 `Qt5::Network` 模块(Widgets 之外的第二个 Qt 模块,父 spec"只链 Widgets"在此**显式放宽一条**,因为 socket tee 必需且 Qt 自带、不增加外部依赖或体积)。
- **兼容性**:socket/file 转发为用户态 I/O,Win7/10/11 行为一致。
- **构建改动**:`CMakeLists.txt` 的 `find_package(Qt5 ...)` 增加 `Network` 组件,主 exe `target_link_libraries` 追加 `Qt5::Network`;`tests/CMakeLists.txt` 的 `tst_outputforwarder` 同链 `Qt5::Network`。

---

## 11. 后续(不在本 spec)

- 视觉美化(父 spec §9 阶段②):主题深化、日志区可读性、异常 badge、可选无边框标题栏 —— 功能(含本 spec)全部完成后再开新 spec。
- 打包/三平台验证:父 spec Task 12。
