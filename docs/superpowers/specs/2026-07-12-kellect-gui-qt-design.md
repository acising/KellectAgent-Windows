# kellect GUI 轻量控制台 — Qt 重写设计

- 日期:2026-07-12
- 状态:已批准(待实现计划)
- 分支:feature/kellect-gui-console(Qt 重写;实现期或新开分支)
- 关联记忆:`kellect-gui-qt-rewrite`(本次决策)、`kellect-gui-wpf-console`(原 WPF 实现,需求/spec 参考,已被取代)、`kellect-gui-packaging-options`
- 取代:`2026-07-10-kellect-gui-console-design.md`(WPF 版,降为参考,保留于 git 历史)

---

## 1. 背景与目标

kellect README L62 明确支持 **Win7**(客户端)/ Server2008+(服务端)及以上。原 WPF + .NET 8 GUI 在功能 MVP 上已实现(20/20 测试绿,见 `kellect-gui-wpf-console`),但 **.NET 8 最低要求 Win10 1607,无法满足 Win7 硬需求**;WPF-UI 也不支持 .NET Framework 4.8(Win7 上 .NET 的唯一选项)。权衡三条路(① net8 美化 / ② Framework 4.8 迁移 / ③ Qt 重写)后选 ③——唯一能同时满足「Win7 SP1 / 10 / 11 全覆盖 + 单 exe + 零运行时依赖」的方案。

**重写目标**:把 WPF MVP 全部功能 + 此前规划的美化,在 Qt 重做:

- 进程生命周期管理(启停 `kellect.exe`)
- stdout 实时解码 + UTF-8 容错(替换 U+FFFD + 计数)
- 8 个事件 flag 选择 + 预设
- 设置持久化(JSON)
- 日志虚拟化 + 饱和裁剪(50000 行上限)
- 美化:分组工具栏、时间戳/正文分层、事件类型着色、标记行、解码异常标红
- DPI 稳健(Win7/10/11 显示比例正常,不出现显示不全/错位)

**硬约束**(用户,贯穿全文):

- **不改 C++ 采集器**(kellect 源码零改动,复用现有 `kellect.exe` + `config/`)
- **绝不 push**(仅本地 commit)
- **简洁,不引入过多依赖**(Qt Widgets 静态,只链 Widgets 模块)
- **兼容性强**(Win7/10/11 显示比例正常,无显示不全/错位)

---

## 2. 核心决策

| 决策点 | 选择 | 理由 |
|---|---|---|
| GUI 框架 | **Qt 5.15 LTS · Qt Widgets**(C++) | Qt 6.5+ 弃 Win7 → 锁 5.15(末代支持 Win7 的 LTS);Widgets 非 QML(体积小、Win7 稳、契合文本日志控制台) |
| 编译器 | **MSVC `/MT` 静态 CRT** | 与 kellect MSVC 工具链一致;静态 CRT → 不依赖 VC++ redist(Win7 不预装)→ 真·零依赖。备选 MinGW 更易零依赖但与 kellect 不一致,故不用 |
| 打包 | **静态单 exe**(~15–25MB) | Qt + CRT + 插件全静态链入;windeployqt 基本空操作 |
| 许可 | **GPL v3**(跟随 kellect) | kellect GPL v3 + Qt LGPL v3 静态链接兼容(GUI 全开源即合规,LGPL 路径①) |
| 控制方式 | **进程分离**(QProcess + stdout `-c`) | 沿用 WPF 架构;零改 C++;GUI 崩溃不影响采集 |
| 提权 | **manifest `requireAdministrator`** | 跨完整性级别无法重定向 stdout → GUI 须自管理员运行,kellect 继承 |
| 工程 | **`gui/QtKellectConsole/`**(取代 `gui/KellectConsole/`) | 全新 Qt 工程;WPF 工程降为参考(保留于 git 历史)。产物 exe 名仍为 `KellectConsole.exe`,保持用户认知一致 |
| Qt 安装位置 | **`D:\Code\Qt\5.15.2-static`**(自编静态) | 本机统一置于 `D:\Code`;CMake `CMAKE_PREFIX_PATH` 指此 |

---

## 3. 架构

进程分离(同 WPF)。GUI 作为父进程,以 `QProcess` 拉起 `kellect.exe -e 0x{flags:X2} -c`,重定向 stdout 实时显示。

```
┌──────────────────────────────────┐      QProcess::start (redirect stdout)
│  KellectConsole (Qt Widgets GUI) │ ──────────────────────────────────────┐
│  管理员 (requireAdministrator)    │                                      │
│                                  │      stdout (匿名管道, UTF-8 主导)     ▼
│  KellectProcessService (QObject) │      ┌───────────────────────────────┐
│   ├─ start(flags)                │      │  kellect.exe (-e 0x?? -c)     │
│   ├─ stop() (kill + waitForFinished) │   │  ETW kernel session (子线程)  │
│   └─ readyReadStandardOutput     │      └───────────────────────────────┘
│      → Utf8Accumulator → 行      │
│  LogModel : QAbstractListModel   │
│  QListView + LogDelegate         │
└──────────────────────────────────┘
```

**不改 kellect 源码**。GUI 退出时主动 `stop()` 回收子进程。

### 模块映射 C# → C++/Qt

| WPF(C#) | Qt(C++) | 说明 |
|---|---|---|
| `Models/LogEntry.cs` | `LogEntry`(struct) | 时间戳 + 文本 + 解码异常标记 |
| `FlagSelection` | `Flags`(quint8) | 8 bit 合成/解析 |
| `Preset` | `Preset` | 预设组合 |
| `Services/SettingsStore.cs` | `SettingsStore` | JSON round-trip(QJsonDocument) |
| `Services/KellectProcessService.cs` | `KellectProcessService`(QObject) | QProcess 封装 |
| UTF8Encoding + DecoderReplacementFallback | **`Utf8Accumulator`**(自写) | 见 §4 |
| `ObservableRangeCollection<LogEntry>` | `LogModel : QAbstractListModel` | `beginInsertRows`/`beginRemoveRows` |
| `ListBox`(虚拟化) | `QListView + LogDelegate` | 按需绘制,天然虚拟化 |
| `MainViewModel`(MVVM) | `MainWindow` 直接持 model + 信号槽 | Widgets 无 MVVM 强制,用信号槽 |
| DispatcherTimer 节流 | `QTimer` | 自动滚动节流 |

---

## 4. 数据流与 UTF-8 容错(Utf8Accumulator)

kellect 输出**批次节奏**(每攒 `outputThreshold`≈20 条 `cv.notify` + `output()` 一次,`std::cout` 全缓冲)与**编码缺陷**(`get_properties*.cpp` 的 `CP_ACP` bug,见 WPF spec §4.1–4.2)沿用 WPF 记录,不在 C++ 侧修改。

**Qt 没有现成的「带计数的 replacement fallback」**(`QTextDecoder` 会把无效字节替换为 U+FFFD 但不计数)→ **自写 `Utf8Accumulator` 类**:

1. 维护跨 `readyReadStandardOutput` 的**残余字节缓冲**(处理半截多字节序列,跨 read 边界)。
2. 按 UTF-8 前缀字节规则识别完整序列边界。
3. 无效字节 → 替换为 U+FFFD 并 `++errorCount`。
4. 按 `\n` 切出完整行交给 `LogModel`。
5. **BOM 防御**:跳过流首 `EF BB BF`;每行 `TrimStart`。

> 根治须改 kellect 源码(`get_properties*.cpp:55` 的 `CP_ACP`→`CP_UTF8`),违反「不改 C++」,列为后续。

---

## 5. UI 设计

### 5.1 布局(分组工具栏)
- 顶部:窗口控制(最小/最大/关),无边框或自定义标题栏。
- 工具栏分三组:
  - ① 事件 flag 复选(8 个,紧凑排布)
  - ② 预设下拉 + 启动/停止按钮
  - ③ 过滤输入框 + 自动滚动勾选 + 解码异常计数角标(`⚠ N`)
- 主体:`QListView`(日志)。
- 状态栏:进程状态 + `kellect.exe` 路径选择(浏览…)。
- QSS 深色主题。

### 5.2 日志视图:`QListView + QStyledItemDelegate`
- `LogModel : QAbstractListModel` 提供 `data(role)`,日志行数据。
- `LogDelegate::paint()` 手绘,**四项着色**:
  1. **时间戳/正文分层** —— 时间戳浅灰等宽、正文正常色,视觉分层。
  2. **事件类型着色** —— 解析 JSON `Event` 字段(如 `FileIOCreate`),按前缀映射到 flag 域 → 八类色板取色。**基于 kellect JSON 的精确分类**(非启发)。前缀映射示例:`Process*`→Process、`Thread*`→Thread、`Image*`→Image、`FileIO*`→File、`DiskIO*`→Disk、`Registry*`→Registry、`TcpIp*`→TcpIp;含 callstack 标记的行→CallStack。完整前缀→域表在实现期据 kellect 实际事件名定稿。
  3. **标记行着色** —— 用户双击行切换书签标记,标记行高亮底色。
  4. **解码异常标红** —— `errorCount > 0` 的行正文红。
- 无 `Event` 字段的行(批次分隔等)用默认色。

### 5.3 自动滚动节流
- `QTimer`(120ms / 单次 dirty 标记)滚动到底。**非修复崩溃**(`QListView` 天然按需绘制,无 WPF 那个 `ItemContainerGenerator` 计数跑偏问题),仅防高吞吐下每帧滚动拖卡。

### 5.4 DPI
- manifest `dpiAware=True/PM`(见 §6)。
- Qt 代码设 `Qt::AA_EnableHighDpiScaling` + `Qt::AA_UseHighDpiPixmaps`。

---

## 6. 构建与静态打包

### 6.1 自编静态 Qt 5.15(一次性,约 1–2h)
```
configure -static -opensource -confirm-license -platform win32-msvc ^
  -static-runtime -nomake examples -nomake tests ^
  -prefix D:\Code\Qt\5.15.2-static
nmake & nmake install
```
`-static-runtime` = Qt 本体用 `/MT`,与最终 exe 一致(单 exe 零依赖的根)。

### 6.2 CMake 工程
- `find_package(Qt5 COMPONENTS Widgets REQUIRED)` —— 只链 Widgets。
- `set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")` —— 强制 `/MT`(Release) / `/MTd`(Debug),与静态 Qt 一致。
- `CMAKE_PREFIX_PATH=D:\Code\Qt\5.15.2-static`。
- 由 `qt-cmake-project` skill 脚手架,按 5.15 适配(`Qt5::` 前缀)。

### 6.3 manifest(四项,嵌入 RT_MANIFEST 资源)

| 项 | 值 | 作用 |
|---|---|---|
| `requestedExecutionLevel` | `requireAdministrator` | 拉起 kellect 需提权 |
| `dpiAware` | `True/PM` | Win7/8.1 走系统级;`PM` 允许逐监视器 —— Win7/10/11 显示比例正常、不全/错位 |
| `supportedOS` GUID | Win7/8/8.1/10/11 | 防 Win11 把 exe 当旧程序塞兼容模式 |
| Common-Controls v6 | `Microsoft.Windows.Common-Controls` | 原生控件现代样式(Win7 上不像 9x) |

**单写 `dpiAware=True/PM`,不双写 `dpiAwareness`**:Qt 5.15 的 PerMonitorV2 支持本就不完整(V2 要 Qt 6),双写无收益反有边角风险;`True/PM` 已覆盖 Win7/8.1/10/11 全部逐监视器感知。若将来某台 Win11 高分屏标题栏模糊,再回填 `dpiAwareness=PerMonitor`(非 V2)兜底。

### 6.4 windeployqt(静态版基本空操作)
静态链接后 `platforms/qwindows` 等插件已入 exe,`windeployqt --no-translations` 兜底,产物仍是单 exe。

### 6.5 交付形态
```
KellectConsole-win-x64/
├─ KellectConsole.exe   ← Qt 静态,~15–25MB,零依赖
├─ kellect.exe          ← 复用现有,不改
└─ config/              ← 复用现有
```
后续美化完再决定裸 zip 还是安装包(见 `kellect-gui-packaging-options`;静态单 exe 已使该选择简化)。

---

## 7. 测试(QtTest)

移植 WPF 的 20 个纯逻辑测试 + 新增 delegate 着色:

- **Flags**(8 bit 合成/解析/位互斥)
- **Preset**(预设组合映射)
- **SettingsStore**(JSON round-trip、缺省回退)
- **Utf8Accumulator**(跨块多字节序列、无效字节→U+FFFD+计数、BOM 跳过)
- **ProcessService 状态机**(Idle→Starting→Running→Idle,失败回退;用 `QSignalSpy` 验状态信号)
- **日志裁剪**(>50000 → `removeFirst(5000)`,model 正确通知)
- **新增:delegate 颜色映射** —— 喂带 `Event` 字段的 JSON,验证返回正确颜色角色(纯逻辑,不渲染)
- **e2e**(手测):管理员启动 → 勾选 → 启动 → 看日志流 → 干净停止,子进程退出,状态正确

---

## 8. 错误处理(7 类)

1. **QProcess 启动失败**(路径错/权限不足)→ `errorOccurred` → 状态回 Idle + UI 状态栏报错(不闪退)。
2. **启动超时** → `waitForStarted(5000)` 超时判失败,走分支 1。
3. **进程意外退出**(`QProcess::CrashExit`)→ 通知用户,转 Idle。
4. **UTF-8 解码异常** → `Utf8Accumulator` 容错(§4)。
5. **进程树回收** → `closeEvent` 调 `stop()`;`QProcess::kill` = `TerminateProcess`(只杀直接进程)。kellect 本体据 README 为单进程采集器(Socket/Kafka 是输出通道而非子进程),预计无需 Job Object;实现期读 kellect 源码核实有无 `CreateProcess` 调用,有则补 Job Object。
6. **日志饱和** → `removeFirst(5000)`(§5.2)。
7. **全局异常捕获**(C++ 无 .NET 式全局异常,三层兜底,均写 exe 同目录 `crash.log`,尽量保活):
   - `qInstallMessageHandler` 捕获 Qt `qFatal`/`qCritical`
   - `std::set_terminate` 捕获未处理 C++ 异常
   - SEH `__try/__except` 捕获访问违规等结构性崩溃

   对应 WPF 的 `Dispatcher.UnhandledException` + `AppDomain.UnhandledException` + `TaskScheduler.UnobservedTaskException` 三层。

---

## 9. 分阶段实现

- **阶段 ① Qt MVP** —— 对齐 WPF 功能基线(进程生命周期 + 解码 + flags + 预设 + 设置 + 虚拟化 + 裁剪 + 错误兜底),深色主题可用,静态打包跑通。目标:Win7/10/11 单 exe 可用。
- **阶段 ② 美化** —— 分组工具栏精修 + 事件类型着色 + 标记行 + 时间戳分层 + 最终打包形态选择。

---

## 10. 许可与约束

- **GPL v3**(跟随 kellect),Qt LGPL v3 静态链接兼容。
- **不改 C++ 采集器**(kellect 源码零改动)。
- **绝不 push**(本地 commit ok)。
- 取代 `gui/KellectConsole/`(WPF,保留于 git 历史作参考)。
