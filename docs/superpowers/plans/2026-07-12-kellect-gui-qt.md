# kellect GUI Qt 重写 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用 Qt 5.15 LTS Widgets 重写 kellect 的轻量控制台 GUI,Win7 SP1/10/11 单 exe 零依赖运行,取代 WPF 版 `gui/KellectConsole/`。

**Architecture:** 进程分离——Qt GUI 作父进程,以 `QProcess` 拉起 `kellect.exe -e 0x{flags:X2} -c`,经 stdout 重定向实时显示。domain 逻辑(flags/preset/settings/UTF-8 解码/进程状态机)纯 C++,UI 用 QListView + 自绘 delegate(时间戳分层 + 事件类型着色 + 书签 + 解码异常标红),静态编译单 exe。

**Tech Stack:** Qt 5.15 LTS(Widgets)· MSVC `/MT` 静态 CRT · CMake 3.16+ · QtTest · QSS 深色主题 · GPL v3。

## Global Constraints

(spec 项目级要求,逐字抄;每个任务的实现隐含遵守)

- **不改 C++ 采集器**:kellect 源码零改动,复用现有 `kellect.exe` + `config/`。
- **绝不 push**:仅本地 `git commit`,不 `git push`。
- **Qt 版本**:Qt 5.15 LTS(Qt 6.5+ 弃 Win7)。工程位置 `gui/QtKellectConsole/`。
- **编译器/CRT**:MSVC `/MT` 静态(`CMAKE_MSVC_RUNTIME_LIBRARY` = `MultiThreaded[Debug]`),与静态 Qt 一致。
- **Qt 路径**:`CMAKE_PREFIX_PATH=D:\Code\Qt\5.15.2-static`(自编静态)。
- **依赖**:只链 `Qt5::Widgets`(含 QtCore/QtGui);不引入 QML/Network/第三方库。
- **平台**:Win7 SP1 / Win10 / Win11 全覆盖,DPI 显示正常、无显示不全/错位。
- **产物名**:`KellectConsole.exe`(保持用户认知),工程目录 `gui/QtKellectConsole/`。
- **许可**:GPL v3(跟随 kellect),Qt LGPL v3 静态链接兼容。

## Prerequisites(一次性环境,非 TDD 任务)

实现前须先自编静态 Qt 5.15(约 1–2h,spec §6.1):

```
# 解压 qt-everywhere-src-5.15.2.zip 到 D:\Code\qt-src,然后:
configure -static -opensource -confirm-license -platform win32-msvc ^
  -static-runtime -nomake examples -nomake tests ^
  -prefix D:\Code\Qt\5.15.2-static
nmake & nmake install
```

需 VS 2019(含 MSVC 19.29 与 Win10 SDK)。验证:`D:\Code\Qt\5.15.2-static\bin\qmake.exe` 存在。

---

## File Structure

```
gui/QtKellectConsole/
├─ CMakeLists.txt                    顶层工程(Qt5 Widgets,/MT,manifest 资源,enable_testing)
├─ app.manifest                     四项:requireAdministrator / dpiAware=True/PM / supportedOS / Common-Controls v6
├─ app.rc                           嵌入 app.manifest 为 RT_MANIFEST + 版本信息
├─ resources/
│  └─ dark.qss                      深色主题样式表
├─ src/
│  ├─ main.cpp                      QApplication + HighDpi + CrashHandler + MainWindow
│  ├─ CrashHandler.h / .cpp         三层全局异常 → crash.log
│  ├─ domain/
│  │  ├─ Flags.h                    EventFlag enum + buildMask/maskToHex/buildKellectArgs(inline)
│  │  ├─ Preset.h / .cpp            Preset struct + defaultPresets()
│  │  ├─ LogEntry.h                 struct LogEntry
│  │  ├─ Utf8Accumulator.h / .cpp   UTF-8 状态机:feed/takeLine/errorCount
│  │  └─ SettingsStore.h / .cpp     JSON round-trip(QJsonDocument)
│  ├─ process/
│  │  ├─ ProcessState.h             enum class ProcessState
│  │  └─ KellectProcessService.h/.cpp  QProcess 封装 + Utf8Accumulator
│  └─ ui/
│     ├─ EventColor.h / .cpp        EventDomain + domainOfEvent/textColor/markBackground
│     ├─ LogModel.h / .cpp          QAbstractListModel + 50000 裁剪
│     ├─ LogDelegate.h / .cpp       QStyledItemDelegate paint(四项着色)
│     └─ MainWindow.h / .cpp        组装 UI + QTimer 节流 + closeEvent
└─ tests/
   ├─ CMakeLists.txt                各 QtTest 可执行 + CTest 注册
   ├─ tst_flags.cpp
   ├─ tst_preset.cpp
   ├─ tst_utf8accumulator.cpp
   ├─ tst_settingsstore.cpp
   ├─ tst_processservice.cpp        QSignalSpy + 真实 cmd.exe
   ├─ tst_logmodel.cpp
   └─ tst_eventcolor.cpp
```

---

### Task 1: 工程脚手架 + manifest + 空主窗口

**Files:**
- Create: `gui/QtKellectConsole/CMakeLists.txt`
- Create: `gui/QtKellectConsole/app.manifest`
- Create: `gui/QtKellectConsole/app.rc`
- Create: `gui/QtKellectConsole/src/main.cpp`
- Create: `gui/QtKellectConsole/src/ui/MainWindow.h`
- Create: `gui/QtKellectConsole/src/ui/MainWindow.cpp`
- Create: `gui/QtKellectConsole/.gitignore`(忽略 build/)

**Interfaces:**
- Produces: 可构建的 Qt Widgets 工程目标 `KellectConsole`;`MainWindow(QWidget*)` 构造(空窗口)。

- [ ] **Step 1: 写 `CMakeLists.txt`**

```cmake
cmake_minimum_required(VERSION 3.16)
project(KellectConsole LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORC ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 静态 Qt 前缀(自编产物)
set(CMAKE_PREFIX_PATH "D:/Code/Qt/5.15.2-static" CACHE PATH "Static Qt 5.15 prefix")

find_package(Qt5 COMPONENTS Widgets REQUIRED)

# 强制 /MT(Release)/ /MTd(Debug),与静态 Qt 的 -static-runtime 一致
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(SOURCES
    src/main.cpp
    src/ui/MainWindow.cpp
)
set(HEADERS
    src/ui/MainWindow.h
)

add_executable(KellectConsole WIN32
    ${SOURCES}
    ${HEADERS}
    app.rc
)
target_include_directories(KellectConsole PRIVATE src)
target_link_libraries(KellectConsole PRIVATE
    Qt5::Widgets
    Qt5::QWindowsIntegrationPlugin  # 静态 Qt 必需:平台插件静态链入
)
target_compile_definitions(KellectConsole PRIVATE UNICODE _UNICODE)
set_target_properties(KellectConsole PROPERTIES
    OUTPUT_NAME "KellectConsole"
)

enable_testing()
add_subdirectory(tests)
```

- [ ] **Step 2: 写 `app.manifest`(四项)**

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="KellectConsole" version="1.0.0.0"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">True/PM</dpiAware>
    </windowsSettings>
  </application>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <!-- Win7 --><supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
      <!-- Win8  --><supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
      <!-- Win8.1--><supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
      <!-- Win10/11 --><supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0" processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
</assembly>
```

- [ ] **Step 3: 写 `app.rc`(嵌入 manifest)**

```rc
1 24 "app.manifest"   // RT_MANIFEST 资源类型=24(避免依赖 windows.h 预处理)
VS_VERSION_INFO VERSIONINFO
 FILEVERSION 1,0,0,0
 PRODUCTVERSION 1,0,0,0
 FILEFLAGSMASK 0x3fL
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "ProductName", "KellectConsole"
      VALUE "FileVersion", "1.0.0.0"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
```

- [ ] **Step 4: 写 `MainWindow.h` / `MainWindow.cpp`(空窗口)**

```cpp
// src/ui/MainWindow.h
#pragma once
#include <QMainWindow>

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
};
```

```cpp
// src/ui/MainWindow.cpp
#include "MainWindow.h"
#include <QApplication>

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle("KellectConsole");
    resize(960, 640);
}
```

- [ ] **Step 5: 写 `main.cpp`(HighDpi + 启动空窗口)**

```cpp
// src/main.cpp
#include <QApplication>
#include <QtPlugin>
#include "ui/MainWindow.h"

Q_IMPORT_PLUGIN(QWindowsIntegrationPlugin) // 静态 Qt:显式导入平台插件

int main(int argc, char* argv[]) {
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
    QApplication app(argc, argv);

    MainWindow w;
    w.show();
    return app.exec();
}
```

- [ ] **Step 6: 写 `tests/CMakeLists.txt`(占位,后续任务填充)**

```cmake
# 各 QtTest 在对应任务里 add_executable + add_test 注册
```

- [ ] **Step 7: 写 `.gitignore`**

```
build/
*.user
```

- [ ] **Step 8: 配置 + 构建,验证工具链通过**

Run(在 `gui/QtKellectConsole/` 下)。Task 1 实测:VS generator + v142 在此 VS2022 安装下检测坏(`No CMAKE_CXX_COMPILER`)→ 改用 **Ninja** + vcvars(cl.exe 14.29 / SDK 19041)+ `-DCMAKE_EXE_LINKER_FLAGS=/MANIFEST:NO`(app.rc 已嵌 manifest,免 CVT1100)。已固化进 `scripts/build.bat`:
```bat
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" x64 10.0.19041.0 -vcvars_ver=14.29
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=D:/Code/Qt/5.15.2-static -DCMAKE_SYSTEM_VERSION=10.0.19041.0 -DCMAKE_EXE_LINKER_FLAGS=/MANIFEST:NO
cmake --build build
```
Git Bash 跑:`cmd //c scripts\build.bat`。Expected: `build/KellectConsole.exe`(Ninja 单 config,无 Release/ 子目录),无链接错误。fallback:CMake 子 MSBuild 没继承 `LIB` → bat 里 vcvars 后 `set "LIB=...;...\19041.0\ucrt\x64"` + INCLUDE 钉 19041 再 configure。

- [ ] **Step 9: 验证 manifest 嵌入**

Run: `mt.exe -inputresource:build\Release\KellectConsole.exe -out:extracted.manifest`
Expected: 生成 `extracted.manifest`,内含 `requireAdministrator` 与 `dpiAware`。

- [ ] **Step 10: Commit**

```bash
git add gui/QtKellectConsole/
git commit -m "feat(qt-gui): scaffold Qt5.15 Widgets project + manifest + empty MainWindow"
```

---

### Task 2: Flags(8-bit 事件位)

**Files:**
- Create: `gui/QtKellectConsole/src/domain/Flags.h`
- Create: `gui/QtKellectConsole/tests/tst_flags.cpp`
- Modify: `gui/QtKellectConsole/CMakeLists.txt`(加 domain include + tst_flags)
- Modify: `gui/QtKellectConsole/tests/CMakeLists.txt`(注册 tst_flags)

**Interfaces:**
- Produces: `enum class EventFlag : quint8 {Process=0x01,Thread=0x02,Image=0x04,File=0x08,Disk=0x10,Registry=0x20,CallStack=0x40,TcpIp=0x80}`;`quint8 buildMask(const QVector<EventFlag>&)`;`QString maskToHex(quint8)`(格式 `0x1F`);`QStringList buildKellectArgs(quint8)`(返回 `{"-e","0x1F","-c"}`)。

- [ ] **Step 1: 写 `tst_flags.cpp`(失败测试)**

```cpp
// tests/tst_flags.cpp
#include <QtTest>
#include "domain/Flags.h"

class TestFlags : public QObject { Q_OBJECT
private slots:
    void buildMaskCombinesBits();
    void buildMaskEmptyIsZero();
    void maskToHexFormat();
    void buildKellectArgsFormat();
};

void TestFlags::buildMaskCombinesBits() {
    QCOMPARE(buildMask({EventFlag::Process, EventFlag::File}), quint8(0x01 | 0x08));
}
void TestFlags::buildMaskEmptyIsZero() {
    QCOMPARE(buildMask({}), quint8(0));
}
void TestFlags::maskToHexFormat() {
    QCOMPARE(maskToHex(0x1F), QString("0x1F"));
    QCOMPARE(maskToHex(0x00), QString("0x00"));
}
void TestFlags::buildKellectArgsFormat() {
    QCOMPARE(buildKellectArgs(0x1F), QStringList({"-e", "0x1F", "-c"}));
}

QTEST_GUILESS_MAIN(TestFlags)
#include "tst_flags.moc"
```

- [ ] **Step 2: 注册 tst_flags 到 `tests/CMakeLists.txt`**

```cmake
add_executable(tst_flags tst_flags.cpp)
target_link_libraries(tst_flags PRIVATE Qt5::Test)
target_include_directories(tst_flags PRIVATE ${CMAKE_SOURCE_DIR}/src)
add_test(NAME tst_flags COMMAND tst_flags)
```

并在顶层 `CMakeLists.txt` 的 `set(SOURCES ...)` 后确认 `domain/Flags.h` 由头文件提供(header-only);无需加到 SOURCES,但需让目标可见(已在 `target_include_directories ... src`)。

- [ ] **Step 3: 运行测试,确认失败(头不存在)**

Run: `cmake --build build --config Release --target tst_flags && ctest --test-dir build -R tst_flags`
Expected: 编译失败 `domain/Flags.h: No such file`。

- [ ] **Step 4: 写 `domain/Flags.h`**

```cpp
// src/domain/Flags.h
#pragma once
#include <QtGlobal>
#include <QVector>
#include <QString>
#include <QStringList>

namespace kellect {

enum class EventFlag : quint8 {
    Process  = 0x01,
    Thread   = 0x02,
    Image    = 0x04,
    File     = 0x08,
    Disk     = 0x10,
    Registry = 0x20,
    CallStack= 0x40,
    TcpIp    = 0x80,
};

inline quint8 buildMask(const QVector<EventFlag>& flags) {
    quint8 m = 0;
    for (auto f : flags) m |= static_cast<quint8>(f);
    return m;
}

inline QString maskToHex(quint8 mask) {
    return "0x" + QString::number(mask, 16).toUpper().rightJustified(2, '0');
}

inline QStringList buildKellectArgs(quint8 mask) {
    return QStringList{ "-e", maskToHex(mask), "-c" };
}

} // namespace kellect

using namespace kellect; // 测试与 UI 直接用非限定名
```

- [ ] **Step 5: 重建并跑测试,确认通过**

Run: `cmake --build build --config Release && ctest --test-dir build -R tst_flags --output-on-failure`
Expected: 4 个测试 PASS。

- [ ] **Step 6: Commit**

```bash
git add gui/QtKellectConsole/src/domain/Flags.h gui/QtKellectConsole/tests/tst_flags.cpp gui/QtKellectConsole/tests/CMakeLists.txt
git commit -m "feat(qt-gui): 8-bit event flags + mask/args builders with tests"
```

---

### Task 3: Preset(预设组合)

**Files:**
- Create: `gui/QtKellectConsole/src/domain/Preset.h`
- Create: `gui/QtKellectConsole/src/domain/Preset.cpp`
- Create: `gui/QtKellectConsole/tests/tst_preset.cpp`
- Modify: `gui/QtKellectConsole/tests/CMakeLists.txt`
- Modify: `gui/QtKellectConsole/CMakeLists.txt`(SOURCES 加 `src/domain/Preset.cpp`)

**Interfaces:**
- Produces: `struct Preset { QString name; QVector<EventFlag> flags; };`;`QVector<Preset> defaultPresets();`。

- [ ] **Step 1: 写 `tst_preset.cpp`**

```cpp
#include <QtTest>
#include "domain/Preset.h"
#include "domain/Flags.h"

class TestPreset : public QObject { Q_OBJECT
private slots:
    void defaultsNonEmpty();
    void allPresetCoversEveryFlag();
    void minimalPresetMask();
};

void TestPreset::defaultsNonEmpty() {
    QVERIFY(!defaultPresets().isEmpty());
}
void TestPreset::allPresetCoversEveryFlag() {
    Preset all;
    for (const auto& p : defaultPresets())
        if (p.name == "全部") all = p;
    quint8 m = buildMask(all.flags);
    QCOMPARE(m, quint8(0xFF));
}
void TestPreset::minimalPresetMask() {
    Preset p;
    for (const auto& x : defaultPresets())
        if (x.name == "精简") p = x;
    QCOMPARE(buildMask(p.flags), quint8(EventFlag::Process | EventFlag::File));
}

QTEST_GUILESS_MAIN(TestPreset)
#include "tst_preset.moc"
```

- [ ] **Step 2: 注册到 `tests/CMakeLists.txt`**

```cmake
add_executable(tst_preset tst_preset.cpp)
target_link_libraries(tst_preset PRIVATE Qt5::Test)
target_include_directories(tst_preset PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_sources(tst_preset PRIVATE ${CMAKE_SOURCE_DIR}/src/domain/Preset.cpp)
add_test(NAME tst_preset COMMAND tst_preset)
```

- [ ] **Step 3: 跑测试确认失败**

Run: `cmake --build build --config Release --target tst_preset && ctest --test-dir build -R tst_preset`
Expected: 编译失败(`domain/Preset.h` 缺失)。

- [ ] **Step 4: 写 `Preset.h` / `Preset.cpp`**

```cpp
// src/domain/Preset.h
#pragma once
#include <QString>
#include <QVector>
#include "Flags.h"

struct Preset {
    QString name;
    QVector<EventFlag> flags;
};

QVector<Preset> defaultPresets();
```

```cpp
// src/domain/Preset.cpp
#include "Preset.h"

QVector<Preset> defaultPresets() {
    return {
        { QStringLiteral("全部"), { EventFlag::Process, EventFlag::Thread, EventFlag::Image,
            EventFlag::File, EventFlag::Disk, EventFlag::Registry,
            EventFlag::CallStack, EventFlag::TcpIp } },
        { QStringLiteral("精简"), { EventFlag::Process, EventFlag::File } },
        { QStringLiteral("IO"),   { EventFlag::File, EventFlag::Disk, EventFlag::Registry } },
        { QStringLiteral("网络"), { EventFlag::TcpIp } },
    };
}
```

- [ ] **Step 5: 跑测试确认通过**

Run: `cmake --build build --config Release && ctest --test-dir build -R "tst_flags|tst_preset" --output-on-failure`
Expected: tst_flags + tst_preset 全 PASS。

- [ ] **Step 6: Commit**

```bash
git add gui/QtKellectConsole/src/domain/Preset.h gui/QtKellectConsole/src/domain/Preset.cpp gui/QtKellectConsole/tests/tst_preset.cpp gui/QtKellectConsole/tests/CMakeLists.txt gui/QtKellectConsole/CMakeLists.txt
git commit -m "feat(qt-gui): event presets with tests"
```

---

### Task 4: Utf8Accumulator(UTF-8 容错解码 + 计数)

**Files:**
- Create: `gui/QtKellectConsole/src/domain/Utf8Accumulator.h`
- Create: `gui/QtKellectConsole/src/domain/Utf8Accumulator.cpp`
- Create: `gui/QtKellectConsole/tests/tst_utf8accumulator.cpp`
- Modify: `gui/QtKellectConsole/tests/CMakeLists.txt`
- Modify: `gui/QtKellectConsole/CMakeLists.txt`(SOURCES 加 `src/domain/Utf8Accumulator.cpp`)

**Interfaces:**
- Produces: `class Utf8Accumulator { void feed(const QByteArray&); bool takeLine(QString& out); int errorCount() const; };`。行为:按 UTF-8 状态机解码,无效字节→U+FFFD 并 `++errorCount`,以 `\n` 切行,跳过流首 BOM,跨 `feed` 保留残余多字节序列。

- [ ] **Step 1: 写 `tst_utf8accumulator.cpp`(覆盖 5 类情形)**

```cpp
#include <QtTest>
#include "domain/Utf8Accumulator.h"

class TestUtf8 : public QObject { Q_OBJECT
private slots:
    void asciiLine();
    void validMultibyte();
    void invalidBytesCounted();
    void splitMultibyteAcrossFeeds();
    void skipsBom();
};

void feedLine(Utf8Accumulator& a, const QByteArray& bytes, QString& got) {
    a.feed(bytes);
    QString line;
    while (a.takeLine(line)) got = line;
}

void TestUtf8::asciiLine() {
    Utf8Accumulator a; QString line;
    feedLine(a, "hello\n", line);
    QCOMPARE(line, QString("hello"));
    QCOMPARE(a.errorCount(), 0);
}
void TestUtf8::validMultibyte() {
    Utf8Accumulator a; QString line;
    // "中文" in valid UTF-8
    feedLine(a, QString("中文").toUtf8() + "\n", line);
    QCOMPARE(line, QString("中文"));
    QCOMPARE(a.errorCount(), 0);
}
void TestUtf8::invalidBytesCounted() {
    Utf8Accumulator a; QString line;
    // 0xC4 0xE3 = "你" in GBK, illegal as UTF-8 lead/continuation mix
    feedLine(a, QByteArray("\xC4\xE3\n"), line);
    QVERIFY(line.contains(QChar(0xFFFD)));
    QCOMPARE(a.errorCount(), 2); // each stray byte is one replacement
}
void TestUtf8::splitMultibyteAcrossFeeds() {
    Utf8Accumulator a; QString line;
    QByteArray whole = QString("中").toUtf8() + "\n"; // 3 bytes + \n
    a.feed(whole.left(2));      // partial
    QVERIFY(!a.takeLine(line));
    a.feed(whole.mid(2));       // remainder + newline
    while (a.takeLine(line)) {}
    QCOMPARE(line, QString("中"));
    QCOMPARE(a.errorCount(), 0);
}
void TestUtf8::skipsBom() {
    Utf8Accumulator a; QString line;
    feedLine(a, QByteArray("\xEF\xBB\xBF") + "x\n", line);
    QCOMPARE(line, QString("x"));
    QCOMPARE(a.errorCount(), 0);
}

QTEST_GUILESS_MAIN(TestUtf8)
#include "tst_utf8.moc"
```

- [ ] **Step 2: 注册到 `tests/CMakeLists.txt`**

```cmake
add_executable(tst_utf8accumulator tst_utf8accumulator.cpp)
target_link_libraries(tst_utf8accumulator PRIVATE Qt5::Test)
target_include_directories(tst_utf8accumulator PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_sources(tst_utf8accumulator PRIVATE ${CMAKE_SOURCE_DIR}/src/domain/Utf8Accumulator.cpp)
add_test(NAME tst_utf8accumulator COMMAND tst_utf8accumulator)
```

- [ ] **Step 3: 跑测试确认失败**

Run: `cmake --build build --config Release --target tst_utf8accumulator && ctest --test-dir build -R tst_utf8accumulator`
Expected: 编译失败(`domain/Utf8Accumulator.h` 缺失)。

- [ ] **Step 4: 写 `Utf8Accumulator.h`**

```cpp
// src/domain/Utf8Accumulator.h
#pragma once
#include <QByteArray>
#include <QString>

class Utf8Accumulator {
public:
    void feed(const QByteArray& bytes);
    bool takeLine(QString& out); // 弹出一个完整解码行;无完整行返回 false
    int errorCount() const { return errors_; }
private:
    QByteArray buf_;     // 未切行的累积字节(含跨行残余多字节)
    int errors_ = 0;
    bool bomChecked_ = false;
};
```

- [ ] **Step 5: 写 `Utf8Accumulator.cpp`(UTF-8 状态机)**

```cpp
// src/domain/Utf8Accumulator.cpp
#include "Utf8Accumulator.h"
#include <vector>

// 把一段 UTF-8 字节解码为 QString,非法字节替换为 U+FFFD 并计数。
static QString decodeUtf8(const QByteArray& bytes, int& errors) {
    const unsigned char* p = reinterpret_cast<const unsigned char*>(bytes.constData());
    int n = bytes.size();
    QString out;
    out.reserve(n);
    int i = 0;
    while (i < n) {
        unsigned char b = p[i];
        int need = 0;
        uint32_t cp = 0;
        if (b < 0x80)               { need = 1; cp = b; }
        else if ((b & 0xE0) == 0xC0){ need = 2; cp = b & 0x1F; }
        else if ((b & 0xF0) == 0xE0){ need = 3; cp = b & 0x0F; }
        else if ((b & 0xF8) == 0xF0){ need = 4; cp = b & 0x07; }
        else { ++errors; out.append(QChar(0xFFFD)); ++i; continue; }

        if (i + need > n) { // 行内末尾字节不足(buf_ 已保证切到 \n,raw 完整)→ 非法
            ++errors; out.append(QChar(0xFFFD)); ++i; continue;
        }
        bool ok = true;
        for (int j = 1; j < need; ++j) {
            unsigned char c = p[i + j];
            if ((c & 0xC0) != 0x80) { ok = false; break; }
            cp = (cp << 6) | (c & 0x3F);
        }
        if (!ok) { ++errors; out.append(QChar(0xFFFD)); ++i; continue; }
        out.append(QString::fromUcs4(&cp, 1));
        i += need;
    }
    return out;
}

void Utf8Accumulator::feed(const QByteArray& bytes) {
    buf_ += bytes;
    if (!bomChecked_) {
        bomChecked_ = true;
        if (buf_.size() >= 3 &&
            (unsigned char)buf_[0] == 0xEF &&
            (unsigned char)buf_[1] == 0xBB &&
            (unsigned char)buf_[2] == 0xBF) {
            buf_.remove(0, 3);
        }
    }
}

bool Utf8Accumulator::takeLine(QString& out) {
    int idx = buf_.indexOf('\n');
    if (idx < 0) return false;
    QByteArray raw = buf_.left(idx);
    buf_.remove(0, idx + 1);
    out = decodeUtf8(raw, errors_);
    // 去 \r 与行首 BOM 残余
    if (out.endsWith('\r')) out.chop(1);
    out.remove(QChar(0xFEFF));
    return true;
}
```

- [ ] **Step 6: 跑测试确认通过**

Run: `cmake --build build --config Release && ctest --test-dir build -R tst_utf8accumulator --output-on-failure`
Expected: 5 个测试 PASS。若 `splitMultibyteAcrossFeeds` 失败,检查 `decodeUtf8` 的 `i + need > n` 截断逻辑是否保留了残余字节(`buf_` 仍含未切行字节,下次 feed 追加后重切)。

> **实现注记:** `takeLine` 切到 `\n` 时,`decodeUtf8` 对 raw 整段解码;若 raw 末尾恰好是半截多字节(理论罕见,因 kellect 行以 `\n` 结束完整事件 JSON),会被替换为 U+FFFD。生产中 kellect 每行是完整 JSON,不会半截;跨 `feed` 的半截只发生在字节流恰在行中间断开而尚未见 `\n` 时——此时 `buf_` 累积到见 `\n` 才切,残余自然拼全。Task 4 的 `splitMultibyteAcrossFeeds` 即验证此路径。

- [ ] **Step 7: Commit**

```bash
git add gui/QtKellectConsole/src/domain/Utf8Accumulator.h gui/QtKellectConsole/src/domain/Utf8Accumulator.cpp gui/QtKellectConsole/tests/tst_utf8accumulator.cpp gui/QtKellectConsole/tests/CMakeLists.txt gui/QtKellectConsole/CMakeLists.txt
git commit -m "feat(qt-gui): UTF-8 tolerant accumulator with replacement+count"
```

---

### Task 5: SettingsStore(JSON 持久化)

**Files:**
- Create: `gui/QtKellectConsole/src/domain/SettingsStore.h`
- Create: `gui/QtKellectConsole/src/domain/SettingsStore.cpp`
- Create: `gui/QtKellectConsole/tests/tst_settingsstore.cpp`
- Modify: `gui/QtKellectConsole/tests/CMakeLists.txt`
- Modify: `gui/QtKellectConsole/CMakeLists.txt`

**Interfaces:**
- Produces: `struct SettingsStore::Settings { QString kellectExePath; quint8 lastMask=0; bool autoScroll=true; QString filterKeyword; };`;`Settings load() const;`(文件缺失/损坏→默认);`void save(const Settings&) const;`。

- [ ] **Step 1: 写 `tst_settingsstore.cpp`**

```cpp
#include <QtTest>
#include <QTemporaryFile>
#include "domain/SettingsStore.h"

class TestSettings : public QObject { Q_OBJECT
private slots:
    void missingFileReturnsDefaults();
    void roundTrip();
    void corruptedFileReturnsDefaults();
};

void TestSettings::missingFileReturnsDefaults() {
    SettingsStore s(QDir::tempPath() + "/kellect_no_exist.json");
    auto d = s.load();
    QCOMPARE(d.autoScroll, true);
    QCOMPARE(d.lastMask, quint8(0));
}
void TestSettings::roundTrip() {
    QString path = QDir::tempPath() + "/kellect_rt.json";
    QFile::remove(path);
    SettingsStore s(path);
    SettingsStore::Settings in;
    in.kellectExePath = "C:/kellect.exe";
    in.lastMask = 0x1F;
    in.autoScroll = false;
    in.filterKeyword = "FileIO";
    s.save(in);
    auto out = s.load();
    QCOMPARE(out.kellectExePath, in.kellectExePath);
    QCOMPARE(out.lastMask, in.lastMask);
    QCOMPARE(out.autoScroll, in.autoScroll);
    QCOMPARE(out.filterKeyword, in.filterKeyword);
}
void TestSettings::corruptedFileReturnsDefaults() {
    QString path = QDir::tempPath() + "/kellect_bad.json";
    QFile f(path); f.open(QIODevice::WriteOnly); f.write("{ not json"); f.close();
    SettingsStore s(path);
    auto d = s.load();
    QCOMPARE(d.autoScroll, true); // 默认,不崩
}

QTEST_GUILESS_MAIN(TestSettings)
#include "tst_settingsstore.moc"
```

- [ ] **Step 2: 注册到 `tests/CMakeLists.txt`**

```cmake
add_executable(tst_settingsstore tst_settingsstore.cpp)
target_link_libraries(tst_settingsstore PRIVATE Qt5::Test)
target_include_directories(tst_settingsstore PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_sources(tst_settingsstore PRIVATE ${CMAKE_SOURCE_DIR}/src/domain/SettingsStore.cpp)
add_test(NAME tst_settingsstore COMMAND tst_settingsstore)
```

- [ ] **Step 3: 跑测试确认失败**

Run: `cmake --build build --config Release --target tst_settingsstore && ctest --test-dir build -R tst_settingsstore`
Expected: 编译失败(`domain/SettingsStore.h` 缺失)。

- [ ] **Step 4: 写 `SettingsStore.h` / `.cpp`**

```cpp
// src/domain/SettingsStore.h
#pragma once
#include <QString>
#include <QtGlobal>

class SettingsStore {
public:
    struct Settings {
        QString kellectExePath;
        quint8 lastMask = 0;
        bool autoScroll = true;
        QString filterKeyword;
    };
    explicit SettingsStore(QString path) : path_(std::move(path)) {}
    Settings load() const;
    void save(const Settings& s) const;
private:
    QString path_;
};
```

```cpp
// src/domain/SettingsStore.cpp
#include "SettingsStore.h"
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>

SettingsStore::Settings SettingsStore::load() const {
    Settings d; // defaults
    QFile f(path_);
    if (!f.open(QIODevice::ReadOnly)) return d;
    QJsonParseError err;
    auto doc = QJsonDocument::fromJson(f.readAll(), &err);
    f.close();
    if (err.error != QJsonParseError::NoError || !doc.isObject()) return d;
    auto o = doc.object();
    d.kellectExePath = o.value("kellectExePath").toString();
    d.lastMask        = static_cast<quint8>(o.value("lastMask").toInt(0));
    d.autoScroll      = o.value("autoScroll").toBool(true);
    d.filterKeyword   = o.value("filterKeyword").toString();
    return d;
}

void SettingsStore::save(const Settings& s) const {
    QJsonObject o;
    o["kellectExePath"] = s.kellectExePath;
    o["lastMask"]       = s.lastMask;
    o["autoScroll"]     = s.autoScroll;
    o["filterKeyword"]  = s.filterKeyword;
    QFile f(path_);
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        f.write(QJsonDocument(o).toJson(QJsonDocument::Indented));
}
```

- [ ] **Step 5: 跑测试确认通过**

Run: `cmake --build build --config Release && ctest --test-dir build -R tst_settingsstore --output-on-failure`
Expected: 3 个测试 PASS。

- [ ] **Step 6: Commit**

```bash
git add gui/QtKellectConsole/src/domain/SettingsStore.h gui/QtKellectConsole/src/domain/SettingsStore.cpp gui/QtKellectConsole/tests/tst_settingsstore.cpp gui/QtKellectConsole/tests/CMakeLists.txt gui/QtKellectConsole/CMakeLists.txt
git commit -m "feat(qt-gui): JSON settings store with defaults fallback"
```

---

### Task 6: ProcessState + KellectProcessService(QProcess 状态机)

**Files:**
- Create: `gui/QtKellectConsole/src/process/ProcessState.h`
- Create: `gui/QtKellectConsole/src/process/KellectProcessService.h`
- Create: `gui/QtKellectConsole/src/process/KellectProcessService.cpp`
- Create: `gui/QtKellectConsole/tests/tst_processservice.cpp`
- Modify: `gui/QtKellectConsole/tests/CMakeLists.txt`
- Modify: `gui/QtKellectConsole/CMakeLists.txt`

**Interfaces:**
- Produces: `enum class ProcessState { Idle, Starting, Running };`;`class KellectProcessService : public QObject`,`start(const QString& exe, const QStringList& args)`、`stop()`、`ProcessState state() const`;信号 `stateChanged(ProcessState)`、`outputLine(const QString&)`、`startFailed(const QString&)`、`decodeErrorCountChanged(int)`。
- Consumes: `Utf8Accumulator`(Task 4)。

- [ ] **Step 1: 写 `tst_processservice.cpp`(用真实 `cmd.exe` 驱动)**

```cpp
#include <QtTest>
#include <QSignalSpy>
#include "process/KellectProcessService.h"

class TestProc : public QObject { Q_OBJECT
private slots:
    void startEmitsLineAndRunning();
    void nonexistentExeFails();
    void stopReturnsToIdle();
};

void TestProc::startEmitsLineAndRunning() {
    KellectProcessService svc;
    QSignalSpy lineSpy(&svc, &KellectProcessService::outputLine);
    QSignalSpy stateSpy(&svc, &KellectProcessService::stateChanged);
    // cmd.exe /c echo hello —— 通用、Win7/10/11 自带
    svc.start("cmd.exe", {"/c", "echo", "hello"});
    QVERIFY(lineSpy.wait(5000));
    QVERIFY(!lineSpy.isEmpty());
    QCOMPARE(svc.state(), ProcessState::Running);
    svc.stop();
    QCOMPARE(svc.state(), ProcessState::Idle);
}
void TestProc::nonexistentExeFails() {
    KellectProcessService svc;
    QSignalSpy failSpy(&svc, &KellectProcessService::startFailed);
    svc.start("C:/nonexistent_xyz_exe.exe", {});
    QVERIFY(failSpy.wait(5000));
    QCOMPARE(svc.state(), ProcessState::Idle);
}
void TestProc::stopReturnsToIdle() {
    KellectProcessService svc;
    svc.start("cmd.exe", {"/c", "ping", "-n", "30", "127.0.0.1"}); // 长任务
    QSignalSpy stateSpy(&svc, &KellectProcessService::stateChanged);
    QVERIFY(stateSpy.wait(3000)); // Running
    svc.stop();
    QCOMPARE(svc.state(), ProcessState::Idle);
}

QTEST_GUILESS_MAIN(TestProc)
#include "tst_processservice.moc"
```

- [ ] **Step 2: 注册到 `tests/CMakeLists.txt`**

```cmake
add_executable(tst_processservice tst_processservice.cpp)
target_link_libraries(tst_processservice PRIVATE Qt5::Test)
target_include_directories(tst_processservice PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_sources(tst_processservice PRIVATE
    ${CMAKE_SOURCE_DIR}/src/process/KellectProcessService.cpp
    ${CMAKE_SOURCE_DIR}/src/domain/Utf8Accumulator.cpp)
add_test(NAME tst_processservice COMMAND tst_processservice)
```

- [ ] **Step 3: 跑测试确认失败**

Run: `cmake --build build --config Release --target tst_processservice && ctest --test-dir build -R tst_processservice`
Expected: 编译失败(`process/KellectProcessService.h` 缺失)。

- [ ] **Step 4: 写 `ProcessState.h`**

```cpp
// src/process/ProcessState.h
#pragma once

enum class ProcessState {
    Idle,
    Starting,
    Running,
};
```

- [ ] **Step 5: 写 `KellectProcessService.h`**

```cpp
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
    void decodeErrorCountChanged(int total);
private:
    void setState(ProcessState s);
    void onStdout();
    void pumpLines();

    QProcess proc_;
    Utf8Accumulator acc_;
    ProcessState state_ = ProcessState::Idle;
    int prevErrors_ = 0;
};
```

- [ ] **Step 6: 写 `KellectProcessService.cpp`**

```cpp
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
        emit outputLine(line);
        int e = acc_.errorCount();
        if (e != prevErrors_) {
            prevErrors_ = e;
            emit decodeErrorCountChanged(e);
        }
    }
}
```

- [ ] **Step 7: 跑测试确认通过**

Run: `cmake --build build --config Release && ctest --test-dir build -R tst_processservice --output-on-failure`
Expected: 3 个测试 PASS。若 `nonexistentExeFails` 超时,确认 `waitForStarted(5000)` 返回 false 后确实 `emit startFailed`(QProcess 在 Win 上对不存在 exe 通常立即 errorOccurred)。

- [ ] **Step 8: Commit**

```bash
git add gui/QtKellectConsole/src/process/ gui/QtKellectConsole/tests/tst_processservice.cpp gui/QtKellectConsole/tests/CMakeLists.txt gui/QtKellectConsole/CMakeLists.txt
git commit -m "feat(qt-gui): QProcess service with state machine + UTF-8 sink"
```

---

### Task 7: LogEntry + LogModel(含 50000 裁剪)

**Files:**
- Create: `gui/QtKellectConsole/src/domain/LogEntry.h`
- Create: `gui/QtKellectConsole/src/ui/LogModel.h`
- Create: `gui/QtKellectConsole/src/ui/LogModel.cpp`
- Create: `gui/QtKellectConsole/tests/tst_logmodel.cpp`
- Modify: `gui/QtKellectConsole/tests/CMakeLists.txt`
- Modify: `gui/QtKellectConsole/CMakeLists.txt`

**Interfaces:**
- Produces: `struct LogEntry { QDateTime time; QString text; int decodeErrors=0; bool marked=false; };`;`class LogModel : public QAbstractListModel`,roles `TextRole/TimeRole/DecodeErrorsRole/MarkedRole`;`void append(const LogEntry&)`、`void trimIfFull()`、`int totalDecodeErrors() const`、`void toggleMark(int row)`、`QVector<LogEntry> filter(const QString& kw) const`。
- 常量 `kMaxLines=50000`、`kTrimBatch=5000`。

- [ ] **Step 1: 写 `tst_logmodel.cpp`**

```cpp
#include <QtTest>
#include "ui/LogModel.h"
#include "domain/LogEntry.h"

class TestModel : public QObject { Q_OBJECT
private slots:
    void appendGrowsRowCount();
    void trimRemovesOldestBatch();
    void toggleMark();
    void totalDecodeErrors();
};

void TestModel::appendGrowsRowCount() {
    LogModel m;
    QCOMPARE(m.rowCount(), 0);
    m.append({ QDateTime::currentDateTime(), "x", 0, false });
    QCOMPARE(m.rowCount(), 1);
}
void TestModel::trimRemovesOldestBatch() {
    LogModel m;
    for (int i = 0; i < kMaxLines + 1; ++i)
        m.append({ QDateTime::currentDateTime(), QString::number(i), 0, false });
    m.trimIfFull();
    QCOMPARE(m.rowCount(), kMaxLines + 1 - kTrimBatch); // 45001
}
void TestModel::toggleMark() {
    LogModel m;
    m.append({ QDateTime::currentDateTime(), "a", 0, false });
    m.toggleMark(0);
    QCOMPARE(m.data(m.index(0), LogModel::MarkedRole).toBool(), true);
    m.toggleMark(0);
    QCOMPARE(m.data(m.index(0), LogModel::MarkedRole).toBool(), false);
}
void TestModel::totalDecodeErrors() {
    LogModel m;
    m.append({ QDateTime::currentDateTime(), "a", 2, false });
    m.append({ QDateTime::currentDateTime(), "b", 3, false });
    QCOMPARE(m.totalDecodeErrors(), 5);
}

QTEST_GUILESS_MAIN(TestModel)
#include "tst_logmodel.moc"
```

- [ ] **Step 2: 注册到 `tests/CMakeLists.txt`**

```cmake
add_executable(tst_logmodel tst_logmodel.cpp)
target_link_libraries(tst_logmodel PRIVATE Qt5::Test Qt5::Gui)
target_include_directories(tst_logmodel PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_sources(tst_logmodel PRIVATE ${CMAKE_SOURCE_DIR}/src/ui/LogModel.cpp)
add_test(NAME tst_logmodel COMMAND tst_logmodel)
```

- [ ] **Step 3: 跑测试确认失败**

Run: `cmake --build build --config Release --target tst_logmodel && ctest --test-dir build -R tst_logmodel`
Expected: 编译失败。

- [ ] **Step 4: 写 `LogEntry.h`**

```cpp
// src/domain/LogEntry.h
#pragma once
#include <QDateTime>
#include <QString>

struct LogEntry {
    QDateTime time;
    QString text;
    int decodeErrors = 0;
    bool marked = false;
};
```

- [ ] **Step 5: 写 `LogModel.h` / `.cpp`**

```cpp
// src/ui/LogModel.h
#pragma once
#include <QAbstractListModel>
#include <QVector>
#include "../domain/LogEntry.h"

inline constexpr int kMaxLines  = 50000;
inline constexpr int kTrimBatch = 5000;

class LogModel : public QAbstractListModel {
    Q_OBJECT
public:
    enum Roles { TextRole = Qt::UserRole + 1, TimeRole, DecodeErrorsRole, MarkedRole };

    int rowCount(const QModelIndex& = {}) const override { return rows_.size(); }
    QVariant data(const QModelIndex& idx, int role) const override;

    void append(const LogEntry& e);
    void trimIfFull();
    void toggleMark(int row);
    int totalDecodeErrors() const;
    const QVector<LogEntry>& rows() const { return rows_; }
private:
    QVector<LogEntry> rows_;
    int totalErrors_ = 0;
};
```

```cpp
// src/ui/LogModel.cpp
#include "LogModel.h"

QVariant LogModel::data(const QModelIndex& idx, int role) const {
    if (!idx.isValid() || idx.row() < 0 || idx.row() >= rows_.size()) return {};
    const auto& e = rows_[idx.row()];
    switch (role) {
        case TextRole:        return e.text;
        case TimeRole:        return e.time;
        case DecodeErrorsRole:return e.decodeErrors;
        case MarkedRole:      return e.marked;
    }
    return {};
}

void LogModel::append(const LogEntry& e) {
    const int n = rows_.size();
    beginInsertRows({}, n, n);
    rows_.append(e);
    totalErrors_ += e.decodeErrors;
    endInsertRows();
}

void LogModel::trimIfFull() {
    if (rows_.size() <= kMaxLines) return;
    const int cut = kTrimBatch;
    beginRemoveRows({}, 0, cut - 1);
    for (int i = 0; i < cut; ++i) totalErrors_ -= rows_[i].decodeErrors;
    rows_.remove(0, cut);
    endRemoveRows();
}

void LogModel::toggleMark(int row) {
    if (row < 0 || row >= rows_.size()) return;
    rows_[row].marked = !rows_[row].marked;
    emit dataChanged(index(row), index(row), {MarkedRole});
}

int LogModel::totalDecodeErrors() const { return totalErrors_; }
```

- [ ] **Step 6: 跑测试确认通过**

Run: `cmake --build build --config Release && ctest --test-dir build -R tst_logmodel --output-on-failure`
Expected: 4 个测试 PASS(`trimRemovesOldestBatch` 插 50001 行约秒级,可接受)。

- [ ] **Step 7: Commit**

```bash
git add gui/QtKellectConsole/src/domain/LogEntry.h gui/QtKellectConsole/src/ui/LogModel.h gui/QtKellectConsole/src/ui/LogModel.cpp gui/QtKellectConsole/tests/tst_logmodel.cpp gui/QtKellectConsole/tests/CMakeLists.txt gui/QtKellectConsole/CMakeLists.txt
git commit -m "feat(qt-gui): LogModel with 50k-line saturation trimming"
```

---

### Task 8: EventColor(Event→域→颜色 纯逻辑)

**Files:**
- Create: `gui/QtKellectConsole/src/ui/EventColor.h`
- Create: `gui/QtKellectConsole/src/ui/EventColor.cpp`
- Create: `gui/QtKellectConsole/tests/tst_eventcolor.cpp`
- Modify: `gui/QtKellectConsole/tests/CMakeLists.txt`
- Modify: `gui/QtKellectConsole/CMakeLists.txt`

**Interfaces:**
- Produces: `enum class EventDomain { Process,Thread,Image,File,Disk,Registry,CallStack,TcpIp,None };`;`EventDomain domainOfEvent(const QString& eventName)`;`QColor textColor(EventDomain d, bool decodeError)`(decodeError 优先红);`QColor markBackground()`。

- [ ] **Step 1: 写 `tst_eventcolor.cpp`**

```cpp
#include <QtTest>
#include <QColor>
#include "ui/EventColor.h"

class TestColor : public QObject { Q_OBJECT
private slots:
    void prefixMapping();
    void unknownIsNone();
    void decodeErrorOverridesColor();
};

void TestColor::prefixMapping() {
    QCOMPARE(domainOfEvent("ProcessStart"),  EventDomain::Process);
    QCOMPARE(domainOfEvent("ThreadStart"),   EventDomain::Thread);
    QCOMPARE(domainOfEvent("ImageLoad"),     EventDomain::Image);
    QCOMPARE(domainOfEvent("FileIOCreate"),  EventDomain::File);
    QCOMPARE(domainOfEvent("DiskIORead"),    EventDomain::Disk);
    QCOMPARE(domainOfEvent("RegistryCreate"),EventDomain::Registry);
    QCOMPARE(domainOfEvent("TcpIpConnect"),  EventDomain::TcpIp);
}
void TestColor::unknownIsNone() {
    QCOMPARE(domainOfEvent(""),            EventDomain::None);
    QCOMPARE(domainOfEvent("WeirdEvent"),  EventDomain::None);
}
void TestColor::decodeErrorOverridesColor() {
    QColor normal = textColor(EventDomain::File, false);
    QColor errored = textColor(EventDomain::File, true);
    QCOMPARE(errored, QColor("#E07070")); // 解码异常固定红
    QVERIFY(normal != errored);
}

QTEST_GUILESS_MAIN(TestColor)
#include "tst_eventcolor.moc"
```

- [ ] **Step 2: 注册到 `tests/CMakeLists.txt`**

```cmake
add_executable(tst_eventcolor tst_eventcolor.cpp)
target_link_libraries(tst_eventcolor PRIVATE Qt5::Test Qt5::Gui)
target_include_directories(tst_eventcolor PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_sources(tst_eventcolor PRIVATE ${CMAKE_SOURCE_DIR}/src/ui/EventColor.cpp)
add_test(NAME tst_eventcolor COMMAND tst_eventcolor)
```

- [ ] **Step 3: 跑测试确认失败**

Run: `cmake --build build --config Release --target tst_eventcolor && ctest --test-dir build -R tst_eventcolor`
Expected: 编译失败。

- [ ] **Step 4: 写 `EventColor.h` / `.cpp`**

```cpp
// src/ui/EventColor.h
#pragma once
#include <QString>
#include <QColor>

enum class EventDomain {
    Process, Thread, Image, File, Disk, Registry, CallStack, TcpIp, None
};

// 解析 kellect JSON 的 "Event" 字段值 → 域(按前缀)。完整前缀表 plan 期可扩。
EventDomain domainOfEvent(const QString& eventName);
// 文字色:decodeError 优先红,否则域色。
QColor textColor(EventDomain d, bool decodeError);
// 书签行背景色。
QColor markBackground();
```

```cpp
// src/ui/EventColor.cpp
#include "EventColor.h"

EventDomain domainOfEvent(const QString& e) {
    if (e.startsWith("Process"))  return EventDomain::Process;
    if (e.startsWith("Thread"))   return EventDomain::Thread;
    if (e.startsWith("Image"))    return EventDomain::Image;
    if (e.startsWith("FileIO"))   return EventDomain::File;
    if (e.startsWith("DiskIO"))   return EventDomain::Disk;
    if (e.startsWith("Registry")) return EventDomain::Registry;
    if (e.startsWith("TcpIp") || e.startsWith("Tcp") || e.startsWith("Udp"))
                                 return EventDomain::TcpIp;
    return EventDomain::None;
}

QColor textColor(EventDomain d, bool decodeError) {
    if (decodeError) return QColor("#E07070");
    switch (d) {
        case EventDomain::Process:  return QColor("#9CDCFE"); // 浅蓝
        case EventDomain::Thread:   return QColor("#C586C0"); // 紫
        case EventDomain::Image:    return QColor("#CE9178"); // 棕
        case EventDomain::File:     return QColor("#DCDCAA"); // 黄
        case EventDomain::Disk:     return QColor("#B5CEA8"); // 浅绿
        case EventDomain::Registry: return QColor("#4EC9B0"); // 青
        case EventDomain::CallStack:return QColor("#D7BA7D"); // 金
        case EventDomain::TcpIp:    return QColor("#F44747"); // 红(网络)
        case EventDomain::None:     return QColor("#D4D4D4"); // 默认灰
    }
    return QColor("#D4D4D4");
}

QColor markBackground() { return QColor(255, 213, 79, 60); } // 半透明琥珀
```

- [ ] **Step 5: 跑测试确认通过**

Run: `cmake --build build --config Release && ctest --test-dir build -R tst_eventcolor --output-on-failure`
Expected: 3 个测试 PASS。

- [ ] **Step 6: Commit**

```bash
git add gui/QtKellectConsole/src/ui/EventColor.h gui/QtKellectConsole/src/ui/EventColor.cpp gui/QtKellectConsole/tests/tst_eventcolor.cpp gui/QtKellectConsole/tests/CMakeLists.txt gui/QtKellectConsole/CMakeLists.txt
git commit -m "feat(qt-gui): event-domain color mapping with decode-error override"
```

---

### Task 9: LogDelegate(自绘四项着色)

**Files:**
- Create: `gui/QtKellectConsole/src/ui/LogDelegate.h`
- Create: `gui/QtKellectConsole/src/ui/LogDelegate.cpp`
- Modify: `gui/QtKellectConsole/CMakeLists.txt`

**Interfaces:**
- Consumes: `LogModel`(Task 7)、`EventColor`(Task 8)。
- Produces: `class LogDelegate : public QStyledItemDelegate`,`paint()` 绘时间戳(灰等宽)+ 正文(域色/解码红),书签行底色;`sizeHint()` 单行高。无单元测试(paint 是像素级,由 Task 10 手测覆盖);逻辑依赖 EventColor 已测。

- [ ] **Step 1: 写 `LogDelegate.h`**

```cpp
// src/ui/LogDelegate.h
#pragma once
#include <QStyledItemDelegate>

class LogDelegate : public QStyledItemDelegate {
    Q_OBJECT
public:
    using QStyledItemDelegate::QStyledItemDelegate;
    void paint(QPainter* p, const QStyleOptionViewItem& o, const QModelIndex& idx) const override;
    QSize sizeHint(const QStyleOptionViewItem& o, const QModelIndex& idx) const override;
private:
    // 从行文本里抽取 kellect JSON 的 "Event" 值;非 JSON 行返回空串。
    static QString extractEvent(const QString& line);
};
```

- [ ] **Step 2: 写 `LogDelegate.cpp`**

```cpp
// src/ui/LogDelegate.cpp
#include "LogDelegate.h"
#include "LogModel.h"
#include "EventColor.h"
#include <QPainter>
#include <QJsonDocument>
#include <QJsonObject>

QString LogDelegate::extractEvent(const QString& line) {
    auto doc = QJsonDocument::fromJson(line.toUtf8());
    if (!doc.isObject()) return {};
    return doc.object().value("Event").toString();
}

void LogDelegate::paint(QPainter* p, const QStyleOptionViewItem& o, const QModelIndex& idx) const {
    p->save();

    const bool marked = idx.data(LogModel::MarkedRole).toBool();
    if (marked) {
        p->fillRect(o.rect, markBackground());
    }

    const QString text = idx.data(LogModel::TextRole).toString();
    const QDateTime time = idx.data(LogModel::TimeRole).toDateTime();
    const int decodeErrors = idx.data(LogModel::DecodeErrorsRole).toInt();
    const EventDomain domain = domainOfEvent(extractEvent(text));
    const QColor bodyColor = textColor(domain, decodeErrors > 0);

    const QFont mono("Consolas", 9);
    const QFont tsFont("Consolas", 9);
    QRect r = o.rect.adjusted(6, 0, -6, 0);

    // 时间戳分层(浅灰)
    QFontMetrics fmTs(tsFont);
    QString ts = "[" + time.toString("HH:mm:ss.zzz") + "] ";
    p->setFont(tsFont);
    p->setPen(QColor("#7A7A7A"));
    p->drawText(r, Qt::AlignLeft | Qt::AlignVCenter, ts);
    r.setLeft(r.left() + fmTs.horizontalAdvance(ts));

    // 正文(域色 / 解码红)
    p->setFont(mono);
    p->setPen(bodyColor);
    p->drawText(r, Qt::AlignLeft | Qt::AlignVCenter, text);

    p->restore();
}

QSize LogDelegate::sizeHint(const QStyleOptionViewItem& o, const QModelIndex&) const {
    QFontMetrics fm(QFont("Consolas", 9));
    return { o.rect.width(), std::max(18, fm.height() + 4) };
}
```

- [ ] **Step 3: 加入 CMake SOURCES 并构建确认**

在顶层 `CMakeLists.txt` 的 `set(SOURCES ...)` 追加 `src/ui/LogDelegate.cpp`、`src/ui/EventColor.cpp`、`src/ui/LogModel.cpp`(前序任务未加则一并补齐)。

Run: `cmake --build build --config Release --target KellectConsole`
Expected: 编译通过(delegate 此时尚未被 MainWindow 引用,为 dead code,不报错;Task 10 接线)。

- [ ] **Step 4: Commit**

```bash
git add gui/QtKellectConsole/src/ui/LogDelegate.h gui/QtKellectConsole/src/ui/LogDelegate.cpp gui/QtKellectConsole/CMakeLists.txt
git commit -m "feat(qt-gui): log delegate with layered timestamp + event coloring + marks"
```

---

### Task 10: MainWindow(组装 UI + 节流 + closeEvent)

**Files:**
- Modify: `gui/QtKellectConsole/src/ui/MainWindow.h`
- Modify: `gui/QtKellectConsole/src/ui/MainWindow.cpp`
- Modify: `gui/QtKellectConsole/src/main.cpp`(实例化带依赖)
- Modify: `gui/QtKellectConsole/CMakeLists.txt`(加全部 SOURCES)
- Create: `gui/QtKellectConsole/resources/dark.qss`

**Interfaces:**
- Consumes: 所有前序 domain/process/ui 组件。
- Produces: 可运行的完整 GUI(分组工具栏 + QListView + 路径选择 + 过滤 + 自动滚动节流 + 解码异常角标 + closeEvent 回收子进程)。无单元测试(集成 UI),靠手动 e2e。

- [ ] **Step 1: 写 `MainWindow.h`**

```cpp
// src/ui/MainWindow.h
#pragma once
#include <QMainWindow>
#include <QHash>
#include "LogModel.h"
#include "../process/KellectProcessService.h"
#include "../domain/SettingsStore.h"

class QCheckBox;
class QComboBox;
class QLineEdit;
class QLabel;
class QListView;
class QTimer;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(SettingsStore* store, QWidget* parent = nullptr);
protected:
    void closeEvent(QCloseEvent* e) override;
private slots:
    void onStart();
    void onStop();
    void browseExe();
    void onOutputLine(const QString& line);
private:
    void applyPreset(int idx);
    quint8 currentMask() const;
    void loadSettings();
    void saveSettings();

    SettingsStore* store_;
    KellectProcessService proc_;
    LogModel model_;
    QHash<EventFlag, QCheckBox*> flagBoxes_;
    QComboBox* presetCombo_ = nullptr;
    QLineEdit* exeEdit_ = nullptr;
    QLineEdit* filterEdit_ = nullptr;
    QCheckBox* autoScrollBox_ = nullptr;
    QLabel* errLabel_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QListView* view_ = nullptr;
    QTimer* scrollTimer_ = nullptr;
    bool logDirty_ = false;
};
```

- [ ] **Step 2: 写 `MainWindow.cpp`**

```cpp
// src/ui/MainWindow.cpp
#include "MainWindow.h"
#include "LogDelegate.h"
#include "../domain/Preset.h"
#include <QCheckBox>
#include <QComboBox>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QListView>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QTimer>
#include <QCloseEvent>
#include <QFileDialog>

MainWindow::MainWindow(SettingsStore* store, QWidget* parent)
    : QMainWindow(parent), store_(store) {
    setWindowTitle("KellectConsole");
    resize(960, 640);

    auto* central = new QWidget;
    auto* root = new QVBoxLayout(central);

    // —— 工具栏:分组 ——
    auto* bar = new QHBoxLayout;

    // 组1:事件 flags
    auto* flagsBox = new QGroupBox(tr("事件类型"));
    auto* flagsLay = new QHBoxLayout(flagsBox);
    const QVector<QPair<EventFlag, QString>> flagItems = {
        {EventFlag::Process,  tr("进程")},  {EventFlag::Thread,   tr("线程")},
        {EventFlag::Image,    tr("镜像")},  {EventFlag::File,     tr("文件")},
        {EventFlag::Disk,     tr("磁盘")},  {EventFlag::Registry, tr("注册表")},
        {EventFlag::CallStack,tr("调用栈")},{EventFlag::TcpIp,    tr("网络")},
    };
    for (const auto& it : flagItems) {
        auto* cb = new QCheckBox(it.second, flagsBox);
        flagBoxes_.insert(it.first, cb);
        flagsLay->addWidget(cb);
    }
    bar->addWidget(flagsBox);

    // 组2:预设 + 启停
    auto* ctrlBox = new QGroupBox(tr("控制"));
    auto* ctrlLay = new QHBoxLayout(ctrlBox);
    presetCombo_ = new QComboBox;
    for (const auto& p : defaultPresets()) presetCombo_->addItem(p.name);
    auto* startBtn = new QPushButton(tr("启动"));
    auto* stopBtn = new QPushButton(tr("停止"));
    ctrlLay->addWidget(new QLabel(tr("预设:")));
    ctrlLay->addWidget(presetCombo_);
    ctrlLay->addWidget(startBtn);
    ctrlLay->addWidget(stopBtn);
    bar->addWidget(ctrlBox);

    // 组3:过滤 + 自动滚动 + 异常计数
    auto* optBox = new QGroupBox(tr("显示"));
    auto* optLay = new QHBoxLayout(optBox);
    filterEdit_ = new QLineEdit;
    filterEdit_->setPlaceholderText(tr("过滤关键字…"));
    autoScrollBox_ = new QCheckBox(tr("自动滚动"), optBox);
    autoScrollBox_->setChecked(true);
    errLabel_ = new QLabel(QStringLiteral("⚠ 0"));
    optLay->addWidget(new QLabel(tr("过滤:")));
    optLay->addWidget(filterEdit_);
    optLay->addWidget(autoScrollBox_);
    optLay->addWidget(errLabel_);
    bar->addWidget(optBox, 1);

    root->addLayout(bar);

    // —— exe 路径行 ——
    auto* exeLay = new QHBoxLayout;
    exeEdit_ = new QLineEdit;
    exeEdit_->setPlaceholderText(tr("kellect.exe 路径"));
    auto* browseBtn = new QPushButton(tr("浏览…"));
    exeLay->addWidget(new QLabel(tr("kellect.exe:")));
    exeLay->addWidget(exeEdit_, 1);
    exeLay->addWidget(browseBtn);
    root->addLayout(exeLay);

    // —— 日志视图 ——
    view_ = new QListView;
    view_->setModel(&model_);
    view_->setItemDelegate(new LogDelegate(this));
    view_->setUniformItemSizes(true);
    root->addWidget(view_, 1);

    statusLabel_ = new QLabel(tr("就绪"));
    root->addWidget(statusLabel_);

    setCentralWidget(central);

    // —— 信号槽 ——
    connect(presetCombo_, qOverload<int>(&QComboBox::activated), this, &MainWindow::applyPreset);
    connect(startBtn, &QPushButton::clicked, this, &MainWindow::onStart);
    connect(stopBtn, &QPushButton::clicked, this, &MainWindow::onStop);
    connect(browseBtn, &QPushButton::clicked, this, &MainWindow::browseExe);
    connect(&proc_, &KellectProcessService::outputLine, this, &MainWindow::onOutputLine);
    connect(&proc_, &KellectProcessService::stateChanged, this, [this](ProcessState s){
        statusLabel_->setText(s == ProcessState::Running ? tr("运行中") :
                              s == ProcessState::Starting ? tr("启动中…") : tr("就绪"));
    });
    connect(&proc_, &KellectProcessService::startFailed, this, [this](const QString& r){
        statusLabel_->setText(tr("启动失败:%1").arg(r));
    });
    connect(&proc_, &KellectProcessService::decodeErrorCountChanged, this, [this](int n){
        errLabel_->setText(QStringLiteral("⚠ %1").arg(n));
    });

    // —— 自动滚动节流(QTimer 120ms,与 CollectionChanged 解耦)——
    scrollTimer_ = new QTimer(this);
    scrollTimer_->setInterval(120);
    scrollTimer_->start();
    connect(scrollTimer_, &QTimer::timeout, this, [this]{
        if (!logDirty_) return;
        logDirty_ = false;
        if (autoScrollBox_->isChecked() && model_.rowCount() > 0)
            view_->scrollTo(model_.index(model_.rowCount() - 1));
    });

    loadSettings();
}

quint8 MainWindow::currentMask() const {
    QVector<EventFlag> on;
    for (auto it = flagBoxes_.begin(); it != flagBoxes_.end(); ++it)
        if (it.value()->isChecked()) on.append(it.key());
    return buildMask(on);
}

void MainWindow::applyPreset(int idx) {
    const auto presets = defaultPresets();
    if (idx < 0 || idx >= presets.size()) return;
    for (auto cb : flagBoxes_) cb->setChecked(false);
    for (auto f : presets[idx].flags) if (auto* cb = flagBoxes_.value(f)) cb->setChecked(true);
}

void MainWindow::onStart() {
    if (exeEdit_->text().trimmed().isEmpty()) {
        statusLabel_->setText(tr("请先选择 kellect.exe"));
        return;
    }
    proc_.start(exeEdit_->text().trimmed(), buildKellectArgs(currentMask()));
}

void MainWindow::onStop() { proc_.stop(); }

void MainWindow::browseExe() {
    auto path = QFileDialog::getOpenFileName(this, tr("选择 kellect.exe"), {},
                                             tr("可执行文件 (*.exe)"));
    if (!path.isEmpty()) exeEdit_->setText(path);
}

void MainWindow::onOutputLine(const QString& line) {
    LogEntry e{ QDateTime::currentDateTime(), line, 0, false };
    // 解码异常计数由 service 的 decodeErrorCountChanged 信号推进,单行不重算
    model_.append(e);
    model_.trimIfFull();
    logDirty_ = true;
}

void MainWindow::loadSettings() {
    auto s = store_->load();
    exeEdit_->setText(s.kellectExePath);
    autoScrollBox_->setChecked(s.autoScroll);
    filterEdit_->setText(s.filterKeyword);
    for (int b = 0; b < 8; ++b)
        if (auto* cb = flagBoxes_.value(static_cast<EventFlag>(1 << b)))
            cb->setChecked((s.lastMask >> b) & 1);
}

void MainWindow::saveSettings() {
    SettingsStore::Settings s;
    s.kellectExePath = exeEdit_->text();
    s.lastMask = currentMask();
    s.autoScroll = autoScrollBox_->isChecked();
    s.filterKeyword = filterEdit_->text();
    store_->save(s);
}

void MainWindow::closeEvent(QCloseEvent* e) {
    proc_.stop(); // C1:关闭前回收子进程,否则 Windows 不回收提权子进程
    saveSettings();
    QMainWindow::closeEvent(e);
}
```

> **注:** `LogDelegate::paint` 只对 `QListView` 当前可见行调用(QListView 虚拟化),故每行 `extractEvent` 的 JSON 解析成本可控,无需在 `append` 时缓存。

- [ ] **Step 3: 写 `dark.qss` 并在 `main.cpp` 加载**

```css
/* resources/dark.qss */
QMainWindow, QWidget { background: #1E1E1E; color: #D4D4D4; }
QGroupBox { border: 1px solid #3C3C3C; margin-top: 10px; padding-top: 6px; }
QGroupBox::title { color: #9CDCFE; subcontrol-origin: margin; left: 8px; }
QPushButton { background: #2D2D30; border: 1px solid #3C3C3C; padding: 4px 12px; }
QPushButton:hover { background: #3C3C3C; }
QLineEdit, QComboBox { background: #2D2D30; border: 1px solid #3C3C3C; padding: 2px; }
QListView { background: #1E1E1E; border: 1px solid #3C3C3C; }
QLabel#errLabel { color: #E07070; }
```

更新 `main.cpp` 装载 qss + 创建依赖:

```cpp
// src/main.cpp
#include <QApplication>
#include <QFile>
#include <QtPlugin>
#include "ui/MainWindow.h"
#include "domain/SettingsStore.h"
#include <QStandardPaths>

Q_IMPORT_PLUGIN(QWindowsIntegrationPlugin)

int main(int argc, char* argv[]) {
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
    QApplication app(argc, argv);

    QFile qss(":/dark.qss");
    if (qss.open(QIODevice::ReadOnly)) app.setStyleSheet(QString::fromUtf8(qss.readAll()));

    QString settingsPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                           + "/KellectConsole/settings.json";
    SettingsStore store(settingsPath);

    MainWindow w(&store);
    w.show();
    return app.exec();
}
```

并在 `CMakeLists.txt` 顶部加资源:
```cmake
qt5_add_resources(QSS resources/dark.qss)
```
`add_executable` 里加 `${QSS}`;SOURCES 加全部 `src/**/*.cpp`。

- [ ] **Step 4: 构建确认通过**

Run: `cmake --build build --config Release`
Expected: `KellectConsole.exe` 生成。

- [ ] **Step 5: 手动 e2e(管理员)**

以管理员运行 `build/Release/KellectConsole.exe`,指向真实 `kellect.exe` + `config/`,勾选事件 → 启动 → 见日志流(时间戳分层 + 事件着色)→ 停止 → 关闭。验证:解码异常角标计数、书签(双击行)、自动滚动。
Expected:全流程正常,关闭后无 kellect 残留进程(任务管理器核实)。

- [ ] **Step 6: Commit**

```bash
git add gui/QtKellectConsole/
git commit -m "feat(qt-gui): assembled MainWindow with grouped toolbar + throttled autoscroll + closeEvent"
```

---

### Task 11: CrashHandler(三层全局异常)

**Files:**
- Create: `gui/QtKellectConsole/src/CrashHandler.h`
- Create: `gui/QtKellectConsole/src/CrashHandler.cpp`
- Modify: `gui/QtKellectConsole/src/main.cpp`(SEH 外层 + install)
- Modify: `gui/QtKellectConsole/CMakeLists.txt`

**Interfaces:**
- Produces: `namespace CrashHandler { void install(); void write(const char* source, const char* msg); }`。`main()` 用 `__try/__except` 包裹运行循环。

- [ ] **Step 1: 写 `CrashHandler.h`**

```cpp
// src/CrashHandler.h
#pragma once

namespace CrashHandler {
void install();                              // qInstallMessageHandler + std::set_terminate
void write(const char* source, const char* msg); // 追加 crash.log(exe 同目录)
}
```

- [ ] **Step 2: 写 `CrashHandler.cpp`**

```cpp
// src/CrashHandler.cpp
#include "CrashHandler.h"
#include <QCoreApplication>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QMessageLogContext>
#include <QtGlobal>
#include <exception>
#include <cstdlib>

static void messageHandler(QtMsgType type, const QMessageLogContext& ctx, const QString& msg) {
    const char* tag = "qInfo";
    switch (type) {
        case QtDebugMsg:    tag = "qDebug"; break;
        case QtInfoMsg:     tag = "qInfo";  break;
        case QtWarningMsg:  tag = "qWarning"; break;
        case QtCriticalMsg: tag = "qCritical"; break;
        case QtFatalMsg:    tag = "qFatal"; break;
    }
    CrashHandler::write(tag, msg.toUtf8().constData());
    if (type == QtFatalMsg) std::abort();
    (void)ctx;
}

static void terminateHandler() {
    try { if (auto ep = std::current_exception()) std::rethrow_exception(ep); }
    catch (const std::exception& e) { CrashHandler::write("std::terminate", e.what()); }
    catch (...) { CrashHandler::write("std::terminate", "unknown exception"); }
    std::abort();
}

namespace CrashHandler {
void write(const char* source, const char* msg) {
    QString path = QCoreApplication::applicationDirPath() + "/crash.log";
    QFile f(path);
    if (!f.open(QIODevice::Append | QIODevice::Text)) return;
    QTextStream s(&f);
    s << QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss.zzz")
      << " [" << source << "] " << msg << "\n";
    s.flush();
}

void install() {
    qInstallMessageHandler(messageHandler);
    std::set_terminate(terminateHandler);
}
}
```

- [ ] **Step 3: 更新 `main.cpp`(install + SEH 外层)**

```cpp
// src/main.cpp
#include <QApplication>
#include <QFile>
#include <QtPlugin>
#include "ui/MainWindow.h"
#include "domain/SettingsStore.h"
#include "CrashHandler.h"
#include <QStandardPaths>
#include <windows.h>

Q_IMPORT_PLUGIN(QWindowsIntegrationPlugin)

static int run(int argc, char* argv[]) {
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
    QApplication app(argc, argv);

    QFile qss(":/dark.qss");
    if (qss.open(QIODevice::ReadOnly)) app.setStyleSheet(QString::fromUtf8(qss.readAll()));

    QString settingsPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                           + "/KellectConsole/settings.json";
    SettingsStore store(settingsPath);

    MainWindow w(&store);
    w.show();
    return app.exec();
}

int main(int argc, char* argv[]) {
    CrashHandler::install();
    __try {
        return run(argc, argv);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        CrashHandler::write("SEH", "unstructured exception (access violation etc.)");
        return 1;
    }
}
```

> **注:** `__try/__except` 与含 C++ 析构的对象不能同函数——故抽出 `run()`,SEH 仅裹 `run()` 调用。

- [ ] **Step 4: 更新 `CMakeLists.txt` SOURCES 加 `src/CrashHandler.cpp`**

- [ ] **Step 5: 构建并验证 crash.log 可写**

Run: `cmake --build build --config Release`
临时在 `run()` 起首插 `CrashHandler::write("boot","test");` 运行一次,确认 exe 同目录生成 `crash.log` 含该行;随后删除测试行。

- [ ] **Step 6: Commit**

```bash
git add gui/QtKellectConsole/src/CrashHandler.h gui/QtKellectConsole/src/CrashHandler.cpp gui/QtKellectConsole/src/main.cpp gui/QtKellectConsole/CMakeLists.txt
git commit -m "feat(qt-gui): three-layer global crash handler (Qt/terminate/SEH) -> crash.log"
```

---

### Task 12: 静态打包验证 + 清单核对

**Files:**
- 无新源码;验证 build/windeployqt/manifest/单 exe。
- Create: `gui/QtKellectConsole/README.md`(打包说明)。

**Interfaces:**
- 验证 spec §6.5 交付形态:单 exe + kellect.exe + config/。

- [ ] **Step 1: 验证静态链接(无 Qt DLL 依赖)**

Run:
```
cmake --build build --config Release
windeployqt --no-translations --no-system-d3d-compiler build/Release/KellectConsole.exe
```
Expected:`build/Release/` 下仅 `KellectConsole.exe`(静态 Qt 本应零额外 Qt DLL;若 windeployqt 拷了 `Qt5Core/Gui/Widgets*.dll`,说明 Qt 未静态编——回 Prerequisites 检查 `configure -static`)。

- [ ] **Step 2: 用 Dependency Walker / dumpbin 核依赖**

Run: `dumpbin /dependents build\Release\KellectConsole.exe`
Expected:依赖仅系统 DLL(`KERNEL32.dll`、`USER32.dll`、`GDI32.dll`、`ole32.dll` 等),无 `VCRUNTIME140.dll`(`/MT` 已静态)、无 `Qt5*.dll`。

- [ ] **Step 3: 核对 manifest 四项**

Run: `mt.exe -inputresource:build\Release\KellectConsole.exe -out:m.txt`
检查 `m.txt` 含:`requireAdministrator`、`dpiAware>True/PM</dpiAware`、四个 `supportedOS Id`、`Common-Controls`。

- [ ] **Step 4: 组装交付文件夹**

```
KellectConsole-win-x64/
├─ KellectConsole.exe   (从 build/Release/ 拷)
├─ kellect.exe          (复用现有)
└─ config/              (复用现有)
```

- [ ] **Step 5: 三平台手测**

- Win10/11 物理机:管理员运行,完整 e2e(启停 + 日志 + DPI 缩放拨 150%/200% 无错位)。
- Win7 SP1(VM 或实机):同上,确认能启动(零运行时依赖)。
- 全部:关闭后任务管理器无残留 kellect 进程。

- [ ] **Step 6: 写 `README.md`(打包说明)**

简述:静态 Qt 路径、构建命令、windeployqt、交付文件夹布局、三平台验证清单。

- [ ] **Step 7: Commit**

```bash
git add gui/QtKellectConsole/README.md
git commit -m "docs(qt-gui): static packaging + platform verification guide"
```

---

## 自审(对照 spec)

**1. Spec coverage:**
- §1 背景目标 → Goal/Architecture/Global Constraints ✓
- §2 核心决策表 → Global Constraints + Prerequisites ✓
- §3 架构 + 模块映射 → File Structure + Task 1/6/10 ✓
- §4 Utf8Accumulator → Task 4 ✓
- §5.1 分组工具栏 → Task 10 ✓
- §5.2 QListView+delegate 四项着色 → Task 7(model)+ 8(color)+ 9(delegate)+ 10(view)✓
- §5.3 QTimer 节流 → Task 10 ✓
- §5.4 DPI → Task 1(manifest)+ main(HighDpi)✓
- §6.1 自编 Qt → Prerequisites ✓
- §6.2 CMake → Task 1 ✓
- §6.3 manifest 四项 → Task 1 ✓
- §6.4 windeployqt → Task 12 ✓
- §6.5 交付形态 → Task 12 ✓
- §7 测试(QtTest 移植 WPF 20 + delegate 着色)→ Task 2–8 各有 tst_*,delegate 着色逻辑由 Task 8 覆盖 ✓
- §8 错误处理 7 类 → Task 6(1/2/3)+ 4(4)+ 10 closeEvent(5)+ 7(6)+ 11(7)✓
- §9 两阶段 → 阶段①=Task 1–12 全功能;阶段②美化(工具栏精修/着色)已内嵌于 Task 8/9/10,最终打包形态 Task 12 ✓
- §10 许可约束 → Global Constraints ✓

**2. Placeholder scan:** 已逐任务检查,无 TBD/TODO/"add error handling"。Task 10 Step 2 注记里显式标注删除 `applySettings();` 占位行(代码体已不含),非残留。

**3. Type consistency:**
- `EventFlag`(Task 2)在 Task 3/7/10 用法一致 ✓
- `buildMask/buildKellectArgs/maskToHex`(Task 2)签名跨任务一致 ✓
- `Utf8Accumulator::feed/takeLine/errorCount`(Task 4)在 Task 6 `KellectProcessService` 用法一致 ✓
- `LogModel` roles 与 `LogDelegate`/`MainWindow` 取用一致(TextRole/TimeRole/DecodeErrorsRole/MarkedRole)✓
- `EventDomain/domainOfEvent/textColor/markBackground`(Task 8)在 Task 9 用法一致 ✓
- `KellectProcessService::start(exe,args)/stop/state/信号` 在 Task 10 接线一致 ✓
- `SettingsStore::Settings` 字段在 Task 10 load/save 一致 ✓

无类型漂移。

---

## Execution Handoff

Plan 完成并保存至 `docs/superpowers/plans/2026-07-12-kellect-gui-qt.md`。
