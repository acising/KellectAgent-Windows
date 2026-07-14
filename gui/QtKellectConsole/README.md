# KellectConsole — Qt 5.15 静态打包说明

KellectConsole 是 kellect 进程的轻量 Qt Widgets 控制台 GUI。本工程的核心交付目标是一份**单 exe、零运行时依赖**的可执行文件，可在 Win7 SP1 / Win10 / Win11 直接运行，无需安装任何 VC++ 运行时或 Qt DLL。

## 1. 构建前提

| 项 | 值 |
|---|---|
| Qt | **5.15.2 静态版**，前缀 `D:\Code\Qt\5.15.2-static`（自编 `configure -static -static-runtime` 产物） |
| 编译器 | MSVC v142（`-vcvars_ver=14.29`，VS2022 工具集回退）|
| Windows SDK | `10.0.19041.0`（Win7 SP1 仍可运行的最后一个目标基线）|
| 生成器 | Ninja（单配置，`CMAKE_BUILD_TYPE=Release`）|
| CRT | `/MT`（Release）/ `/MTd`（Debug），由 `CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded` 强制 |

> SDK 19041 + 静态 UCRT 是 Win7 SP1 能跑的关键：静态链入 `ucrt` 后不再依赖系统 `ucrtbase.dll`，而 19041 的静态 UCRT 仍兼容 Win7 SP1 的 KERNEL32 导出表。

## 2. 构建命令

```bat
REM 在 gui\QtKellectConsole 目录下
cmd /c scripts\build.bat          REM 仅构建
cmd /c scripts\build.bat test     REM 构建 + ctest
```

产物：`build\KellectConsole.exe`（约 16 MB，Ninja 单配置，**无 `Release/` 子目录**）。

`build.bat` 内部依次执行：调用 `vcvarsall.bat x64 10.0.19041.0 -vcvars_ver=14.29` → `cmake -B build -G Ninja` → `cmake --build build`。链接期使用 `/MANIFEST:NO`（禁用链接器默认清单），改由 `app.rc` 以 `RT_MANIFEST` 资源形式（`1 24 "app.manifest"`）内嵌我们手写的清单。

## 3. 静态链接验证（权威检查）

构建完成后，在已加载 vcvars 的命令行里执行：

```bat
dumpbin /dependents build\KellectConsole.exe
mt.exe -inputresource:build\KellectConsole.exe -out:manifest.xml
```

> `windeployqt` 对纯静态构建意义不大，且可能误拷 D3D compiler / vcredist 污染 `build/`。**静态链接的权威判据是 `dumpbin /dependents`**，windeployqt 可跳过。

### 本次构建（2026-07-13）的 dumpbin 结果

`KellectConsole.exe` 导入表只含 Windows 系统 DLL：

```
KERNEL32.dll   USER32.dll    GDI32.dll     SHELL32.dll
ole32.dll      OLEAUT32.dll  ADVAPI32.dll  IMM32.dll
USERENV.dll    VERSION.dll   NETAPI32.dll  WS2_32.dll
WINMM.dll      UxTheme.dll   dwmapi.dll    WTSAPI32.dll
```

判定：
- **无** `Qt5Core.dll` / `Qt5Gui.dll` / `Qt5Widgets.dll` → Qt 已静态链入（`.qtmetad` / `.qtmimed` 段即 Qt 元数据 / MIME 内嵌资源）
- **无** `VCRUNTIME140.dll` / `MSVCP140.dll` → `/MT` 静态 CRT 生效
- **无** `ucrtbase.dll` → 静态 UCRT 生效（Win7 SP1 兼容性保障）

以上 16 个系统 DLL 均为 Win7 SP1 起内置，满足零运行时依赖目标。

### 本次构建（2026-07-13）的 manifest 核对

`mt.exe` 从 exe 抽取的内嵌清单四项全部到位：

| 项 | 值 | 用途 |
|---|---|---|
| `requestedExecutionLevel` | `level="requireAdministrator"` | 启动即提权（kellect 需管理员抓取）|
| `dpiAware` | `True/PM` | Per-Monitor DPI v1，150%/200% 缩放不糊不糊位 |
| `supportedOS Id`（×4）| Win7 `{35138b9a-...}` / Win8 `{4a2f28e3-...}` / Win8.1 `{1f676c76-...}` / Win10-11 `{8e0f7a12-...}` | 各版本取现代 API 行为 |
| `dependentAssembly` | `Microsoft.Windows.Common-Controls 6.0` | 启用现代主题控件 |

## 4. 交付文件夹布局

仓库 `release/` 目录已持有 kellect 采集器运行时；GUI 的 `KellectConsole.exe` 单独由 `build/` 产出。最终交付文件夹需**把两者合并**（下列文件由发布人员组装，不入库）：

```
KellectConsole-win-x64/
├─ KellectConsole.exe          <- 从 gui\QtKellectConsole\build\ 取
├─ kellect.exe                 <- 从 release\ 取
├─ kellect.exe.manifest        <- kellect 自身的清单（release\ 取）
├─ config\                     <- kellect 配置（release\ 取）
├─ librdkafka.dll              ┐
├─ librdkafkacpp.dll           │  kellect 依赖的运行时 DLL
├─ libzstd.dll                 │（release\ 取；不是 GUI 的依赖）
└─ zlib.dll                    ┘
```

要点：
- `KellectConsole.exe` 单文件零依赖，可直接双击运行（会触发 UAC 提权）。
- `kellect.exe` 依赖上列 4 个第三方 DLL，缺一不可——GUI 通过 QProcess 启动它，缺失会导致采集失败但 GUI 本体仍可启动。
- GUI 与 kellect 进程分离：关闭 GUI 的 closeEvent 会先停 kellect；异常退出场景需任务管理器确认无残留。

## 5. 多平台运行时验证清单（发布前人工执行）

静态链接验证只能证明符号依赖层面零运行时；真正发布前需在三平台实跑下列检查（由人工在物理机/VM 完成）：

### Win10 / Win11 物理机
- [ ] 双击 `KellectConsole.exe` → UAC 提权 → 主窗口正常显示
- [ ] 完整 e2e：选择 kellect.exe + 配置 → 启动 → 观察日志流 → 停止
- [ ] DPI 缩放：系统设置拨到 150% / 200%，界面无错位、无模糊
- [ ] 关闭主窗口后，任务管理器确认无残留 `kellect.exe` 进程

### Win7 SP1（VM 或实机）
- [ ] 同上四项；重点确认**零运行时依赖**——裸系统直接运行 `KellectConsole.exe` 能启动（不预装任何 VC++ Redist / Qt 运行时）
- [ ] 若启动失败，回到 Prerequisites 检查静态 Qt 的 `configure -static -static-runtime` 是否成功

## 6. 许可

本工程采用 **GPL v3**（静态链入 Qt 的 GPL 兼容方案）。kellect 采集器及其第三方 DLL 的许可以各自产物为准。
