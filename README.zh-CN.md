# **KELLECT**:a **K**ernel-based Efficient and **L**oss**l**ess Event Log Coll**ec**tor

简体中文 | [English](./README.md)

[项目架构与交接报告](./PROJECT_REPORT.md)

![](http://121.40.168.60/kellect/kellect.jpeg)

## KELLECT简介

KELLECT（a **K**ernel-based efficient and **L**oss**l**ess event log coll**ec**tor）是一款用于内核级事件日志处理的系统框架 ，包括采集、清洗、融合、存储和分析阶段，KELLCT根据功能的不同，我们分为KellectAgent和KellectService。

## KellectAgent-Windows简介
KellectAgent-Windows（以下简称kellectAgent）作为首发版本，是一款基于ETW(Event Tracing for Windows)的多线程Windows内核日志采集器，基于C++语言开发，性能高效，系统开销低。 KellectAgent-Windows可以跟踪Windows系统的内核级事件信息，如FileIO、Process、Thread、ImageLoad、Registry等。也可以跟踪用户侧的事件信息，如Microsoft_Windows_DNS_Client。

该程序集成了事件收集、事件分析、事件语义校正、事件输出等功能。输出格式遵循JSON规范，支持以下主输出方式：

1. 输出至控制台显示；
2. 输出至指定文件路径；
3. 输出至指定Socket通信端；

用户可直接通过"PowerShell.exe"或"cmd.exe"使用该工具，并根据需要进行命令参数的设定。我们还提供了一些配置文件，用户可以根据需求进行定制。

有关KELLECT的进一步发展，请参阅[未来规划](https://github.com/acising/kellect/blob/v1.0/README.zh-CN.md#roadmap)。

## **实现细节**

KellectAgent使用一些第三方依赖库，如下所示，请查阅LICENSE-3RD-PARTY获取更多信息。

| Module Name                 | Module Version | LicenseUrl                                    |
| --------------------------- | -------------- | --------------------------------------------- |
| easyloggingpp               | v9.96.7        | https://github.com/amraynonweb/easyloggingpp  |
| moodycamel::ConcurrentQueue | /              | https://github.com/cameron314/concurrentqueue |
| nlohmann::json              | v3.10.4        | https://github.com/nlohmann/json              |
| TinyXML-2                   | v2             | https://github.com/leethomason/tinyxml2       |

KellectAgent的开发主要依赖于Clion开发工具，编译主要依赖于MSVC编译器。开发使用的软件和版本如下表所示：

| 工具名称      | 版本          |
| ------------- | ------------- |
| Visual Studio | 16.11.13      |
| MSVC          | 19.29.30143.0 |
| Windows SDK   | 10.0.20348.0  |
| Clion         | 2022.1        |

KELLECT项目的结构如下表所示：

| 目录名称      | 说明     |
| ------------- | -------- |
| include       | 头文件   |
| lib           | 第三方库 |
| source        | 源文件   |
| source/config | 配置文件 |
| bin           | 本机构建产物 |

## **KELLECT使用说明**

### **通过命令行调用**

采集功能必须以**管理员**身份运行。默认使用 `behavior` 模式：进程/线程/文件/注册表/TCP-IP/UDP-IP；Image 默认关闭；CallStack 默认关闭（实测开启后内核栈回溯会造成大量 `etw_lost`），需要时加 `--callstack`；不采集 CSwitch、DPC、ISR、Syscall、DiskIO Init 等性能诊断事件。

```bat
:: 默认只统计，不写文件
kellect.exe

:: 需要落盘时显式指定文件
kellect.exe -f events.jsonl

:: -e all = 全部行为事件（Process/Thread/File/Registry/TCP-IP/UDP-IP），不含 Image/CallStack
kellect.exe -e all -f events.jsonl

:: 高级诊断：额外开启 DiskIO/CSwitch/Memory/ALPC 等
kellect.exe --profile diagnostic -f diagnostic.jsonl

:: 本地文件 + SecArgus MQTT
kellect.exe -f events.jsonl --mqtt

:: 屏幕逐条查看（高吞吐时会影响性能）
kellect.exe -c
```

CallStack 默认关闭；`--callstack` 是隐藏的高级开关（只对 Process/Thread/Image 生命周期抓栈）。`--profile diagnostic` 才会恢复全量栈与性能事件。
停止时输出 `[stats]`，其中 `etw_lost` 是内核真正丢事件数，`schema_unknown`/`decode_failed`/`filtered_third`/`disk_side` 是解析层分类，不再混为一个 `drop_parse`。

### **行为链的完整性、顺序和零丢失**

- behavior 第一阶段就启用 Process/Thread/File/Registry/TCPIP；只有 Image 会被延后，避免出现文件/注册表观测缺口。
- Registry KCB RUNDOWN 仍会解析，用来建立旧注册表键名映射；它不输出为行为事件。
- **默认序列化线程固定为 1**，保证 JSONL 行序与 ETW 事件顺序一致；`--serialize-threads >1` 是显式的吞吐换顺序选项。
- 自适应只调整 ETW `MaximumBuffers`，不再自动增加序列化线程。
- Image 默认关闭：`ImageDCStart` 属于启动模块枚举，不是新的行为事件；需要模块证据时用 `--enable-image`，DCStart 仍会被丢弃。

### **MQTT 远程命令**

启用 `--mqtt` 后，agent 订阅：

```text
secargus/v1/endpoints/<endpoint_id>/commands
```

支持的命令：

| 命令 | 行为 |
|---|---|
| `get_status` / `get_metrics` / `get_capabilities` / `get_collection_config` | 只读查询 |
| `update_collection_config` | 写入 `config/remote/desired.json` 和 filter；`"restart": true` 时回复后自动停止，由 supervisor/service 重启生效 |
| `stop_collection` | 回复后优雅停止采集 |
| `restart_collection` | 回复后停止，由 supervisor/service 重启 |
| `start_collection` | 进程在运行时返回 already_running |

发送工具（纯标准库，无需 paho）：

```bat
python tools\mqtt_command.py --name get_status
python tools\mqtt_command.py --name stop_collection
python tools\mqtt_command.py --name update_collection_config ^
  --args "{\"event_mask\":175,\"restart\":true}"
```

默认从 `dist/config/endpoint.json` 读取 endpoint_id，Broker 默认 `192.168.1.93:1883`。
`stop_collection` / `restart_collection` 只接受非 retained 命令，并经过 endpoint/时间戳/command_id 幂等校验。

### **图形界面（双击运行）**

`dist\KellectGui.exe` 是免 Qt 依赖的 WinForms 控制台，双击会自动请求管理员权限：

- 可视化配置 Profile/事件掩码/Thread/CallStack、输出、证据、Schema、Probe、Socket、用户 Provider；
- 开始 / 停止采集，选择输出 JSONL；
- 实时显示 Received / Parsed / Queued / ETW lost；
- 实时显示 Parse Q / Serialize Q / Output Q（缓冲池积压）与进度条；
- MQTT 开关、Broker/端口，显示 connected / sent / acked / spool / dropped；
- 下方滚动显示事件尾部。

构建：`scripts\build-gui.ps1`（`build-single.ps1` 会自动调用并输出到 `dist`）。

### **采集模式**

| 模式 | 事件 | CallStack | 用途 |
|---|---|---|---|
| `behavior`（默认） | Process/Thread(Start/End)/FileIO/Registry/TCP-IP/UDP-IP | 默认关闭；`--callstack` 只给 Process/Thread 生命周期抓栈，且 behavior 只输出 模块+RVA（不查导出/PDB） | 行为还原主线 |
| `diagnostic` | behavior + DiskIO/CSwitch/Memory/ALPC/PageFault/Syscall 等 | 全部支持的事件（高开销，可能丢事件） | 仅诊断/实验 |

`-e all` 现在等价于行为模式（`0xaf`），不包含 CallStack；`-e <hex>` 仍按传统位掩码解析。

### **丢失与统计**

停止时 `[stats]` 一次输出：

- `etw_lost` / `etw_buffers_lost`：**ETW 内核侧真正丢失**（权威）；
- `disk_side`：FileIO 名称映射依赖 DISK_IO 带出的 DiskIo 事件，已从默认输出剔除；
- `schema_unknown`：没有 XML 布局的事件，已保留并输出 `Unknown_<provider>_<opcode>`；
- `decode_failed` / `filtered_third`：解析失败 / 第三方过滤丢弃；
- `decode_queue_dropped`：传统解码队列满（仅证据模式下丢，普通模式施加背压）；
- `parse_q` / `serialize_q` / `output_q`：停止时三级队列积压，用来判断是不是消费端跟不上；
- `parsed` / `queued`：成功进入 JSON 输出的事件。

另外日志会按 Provider/Opcode/Version/原因聚合 `[decode-failure]` 行，便于定位未知 Schema。

### **配置文件的用法**

#### filter.txt

运行时过滤配置，启动时由 `initFilter()` 读取。三个配置节，使用人类可读的条目：

```text
# config/filter.txt
filteredProcessID
0
4
128

droppedEventName

filteredImageFile
C:\Windows\SysWOW64\ntdll.dll
```

**配置节说明：**

1. *[filteredProcessID]*

   PID 黑名单（每行一个）。内置条目 {0, 4, 128} 始终存在；此文件中的额外 PID 为增量添加。

2. *[droppedEventName]*

   事件名黑名单（来自 `eventStruct_win10.xml`），在最早的过滤阶段丢弃，不进入解析管线。用于治理高量低值噪声（如 `FileIODirNotify`）。CLI 的 `-x` 参数效果相同，运行时追加到该列表。

3. *[filteredImageFile]*

   通过 Image 文件路径**过滤**加载 Image 的事件及对应的 CallStack。

#### initImages.txt

该文件存储的为一些系统DLL文件，我们在KellectAgent运行时会对这些文件进行预读取，以加快后续事件解析效率。用户可以添加需要预加载的DLL文件路径到文件中。

```json
C:\Windows\System32\win32u.dll
C:\Windows\SysWOW64\win32u.dll
C:\Windows\System32\msvcp_win.dll
C:\Windows\SysWOW64\msvcp_win.dll
C:\Windows\System32\KernelBase.dll
C:\Windows\SysWOW64\KernelBase.dll
C:\Windows\SysWOW64\FWPUCLNT.DLL
C:\Windows\System32\wininet.dll
C:\Windows\System32\StateRepository.Core.dll
C:\Windows\System32\rilproxy.dll
C:\Windows\System32\fwpolicyiomgr.dll
C:\Windows\System32\dbghelp.dll
...
```

注意：有些DLL文件无法解析。

#### log.conf

配置日志输出格式与路径信息。

#### uuid

当前主机的唯一标识。首次运行时通过 `CoCreateGuid` 生成并持久化到 `config/uuid`；后续运行复用同一值。每台机器各自生成不同的 UUID。

## **输出格式**

我们以 JSON 格式输出事件记录。 每个 BaseEvent 都有两部分属性：公共属性和私有属性。 各部分说明如下：

- 公共属性

| 属性      | 描述                                                         |
| --------- | ------------------------------------------------------------ |
| Event     | 对应的事件名称                                               |
| TID       | 产生事件的线程ID                                             |
| PID       | 产生事件的进程ID                                             |
| PName     | 产生事件的进程名称                                           |
| PPID      | 产生事件父进程ID                                             |
| PPName    | 产生事件的父进程名                                           |
| TimeStamp | 事件发生的时间                                               |
| Host-UUID | 产生事件的主机标识，<br />用于在多主机日志联合分析时区别具体日志来源 |
| Args      | 具体事件类型的私有属性对                                     |

- 私有属性

  此类型属性因事件类型而异。 例如：

1. FileIOFileCreate事件

   | 属性           | 描述                                                         |
   | -------------- | ------------------------------------------------------------ |
   | IrpPtr         | I/O请求包                                                    |
   | TTID           | 正在创建文件的线程标识符                                     |
   | FileObject     | 可用于在文件创建和关闭事件之间将操作与同一打开的文件对象实例相关联的标识符 |
   | CreateOptions  | 在 CreateOptions 和 CreateDispositions 参数中传递给 NtCreateFile 函数的值 |
   | FileAttributes | 在 FileAttributes 参数中传递给 NtCreateFile 函数的值         |
   | ShareAccess    | 在 ShareAccess 参数中传递给 NtCreateFile 函数的值            |
   | OpenPath       | 文件路径                                                     |

2. FileIOName 事件

   | 属性       | 描述                                                         |
   | ---------- | ------------------------------------------------------------ |
   | FileObject | 将此指针的值与 [**DiskIo_TypeGroup1**](https://docs.microsoft.com/en-us/windows/win32/etw/diskio-typegroup1) 事件中的 **FileObject** 指针值匹配以确定 I/O 操作的类型 |
   | FileName   | 文件的完整路径，不包括驱动器号                               |

3. CallStack 事件（目前对CallStack的解析**不完全支持**）

   | 属性      | 描述                                                         |
   | --------- | ------------------------------------------------------------ |
   | stackInfo | 进程操作的调用栈. (每个调用的格式如下所示 : **ModulePath:APIName**, 如: C:\Windows\System32\ntdll.dll:LdrSystemDllInitBlock) |

4. ...... 其他事件属性描述可参考[微软的文档](https://docs.microsoft.com/en-us/windows/win32/etw/msnt-systemtrace)。

需要注意的是，我们已经**修改或填充了**大部分事件的属性，所以Windows提供的原生事件和我们的会有一些差异。

```json
#FileIO的create 事件
{
	"Event": "FileIOCreate",
	"PID": 956,
	"PName": "QQPCTray.exe",
	"PPID": 2832,
	"PPName": "QQPCRTP.exe",
	"TID": 9516,
	"TimeStamp": 133253085392394264,
	"Host-UUID": "XXXXXXXX-XXXX-4XXX-XXXX-XXXXXXXXXXXX",
	"Args": {
		"CreateOptions": 18890752,
		"FileAttributes": 0,
		"FileObject": 2590015792,
		"IrpPtr": 2812860872,
		"OpenPath": "C:\Program Files\WindowsApps\Microsoft.LanguageExperiencePackzh-CN_19041.57.180.0_neutral__8wekyb3d8bbwe\Windows\System32\DriverStore\zh-CN\uaspstor.inf_loc",
		"ShareAccess": 7,
		"TTID": 9516
	}
}

#callstack事件
{
	"Event": "CallStack",
	"PID": 21576,
	"PName": "GoogleUpdate.exe",
	"PPID": 1808,
	"PPName": "svchost.exe",
	"TID": 44940,
	"TimeStamp": 133253092340669753,
	"Host-UUID": "XXXXXXXX-XXXX-4XXX-XXXX-XXXXXXXXXXXX",
	"Args": {
		"stackInfo": "C:\Program Files (x86)\Google\Update\1.3.36.152\goopdate.dll:DllEntry,
        C:\Program Files (x86)\Google\Update\1.3.36.152\goopdate.dll:DllEntry,
        C:\Windows\SysWOW64\sechost.dll:RegisterTraceGuidsA,
        C:\Windows\SysWOW64\sechost.dll:RegisterTraceGuidsA,
        C:\Program Files (x86)\Google\Update\1.3.36.152\goopdate.dll:DllEntry,
        C:\Program Files (x86)\Google\Update\1.3.36.152\goopdate.dll:DllEntry,
        C:\Program Files (x86)\Google\Update\1.3.36.152\goopdate.dll:DllEntry,
        C:\Program Files (x86)\Google\Update\1.3.36.152\goopdate.dll:DllEntry,
        C:\Windows\System32\ntdll.dll:RtlCaptureStackContext,
        C:\Windows\System32\ntdll.dll:RtlpCleanupRegistryKeys,
        C:\Windows\System32\ntdll.dll:RtlValidProcessProtection,
        C:\Windows\System32\ntdll.dll:_CIcos,
        C:\Windows\System32\ntdll.dll:cos,
        C:\Windows\SysWOW64\ntdll.dll:NtQueryAttributesFile,
        C:\Windows\SysWOW64\ntdll.dll:RtlMultiByteToUnicodeN,
        C:\Windows\SysWOW64\ntdll.dll:RtlMultiByteToUnicodeN,
        ...
	}
}
```

## **WDM（windows common data model）输出格式**
   目前WDM格式转化只对，注册表（Registry），进程（Process），线程（Thread），文件（File），网络（Tcp）进行格式转化。
   其中每个事件都会产出边，每个边的格式为：
   ```json
   
   {
        "data": {
             "Event": {
                "uuid": ,
                "Type": "", 
                "subject": "",
                "object": "",
                "object2": "",
                "CommandLine": "",
                "TimeStamp": 
            },
            "args": ,
            "weights": 1
        },
        "WDMVersion": "1.0",
        "source": ""
   }
  ```
   而对于每个点来说，不同事件的产出会有些不一样。

   例如
   ```json
   #进程事件
 {
            "data": {
                "Subject": {
                    "uuid": ,
                    "Type": 
                    "PID" ,
                    "PName": ,
                    "NodeType": ,
                    "ParentSubject": ,   
                    "TimeStamp": 
                },
                "args": ,
                "weights": 1
            },
            "WDMVersion": "1.0",
            "source": ""
        }

#文件事件
{
            "data": {
                "Object": {
                    "uuid": ,
                    "Type": ,
                    "Path": ,
                    "NodeType": ,
                    "TimeStamp": 
                },
                "args": ,
                "weights": 1
            },
            "WDMVersion": "1.0",
            "source": ""
        }

   ```


## 数据集

我们使用kellectAgent作为采集工具，并基于redcanaryco提出的脚本[Automic Red Team](https://github.com/redcanaryco/atomic-red-team)进行数据采集。该脚本基于[ATT&CK](https://attack.mitre.org/)中的战术，我们采集到的数据共享在[Kellect网站](http://www.kellect.org)中

## 构建与服务

运行 `cmd /c scripts\build-collector.bat` 生成 `bin\kellect.exe`、
`bin\KellectService.exe` 和 `bin\config\`。也可以用
`scripts\build-single.ps1` 生成 `dist\` 运行目录。从产物目录启动采集器，
使相对路径 `config\` 指向随附配置。实时 ETW 需要管理员权限。

| 入口 | 配置 | 输出 |
| --- | --- | --- |
| `kellect.exe` | 命令行及 `config\` | 控制台、文件、Socket、探针通道 |
| `KellectConsole.exe` | GUI | 实时视图，可转发至文件或 Socket |
| `KellectService.exe` | `config\agent.ini` | 文件、探针通道、Socket |

```powershell
scripts\install-service.bat
scripts\service-status.bat
net stop KellectAgent
scripts\uninstall-service.bat
```

`--probe` 使用 WebSocket 和 MessagePack 向 Kellect 后端上报事件。服务使用
`output=probe`，凭据由 `config\probe.ini` 提供。[探针协议说明](docs/PROBE-CHANNEL.zh-CN.md)

`--mqtt` 是 SecArgus 的附加输出，使用 `config\secargus.ini`。未收到业务 ACK 的
批次保存在本地 spool。[SecArgus 构建和验证](docs/SECARGUS-BUILD-TEST.zh-CN.md)

## VNext 原始证据

```powershell
.\kellect.exe --profile provenance --evidence-dir D:\KellectEvidence
.\kellect.exe --profile full_kernel --evidence-dir D:\KellectEvidence --kernel-etl
.\kellect.exe --replay-etl D:\KellectEvidence\<run-id>\kernel.etl --evidence-dir D:\KellectReplay
```

`config\profiles.ini` 提供 `lightweight`、`provenance`、`full_kernel` 和
`full_research`。仅传 `--evidence-dir` 时使用 `full_kernel`。每次运行有独立目录，
其中 `raw.jsonl` 保存 ETW 原始记录，`stacks.jsonl` 保存栈和关联，
`coverage.jsonl` 保存观测目录及丢失账本。可另用 `-f` 输出传统 JSON 并附带
回溯原始记录的引用。[验证步骤与已知范围](docs/baseline.md)

`enrichment.jsonl` 记录进程与映像生命周期，以及栈帧到映像和 RVA 的映射。
采集结束后可用 `--symbolize` 读取本地匹配的 PE/PDB，并写出独立的符号文件。
传统栈预热支持 `--prewarm-mode` 和 `--init-images`。[离线解析与预热用法](docs/baseline.md)

## KellectConsole(图形控制台)

`gui/QtKellectConsole` 提供一个可选的 Qt 图形控制台来驱动 `kellect.exe`。它基于
**官方动态 Qt 5.15 LTS**(msvc2019_64)+ MSVC `/MD` 构建;约 200 KB 的 exe 随包携带
Qt DLL、平台插件和 VC++/UCRT 运行时(app-local),在 **Windows 7 SP1 / 10 / 11** 上
免前置依赖直接运行。须以**管理员**身份运行(manifest 申请提权——ETW 必需)。

启动 `KellectConsole.exe` 后:

1. **设置** → `kellect.exe` 启动时自动探测(先 GUI 同目录,再上一级安装根目录),
   需要时在设置中改指。
2. 勾选需要的**内核事件类别**(或选一个预设)。
3. 选择控制台、文件或 Socket。GUI 显示实时事件，并按设置转发到目标。
4. **启动**。JSON 事件流按事件类型着色、双击出详情对话框。

> GUI 始终以 `-c` 启动 `kellect.exe`,且**不暴露** `-u`。需追踪用户态提供者请直跑
> 二进制(见下)。

构建:

```
cmd /c gui\QtKellectConsole\scripts\build.bat test
```
(官方动态 Qt 5.15.2 msvc2019_64,位于 `%QTDIR%`——默认
`D:\Code\Qt\5.15.2\msvc2019_64`,可环境变量覆盖;MSVC v142 / 14.29、Windows SDK
10.0.19041.0。Qt 一次性获取:
`pip install aqtinstall` 后执行
`python -m aqt install-qt windows desktop 5.15.2 win64_msvc2019_64 -O D:\Code\Qt --archives qtbase`。
构建脚本会把 Qt DLL 和 `platforms\qwindows.dll` 拷到 exe 旁。)

## MSI 安装包

**MSI**——一条流水线构建采集器 + GUI + 安装包:

```
cmd /c scripts\build-all.bat
```
→ `installer\build-msi\Kellect-win-x64.msi`(支持自定义安装目录;GUI 随其 Qt/CRT
运行时装进 `gui\` 子目录,采集器装在根目录)。

> 无人值守采集使用由 SCM 托管的 `KellectService.exe`。服务与命令行共用采集引擎。

### 用户态提供者(`-u`)

`kellect.exe` 可通过 `-u` 额外追踪**一个**用户态 ETW 提供者(单选枚举,非位掩码):

| 值 | 提供者 |
|----|--------|
| `0x01` | 线程池(Thread Pool)|
| `0x02` | DNS Client |
| `0x03` | 打印服务(Print Service)|

```
kellect.exe -e all -u 0x02 -f dns.json   :: DNS 解析到文件(须管理员)
```

## 未来计划

1. 基于ETW的Windows内核日志采集工具（V1.0，已发布）
2. 基于eBPF的Linux内核日志采集工具（V1.1，研发中）
3. 提供Common Data Model数据统一接口
