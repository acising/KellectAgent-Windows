# **KELLECT**:a **K**ernel-based Efficient and **L**oss**l**ess Event Log Coll**ec**tor

简体中文 | [English](./README.md)

![](http://121.40.168.60/kellect/kellect.jpeg)

## KELLECT简介

KELLECT（a **K**ernel-based efficient and **L**oss**l**ess event log coll**ec**tor）是一款用于内核级事件日志处理的系统框架 ，包括采集、清洗、融合、存储和分析阶段，KELLCT根据功能的不同，我们分为KellectAgent和KellectService。

## KellectAgent-Windows简介
KellectAgent-Windows（以下简称kellectAgent）作为首发版本，是一款基于ETW(Event Tracing for Windows)的多线程Windows内核日志采集器，基于C++语言开发，性能高效，系统开销低。 KellectAgent-Windows可以跟踪Windows系统的内核级事件信息，如FileIO、Process、Thread、ImageLoad、Registry等。

该程序集成了事件收集、事件分析、事件语义校正、事件输出等功能。输出格式遵循JSON规范，有以下4种输出方式：

1. 输出至控制台显示；
2. 输出至指定文件路径；
3. 输出至指定Socket通信端；
4. 输出至指定Kafka服务器。

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
| librdkafka                  | v1.6           | https://github.com/edenhill/librdkafka        |

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
| release       | 发布版本 |

## **KELLECT使用说明**

### **通过命令行调用**

经过测试，KellectAgent可以在**Windows7（客户端版本）、Windows Server2008（服务器版本）及以上版本**运行。

> **注意:** Windows11版本目前暂不支持，将在后续版本支持。

采集功能必须以**管理员**身份运行。如下所示，可通过配置参数的形式进行功能的选择。

![image-20230407102213003](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20230407102213003.png)

例如，可以通过以下命令全量采集系统日志并输出至文件"test.json"：

```
kellect.exe -e all -f test.json
```

**注意:** 参数"-e" 请指定16进制格式参数值。

### **配置文件的用法**

#### filter.txt

​	用户可以通过配置filter.txt实现不同功能。通常KellectAgent运行不需要进行修改，除非有定制化的需求。

```json
filteredProcessID
0 4 128

filteredEventIdentifier
3740466758 32
1030727888 1
1030727888 2
1030727889 1
1030727889 2
1030727889 36
749821213 10
749821213 2
...

filteredImageFile
C:\Windows\SysWOW64\ntdll.dll
```

**配置文件不同标签详情：**

1. *[filteredProcessID]*

   表示根据此标签中的 ID 列表过滤具体事件。 进程 ID 由空格分隔。

2. *[filteredEventIdentifier]*

   表示通过Event ProviderID和opcode的组合过滤事件，我们称之为EventIdentifier。 具体的事件日志详情可以在[微软文档](https://docs.microsoft.com/en-us/windows/win32/etw/fileio)中获取. ProviderID 是 Guid 类第一部分的十进制形式，opcode 是每个 BaseEvent Class Page 的 Remarks 下的 EventType 值。

   > 注意：该标签下的事件标识符为白名单列表，是我们需要采集的事件类型。

   [![image-20220503171251436](https://camo.githubusercontent.com/0d8e30388ebd9df55ce302d1fb37bb5e84f1edd598604e33b8667dbf14203376/687474703a2f2f3132312e34302e3136382e36302f6b656c6c6563742f6576656e74547970652e706e67)](https://camo.githubusercontent.com/0d8e30388ebd9df55ce302d1fb37bb5e84f1edd598604e33b8667dbf14203376/687474703a2f2f3132312e34302e3136382e36302f6b656c6c6563742f6576656e74547970652e706e67)

   [![image-20220503171255065](https://camo.githubusercontent.com/fa83496afb6f388c337e59491df6e122e4f0e896314879201824b9576ded7a75/687474703a2f2f3132312e34302e3136382e36302f6b656c6c6563742f677569642e706e67)](https://camo.githubusercontent.com/fa83496afb6f388c337e59491df6e122e4f0e896314879201824b9576ded7a75/687474703a2f2f3132312e34302e3136382e36302f6b656c6c6563742f677569642e706e67)

3. *[filteredImageFile]*

   可以通过此标签中列出的Image文件路径**过滤** 加载Image 的事件。

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

设置当前主机的UUID。若未指定，则KellectAgent会自动生成UUID并输出到该文件中。

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
	"Host-UUID": "FBFFA15C-FEDE-4f96-9AF8-398294758A2A",
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
	"Host-UUID": "FBFFA15C-FEDE-4f96-9AF8-398294758A2A",
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

## 数据集

我们使用kellectAgent作为采集工具，并基于redcanaryco提出的脚本[Automic Red Team](https://github.com/redcanaryco/atomic-red-team)进行数据采集。该脚本基于[ATT&CK](https://attack.mitre.org/)中的战术，我们采集到的数据共享在[谷歌云盘](https://drive.google.com/drive/folders/1jk6qx6jNGag8a-VHYyQkON6cMgH9djct?usp=sharing)中

## 未来计划

1. 基于ETW的Windows内核日志采集工具（V1.0，已发布）
2. 基于pBPF的Linux内核日志采集工具（V1.1，研发中）
3. 提供Common Data Model数据统一接口