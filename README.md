# **KELLECT  :a **K**ernel-based Efficient and **L**oss**l**ess Event Log Coll**ector

[简体中文](./README.zh-CN.md) | English 

![](http://121.40.168.60/kellect/kellect.jpeg)


## KELLECT Introduction

**KELLECT **(a **K**ernel-based efficient and **L**oss**l**ess event log coll**ec**tor) is a framework for kernel-level event log processing, including the stages of acquisition, cleaning, fusion, storage and analysis, KELLECT is divided into KellectAgent and KellectService according to different functions.

### KellectAgent-Windows Introduction

KellectAgent-Windows (hereinafter referred to as kellectAgent), as the first version, is a multi-threaded Windows kernel log collector based on ETW (Event Tracing for Windows), developed based on C++ language, with high performance and low system overhead. KellectAgent can track the kernel-level event information of the Windows system, such as FileIO, Process, Thread, ImageLoad, Registry, etc.

The program integrates functions such as event collection, event analysis, event semantic correction, and event output. The output format follows the JSON specification, and there are the following four output methods:

- Output to console display;
- Output to the specified file path;
- Output to the designated Socket communication terminal;
- Output to the specified Kafka server.

Users can use this tool directly through "PowerShell.exe" or "cmd.exe", and set command parameters as needed. We also provide some configuration files, which users can customize according to their needs.

For more information on the future of KELLECT , see the [Future Work]() section.

## **Implementation Details**

KellectAgent uses a number of 3rd party libraries, as shown below. Please see LICENSE-3RD-PARTY for further details.

| Module Name                 | Module Version | LicenseUrl                                    |
| --------------------------- | -------------- | --------------------------------------------- |
| easyloggingpp               | v9.96.7        | https://github.com/amraynonweb/easyloggingpp  |
| moodycamel::ConcurrentQueue | /              | https://github.com/cameron314/concurrentqueue |
| nlohmann::json              | v3.10.4        | https://github.com/nlohmann/json              |
| TinyXML-2                   | v2             | https://github.com/leethomason/tinyxml2       |
| librdkafka                  | v1.6           | https://github.com/edenhill/librdkafka        |

The development of KellectAgent mainly depends on the Clion development tool, and the compilation mainly depends on the MSVC compiler. The software and versions used for development are shown in the table below:

| Tool Name     | Version  |
|---------------|-----|
| Visual Studio |   16.11.13|
| MSVC          |  19.29.30143.0  |
| Windows SDK   |  10.0.20348.0  |
| Clion         |   2022.1  |

The directory of kellect is shown as below:

| name of directory | meaning                  |
|-------------------|--------------------------|
| include           | header files             |
| lib               | the  3rd party libraries |
| source            | source files             |
| source/config     | config files             |
| release           | executable file   |

## **KellectAgent Manual**

### **Usage of the command-line**

After testing, KellectAgent can run on **Windows7 (client version), Windows Server2008 (server version) and above versions**.

> **Note:** The Windows 11 version is currently not supported, and will be supported in subsequent versions.

The KellectAgent must be run as **Administrator**. As shown below, the function can be selected in the form of configuration parameters.

![image-20230407102213003](images/command.png)

For example, the following command can be used to collect all system logs and output them to the file "test.json":


   ```
   kellect.exe -e all -f test.json
   ```

**Note:** For the parameter "-e", please specify the value in hexadecimal format.

### **Usage of the configuration file**

#### filter.txt

Users can implement different functions by configuring filter.txt. Usually KellectAgent does not need to be modified to run, unless there are customized requirements.

- The role of filter.txt is to filter events you don't need. There are three types of labels used for filtering, which are the process ID, event identifier, blacklist of image file path and whitelist of image file path. The default configuration is as follows:

```c++
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

**Label descriptions:**

1. *[filteredProcessID]*

    Indicates to filter events based on the list of PIDs separated by spaces.

2. *[filteredEventIdentifier]*

    Indicates tracing events through the combination of Event ProviderID and opcode, which we call EventIdentifier. The specific event log details can be obtained in [Microsoft Documentation](https://docs.microsoft.com/en-us/windows/win32/etw/fileio). ProviderID is the decimal form of the first part of the Guid class, and opcode is the EventType value under Remarks of BaseEvent Class Page.
    
    > **Note:** The event identifiers under this label are whitelisted and are the types of events we need to collect.

![image-20220503171251436](images/eventType.png)

![image-20220503171255065](images/guid.png)

​	3.*[filteredImageFile]*

​		ImageLoad events and corresponding CallStacks will be **filtered** by the Image file path listed in this label.

#### initImages.txt

This file stores some system DLL files, and we will pre-read these files when KellectAgent is running to speed up the efficiency of subsequent event parsing. Users can add the path of the DLL file that needs to be preloaded to the file.

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

> **NOTE:** Some DLL files cannot be resolved.

#### log.conf

Configure the log output format and path information.

#### uuid

Set the UUID of the current host. If not specified, KellectAgent will automatically generate a UUID and output it to the file.

## **Output Format**

We output event records in the format of JSON. Each BaseEvent has two parts of properties: common properties and private properties. The description of each part as follows:

- Common properties

  | 属性      | 描述                                                         |
  | --------- | ------------------------------------------------------------ |
  | Event     | corresponding event name                                     |
  | TID       | ID of the thread that generated the event                    |
  | PID       | ID of the process that generated the event                   |
  | PName     | name of the process that generated the event                 |
  | PPID      | parent ID of the process that generated the event            |
  | PPName    | parent name of the process that generated the event          |
  | TimeStamp | time of the event occured                                    |
  | Host-UUID | the host ID that generated the event, <br />distinguish the specific log source in the joint analysis of multi-host logs |
  | Args      | private property pairs for specific event types              |

- Private properties

  This type properties is various depends on the BaseEvent types. For example: 

1. file_create event

   | Property       | Description                                                  |
   | -------------- | ------------------------------------------------------------ |
   | IrpPtr         | IO request packet                                            |
   | TTID           | Thread identifier of the thread that is  creating the file.  |
   | FileObject     | Identifier that can be used for  correlating operations to the same opened file object instance between file  create and close events. |
   | CreateOptions  | Values passed in the CreateOptions and  CreateDispositions parameters to the NtCreateFile function. |
   | FileAttributes | Value passed in the FileAttributes  parameter to the NtCreateFile function. |
   | ShareAccess    | Value passed in the ShareAccess  parameter to the NtCreateFile function. |
   | OpenPath       | Path to the file.                                            |

2. FileIo_Name event

   | Property   | Description                                                  |
   | ---------- | ------------------------------------------------------------ |
   | FileObject | Match the value of this pointer to the **FileObject** pointer value in a [**DiskIo_TypeGroup1**](https://docs.microsoft.com/en-us/windows/win32/etw/diskio-typegroup1) event to determine the type of I/O operation. |
   | FileName   | Full path to the file, not including the drive letter.       |

 3. CallStack event . The APIs we collected is provided by OS-defined(part of) and user-defined dll files.

    | Property  | Property                                                     |
    | --------- | ------------------------------------------------------------ |
    | stackInfo | the callstacks of the process operation.<br />  (the format of each call is like : **ModulePath:APIName**, e.g: C:\Windows\System32\ntdll.dll:LdrSystemDllInitBlock) |

 4. ...... for other event attribute descriptions, please refer to [Microsoft Documentation](https://docs.microsoft.com/en-us/windows/win32/etw/msnt-systemtrace).

It should be noted that we have **modified or populated** the properties of most events, so there will be some differences between the native events provided by Windows and ours. 

The output case are as follows:

```json
#FileIO Create BaseEvent
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

#Callstack event
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
## Dateset
We use KellectAgent as the collection tool and based on the script [Automic Red Team](https://github.com/redcanaryco/atomic-red-team) proposed by redcanaryco for data collection. The script is based on the tactics in [ATT&CK](https://attack.mitre.org/), and the data we collected is shared in [Google Cloud Disk](https://drive.google.com/drive/folders/1jk6qx6jNGag8a -VHYyQkON6cMgH9djct?usp=sharing)

## Future Work

1. <s>ETW-based Windows kernel events log collector（V1.0，released）</s>
2. eBPF-based Linux kernel events log collector（V1.1，developing）
3. Common Data Model interface.















