简体中文 | [English](./README.md)
# kellect 简介

kellect是一个基于ETW（Event Tracing for Windows）和C++语言开发高性能多线程内核日志收集器。kellect可以追踪Windows系统的内核级信息，如文件、进程/线程、Image加载、注册表等信息。

kellect集成了事件收集、事件分析、事件语义修正、事件输出的全功能。采集事件可以以JSON事件输出到指定文件路径或通过socket传输到另外一台主机。

用户可以直接通过PowerShell.exe或cmd.exe使用改工具，并根据需要进行命令参数的设定，无需修改源代码。我们还提供了一些配置文件，用户可以根据需求进行定制。

有关采集器的详细信息，请参阅[Demo Paper](./demoPaper.pdf) .

有关kellect的进一步发展，请参阅[未来规划](#roadmap)。



# **实现细节**

kellect使用一些第三方依赖库，如下所示，请查阅LICENSE-3RD-PARTY获取更多信息。


| 模块名称                        | 版本      | License链接                                     |
|-----------------------------|---------|-----------------------------------------------|
| easyloggingpp               | v9.96.7 | https://github.com/amraynonweb/easyloggingpp  |
| moodycamel::ConcurrentQueue | /       | https://github.com/cameron314/concurrentqueue |

kellect的开发主要依赖于Clion开发工具，但是编译主要依赖于MSVC编译器。开发用到的软件和版本如下表所示：

| 工具名称          | 版本  |
|---------------|-----|
| Visual Studio |   16.11.13|
| MSVC          |  19.29.30143.0  |
| Windows SDK   |  10.0.20348.0  |
| Clion         |   2022.1  |

# **kellect 说明**

## **通过命令行调用**

经过测试，kellect可以在Windows7(x64)系统以上版本运行。

采集器必须以**管理员**方法运行。如下所示，可通过配置参数的形式进行功能的选择。

![image-20220503171012480](images/command.png)

我们可以通过以下命令进行数据采集：


   ```
   kellect.exe -e 1 -f test.json
   ```

**注意:** 参数 -e 请以十进制进行输入。


## **配置文件的用法**

用户可以配置filter.txt进行功能实现。通常采集器运行不需要进行修改，除非有定制化的需求。

- filter.txt的功能是去过滤不需要的日志数据。配置中可以进行三种不同类型的配置：进程ID、事件类别、Image文件路径的黑白名单。默认配置如下所示：

```c++
filteredProcessID
0 4 128

filteredEventIdentifier
2429279289 76
2429279289 69
2429279289 74
2429279289 75
2429279289 84
2429279289 82
2429279289 80
2429279289 81
2429279289 79
2429279289 83
2429279289 86
3208270021 11
3208270021 17
3208270021 27
3208270021 26
3208270021 10
1030727888 11

blacklistOfImageFiles

whitelistOfImageFiles
```

**配置文件不同标签详情：**

1. *[filteredProcessID]*

   表示根据此标签中的 ID 列表过滤事件。 进程 ID 由空格分隔。

2. *[filteredEventIdentifier]*

   表示通过Event ProviderID和opcode的组合过滤事件，我们称之为EventIdentifier。 具体的事件日志详情可以在[微软文档](https://docs.microsoft.com/en-us/windows/win32/etw/fileio)中获取. ProviderID 是 Guid 类第一部分的十进制形式，opcode 是每个 Event Class Page 的 Remarks 下的 EventType 值。

   ![image-20220503171251436](images/eventType.png)

   ![image-20220503171255065](images/guid.png)

3. *[blacklistOfImageFiles]*

   可以通过此标签中列出的Image**过滤** Image 和 CallStack 类型的事件。

4. *[whitelistOfImageFiles]*

   可以通过此标签中列出的Image来**保留**Image和 CallStack 类型的事件。

# **输出格式**

我们以 JSON 格式输出事件记录。 每个 Event 都有两部分属性：公共属性和私有属性。 各部分说明如下：

- 公共属性

| 属性          | 描述                                      |
|-------------|-----------------------------------------|
| threadID    | 产生事件的线程ID                               |
| processID   | 产生事件的进程ID                               |
| processName | 产生事件的进程名称                               |
| timestamp   | 事件发生的时间 |

- 私有属性

  此类型属性因事件类型而异。 例如：

  1. file_create 事件

  | 属性              | 描述                                                            |
      |---------------------------------------------------------------|--------|
     | IrpPtr         | IO请求包                                                         |
     | TTID           | 正在创建文件的线程的线程标识符                                               |
     | FileObject     | 可用于在文件创建和关闭事件之间将操作与同一打开的文件对象实例相关联的标识符                         |
     | CreateOptions  | 在 CreateOptions 和 CreateDispositions 参数中传递给 NtCreateFile 函数的值 |
     | FileAttributes | 在 FileAttributes 参数中传递给 NtCreateFile 函数的值                     |
     | ShareAccess    | 在 ShareAccess 参数中传递给 NtCreateFile 函数的值                        |
     | OpenPath       | 文件路径                                                          |

  1. FileIo_Name 事件

     |   属性          | 描述                                                                                                                                                            | 
     |---------------------------------------------------------------------------------------------------------------------------------------------------------------|--------|
     | FileObject | 将此指针的值与 [**DiskIo_TypeGroup1**](https://docs.microsoft.com/en-us/windows/win32/etw/diskio-typegroup1) 事件中的 **FileObject** 指针值匹配以确定 I/O 操作的类型 |
     | FileName   | 文件的完整路径，不包括驱动器号                                                                                                         |

3. CallStack 事件 . 我们收集的API是Windows自己提供的，不收集用户自定义dll文件中的任何API。

   | 属性             | 描述                                                                                                              |
        |-----------------------------------------------------------------------------------------------------------------|--------|
   | callStackInfo | 进程操作的调用栈.<br />  (每个调用的格式如下所示 : **ModulePath:APIName**, 如: C:\Windows\System32\ntdll.dll:LdrSystemDllInitBlock) |

4. ...... 我们可以在[微软的文档](https://docs.microsoft.com/en-us/windows/win32/etw/msnt-systemtrace)中找到其他的时间属性描述 

需要注意的是，我们已经**修改或填充了**大部分事件的属性，所以Windows提供的原生事件和我们的会有一些差异。

输出情况如下：
```
{"EventName":FileIOCreate,"ProcessID":11144,"ProcessName":clion64.exe,"ThreadID":15692,"TimeStamp":132959694278638867,"arguments":{"CreateOptions":50331744,"FileAttributes":128,"FileObject":251724112,"IrpPtr":116229640,"OpenPath":"C:\Users\Administrator\AppData\Local\JetBrains\CLion2022.1\caches\contentHashes.dat.keystream.len","ShareAccess":7,"TTID":15692}}

{"EventName":CallStack,"ProcessID":11144,"ProcessName":clion64.exe,"ThreadID":15692,"TimeStamp":132959694278638867,"arguments":{"stackInfo":"C:\Windows\System32\ntdll.dll:LdrSystemDllInitBlock,C:\Windows\System32\ntdll.dll:LdrSystemDllInitBlock,C:\Windows\System32\ntdll.dll:LdrSystemDllInitBlock,C:\Windows\System32\ntdll.dll:LdrSystemDllInitBlock,C:\Windows\System32\ntdll.dll:LdrSystemDllInitBlock,C:\Windows\System32\ntdll.dll:LdrSystemDllInitBlock,C:\Windows\System32\ntdll.dll:LdrSystemDllInitBlock,C:\Windows\System32\ntdll.dll:LdrSystemDllInitBlock,C:\Windows\System32\ntdll.dll:LdrSystemDllInitBlock,C:\Windows\System32\ntdll.dll:LdrSystemDllInitBlock,C:\Windows\System32\ntdll.dll:LdrSystemDllInitBlock,C:\Windows\System32\ntdll.dll:LdrSystemDllInitBlock,C:\Windows\System32\ntdll.dll:LdrSystemDllInitBlock,C:\Windows\System32\ntdll.dll:RtlCaptureStackContext"}}
```

# 未来工作

## **路线**

1. 










