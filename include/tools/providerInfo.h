//
// Created by qxb .
//

#ifndef KELLECT_PROVIDERINFO_H
#define KELLECT_PROVIDERINFO_H

//the following are first part of providerIDs
#include <initguid.h>

#define FileProvider		0x90cbdc39
#define ThreadProvider		0x3d6fa8d1
#define ProcessProvider 	0x3d6fa8d0
#define ImageProvider		0x2cb15d1d
#define RegistryProvider	0xae53722e
#define DiskProvider		0x3d6fa8d4
#define SystemCallProvider	0xce1dbfb4
#define TcpIpProvider		0x9a280ac0
#define CallStackProvider	0xdef2fe46

//the following are Provider GUIDs
DEFINE_GUID(
        DiskIoGuid,
0x3d6fa8d4,
0xfe05,
0x11d0,
0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c
);

DEFINE_GUID(
        FileGuid,
0x90cbdc39,
0x4a3e,
0x11d1,
0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3
);
DEFINE_GUID(
        ImageLoadGuid,
0x2cb15d1d,
0x5fc1,
0x11d2,
0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18
);

DEFINE_GUID(
        PerfInfoGuid,
0xce1dbfb4,
0x137e,
0x4da6,
0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc
);
DEFINE_GUID(
        ProcessGuid,
0x3d6fa8d0,
0xfe05,
0x11d0,
0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c
);
DEFINE_GUID(
        RegistryGuid,
0xae53722e,
0xc863,
0x11d2,
0x86, 0x59, 0x0, 0xc0, 0x4f, 0xa3, 0x21, 0xa1
);
DEFINE_GUID(
        TcpIpGuid,
0x9a280ac0,
0xc8e0,
0x11d1,
0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2
);
DEFINE_GUID(
        ThreadGuid,
0x3d6fa8d1,
0xfe05,
0x11d0,
0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c
);
/*
// Guid definitions from "NT Kernel Logger Constants" section on MSDN.
*/
struct __declspec(uuid("{802ec45a-1e99-4b83-9920-87c98277ba9d}")) DXGKRNL_PROVIDER_GUID_HOLDER;
static const GUID DXGKRNL_PROVIDER_GUID = __uuidof(DXGKRNL_PROVIDER_GUID_HOLDER);

struct __declspec(uuid("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}")) Kernel_Process_GUID_HOLDER;
static const GUID Kernel_Process = __uuidof(Kernel_Process_GUID_HOLDER);

struct __declspec(uuid("{7dd42a49-5329-4832-8dfd-43d979153a88}")) KERNEL_NETWORK_GUID_HOLDER;
static const GUID Kernel_Network = __uuidof(KERNEL_NETWORK_GUID_HOLDER);

struct __declspec(uuid("{edd08927-9cc4-4e65-b970-c2560fb5c289}")) KERNEL_FILE_GUID_HOLDER;
static const GUID Kernel_File = __uuidof(KERNEL_FILE_GUID_HOLDER);



#endif //KELLECT_PROVIDERINFO_H
