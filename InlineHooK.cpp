///////////////////////////////////////////////////////////////////////////////
///
/// Copyright (c) 2017 - <company name here>
///
/// Original filename: InlineHook.cpp
/// Project          : InlineHook
/// Date of creation : 2017-01-29
/// Author(s)        : <author name(s)>
///
/// Purpose          : <description>
///
/// Revisions:
///  0000 [2017-01-29] Initial revision.
///
///////////////////////////////////////////////////////////////////////////////

// $Id$

#ifdef __cplusplus
extern "C" {
#endif
#include <ntddk.h>
#include <string.h>
#ifdef __cplusplus
}; // extern "C"
#endif

#include "InlineHook.h"

#ifdef __cplusplus
namespace { // anonymous namespace to limit the scope of this global variable!
#endif
PDRIVER_OBJECT pdoGlobalDrvObj = 0;
#ifdef __cplusplus
}; // anonymous namespace
#endif

/****************************************************************************************************************************************/

typedef unsigned char BYTE;
KIRQL Irql;
HANDLE PID;  //保存进程的pid
BYTE  OriginalBytes[5]={0}; //保存原始函数前五个字节

#pragma pack(1)	//SSDT表的结构
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //Used only in checked build
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

//导入KeServiceDescriptorTable表
extern"C" __declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;	

//定义宏
#define SYSTEMSERVICE(_function)  KeServiceDescriptorTable.ServiceTableBase[*(PULONG)((PUCHAR)_function+1)]

typedef NTSTATUS (__stdcall *NTOPENPROCESS)( OUT PHANDLE ProcessHandle, 
											IN ACCESS_MASK DesiredAccess, 
											IN POBJECT_ATTRIBUTES ObjectAttributes,
											IN PCLIENT_ID ClientId 
											);

NTOPENPROCESS  RealNtOpenProcess; 

/****************************************************************************************************************************************/
//函数
NTSTATUS __declspec(naked)(__stdcall MyNtOpenProcess)(PHANDLE ProcessHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PCLIENT_ID ClientId) 
{

	__asm
	{
		
		push eax
		mov eax,[esp+0x14]  ////获取ClientId
		mov eax,[eax]
		mov PID,eax        
		pop eax
	}

	if(PID==(HANDLE)2040)  //要保护进程的pid
	{
		__asm
		{
			mov [esp+4],0  /返回空句柄
			mov eax,0xC0000022L  /返回值STATUS_ACCESS_DENIED 无法发现进程
			retn 0x10   //执行保护后的返回
		}
	}
	else
	{
		_asm{
			__emit 90  //占坑，运行时填充
			__emit 90
			__emit 90
			__emit 90
			__emit 90

			mov edx,RealNtOpenProcess
			add edx,5
			jmp edx

		}

	}

}


//Hook²¿·Ö
VOID Hook()
{  
	ULONG jmpaddr;
	__asm  //去掉内存保护
	{
		cli
		mov    eax,cr0
		and    eax,not 10000h
		mov    cr0,eax
	}

	Irql=KeRaiseIrqlToDpcLevel();
	RtlCopyMemory((BYTE *)OriginalBytes,RealNtOpenProcess,5);  //保存原始函数的5个字节
	RtlCopyMemory((BYTE *)MyNtOpenProcess+0x28,RealNtOpenProcess,5);  //填充MyNtOpenProcess占坑的地方，方便跳会原函数
	KeLowerIrql(Irql);

	jmpaddr=(ULONG)MyNtOpenProcess-(ULONG)RealNtOpenProcess-5;  //计算要跳转的相对地址
	__asm
	{
		mov ebx,RealNtOpenProcess
		mov eax,jmpaddr
		mov byte ptr ds:[ebx],0xE9  //在原始函数头加jmp 
		mov DWORD ptr ds:[ebx+1],eax  //在原始函数jmp后加跳转的相对地址 
	}
	__asm  //恢复内存保护  
	{
		mov    eax,cr0
		or     eax,10000h
		mov    cr0,eax
		sti
	}
}
/****************************************************************************************************************************************/

NTSTATUS INLINEHOOK_DispatchCreateClose(
    IN PDEVICE_OBJECT		DeviceObject,
    IN PIRP					Irp
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS INLINEHOOK_DispatchDeviceControl(
    IN PDEVICE_OBJECT		DeviceObject,
    IN PIRP					Irp
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    switch(irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_INLINEHOOK_OPERATION:
        // status = SomeHandlerFunction(irpSp);
        break;
    default:
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        break;
    }

    status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID INLINEHOOK_DriverUnload(
    IN PDRIVER_OBJECT		DriverObject
    )
{
	__asm      //去掉内存保护
	{
		cli
		mov    eax,cr0
		and    eax,not 10000h
		mov    cr0,eax
	}

	//提升IRQL到Dpc
	Irql=KeRaiseIrqlToDpcLevel();
	RtlCopyMemory(RealNtOpenProcess,(BYTE *)OriginalBytes,5);
	KeLowerIrql(Irql);

	__asm   //恢复内存保护 
	{
		mov    eax,cr0
		or     eax,10000h
		mov    cr0,eax
		sti
	}

    PDEVICE_OBJECT pdoNextDeviceObj = pdoGlobalDrvObj->DeviceObject;
    IoDeleteSymbolicLink(&usSymlinkName);

    // Delete all the device objects
    while(pdoNextDeviceObj)
    {
        PDEVICE_OBJECT pdoThisDeviceObj = pdoNextDeviceObj;
        pdoNextDeviceObj = pdoThisDeviceObj->NextDevice;
        IoDeleteDevice(pdoThisDeviceObj);
    }
}

#ifdef __cplusplus
extern "C" {
#endif
NTSTATUS DriverEntry(
    IN OUT PDRIVER_OBJECT   DriverObject,
    IN PUNICODE_STRING      RegistryPath
    )
{
    PDEVICE_OBJECT pdoDeviceObj = 0;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    pdoGlobalDrvObj = DriverObject;

    // Create the device object.
    if(!NT_SUCCESS(status = IoCreateDevice(
        DriverObject,
        0,
        &usDeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &pdoDeviceObj
        )))
    {
        // Bail out (implicitly forces the driver to unload).
        return status;
    };

    // Now create the respective symbolic link object
    if(!NT_SUCCESS(status = IoCreateSymbolicLink(
        &usSymlinkName,
        &usDeviceName
        )))
    {
        IoDeleteDevice(pdoDeviceObj);
        return status;
    }

    // NOTE: You need not provide your own implementation for any major function that
    //       you do not want to handle. I have seen code using DDKWizard that left the
    //       *empty* dispatch routines intact. This is not necessary at all!
    DriverObject->MajorFunction[IRP_MJ_CREATE] =
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = INLINEHOOK_DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = INLINEHOOK_DispatchDeviceControl;
    DriverObject->DriverUnload = INLINEHOOK_DriverUnload;

    //SYSTEMSERVICE通过Zw*的第二个字节，也就是SSDT索引号得到保存在SSDT中Nt*函数的地址
	RealNtOpenProcess=(NTOPENPROCESS)(SYSTEMSERVICE(ZwOpenProcess)); 
	Hook();  //开始hook

    return STATUS_SUCCESS;
}
#ifdef __cplusplus
}; // extern "C"
#endif
