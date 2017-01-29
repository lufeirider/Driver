///////////////////////////////////////////////////////////////////////////////
///
/// Copyright (c) 2017 - <company name here>
///
/// Original filename: SSTDHook.cpp
/// Project          : SSTDHook
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

#include "SSTDHook.h"

#ifdef __cplusplus
namespace { // anonymous namespace to limit the scope of this global variable!
#endif
PDRIVER_OBJECT pdoGlobalDrvObj = 0;
#ifdef __cplusplus
}; // anonymous namespace
#endif


/********************************************************************************************/

typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //Used only in checked build
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;


extern"C" __declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;        //变量名是不能变的,因为是从外部导入


//这个是查询某个函数的地址的一个宏
#define SYSTEMSERVICE(_function)  KeServiceDescriptorTable.ServiceTableBase[*(PULONG)((PUCHAR)_function+1)]

NTSYSAPI NTSTATUS NTAPI ZwOpenProcess(
                                    OUT PHANDLE ProcessHandle,
                                    IN ACCESS_MASK DesiredAccess,
                                    IN POBJECT_ATTRIBUTES ObjectAttributes,
                                    IN PCLIENT_ID ClientId OPTIONAL
                                    );

typedef NTSTATUS (*ZWOPENPROCESS)(
                                OUT PHANDLE ProcessHandle,
                                IN ACCESS_MASK DesiredAccess,
                                IN POBJECT_ATTRIBUTES ObjectAttributes,
                                IN PCLIENT_ID ClientId OPTIONAL
                                );

ZWOPENPROCESS OldZwOpenProcess;

long pid = 2704;


/********************************************************************************************/
//函数申明
NTSTATUS NewZwOpenProcess(  
                        OUT PHANDLE ProcessHandle,
                        IN ACCESS_MASK DesiredAccess,
                        IN POBJECT_ATTRIBUTES ObjectAttributes,
                        IN PCLIENT_ID ClientId OPTIONAL
                        )
{
	//用来替换的新函数
	NTSTATUS nStatus = STATUS_SUCCESS;
	if((long)ClientId->UniqueProcess == pid)
	{
		DbgPrint("保护进程 PID:%ld\n",pid);
		return STATUS_ACCESS_DENIED;
	}

	//剩下的交给我们的原函数
	nStatus = OldZwOpenProcess(ProcessHandle,DesiredAccess,ObjectAttributes,ClientId);
	return STATUS_SUCCESS;
}
/********************************************************************************************/


NTSTATUS SSTDHOOK_DispatchCreateClose(
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

NTSTATUS SSTDHOOK_DispatchDeviceControl(
    IN PDEVICE_OBJECT		DeviceObject,
    IN PIRP					Irp
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    switch(irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_SSTDHOOK_OPERATION:
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

VOID SSTDHOOK_DriverUnload(
    IN PDRIVER_OBJECT		DriverObject
    )
{
/*********************************************************************************************************************/
	//恢复原来的OpenProcess地址，不然会蓝屏
    SYSTEMSERVICE(ZwOpenProcess) = (unsigned int)OldZwOpenProcess;
/*********************************************************************************************************************/

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
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = SSTDHOOK_DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SSTDHOOK_DispatchDeviceControl;
    DriverObject->DriverUnload = SSTDHOOK_DriverUnload;

/*********************************************************************************************************************/
	//修改 ZwOpenProcess 函数地址
	//将原来ssdt中所要hook的函数地址换成我们自己的函数地址
    //(SYSTEMSERVICE(ZwOpenProcess))获取到的是7A （122） OpenProcess 的编号
	
	OldZwOpenProcess =(ZWOPENPROCESS)(SYSTEMSERVICE(ZwOpenProcess));
	SYSTEMSERVICE(ZwOpenProcess) = (unsigned int)NewZwOpenProcess;
/*********************************************************************************************************************/

    return STATUS_SUCCESS;
}
#ifdef __cplusplus
}; // extern "C"
#endif
