///////////////////////////////////////////////////////////////////////////////
///
/// Copyright (c) 2017 - <company name here>
///
/// Original filename: Notify.cpp
/// Project          : Notify
/// Date of creation : 2017-01-25
/// Author(s)        : <author name(s)>
///
/// Purpose          : <description>
///
/// Revisions:
///  0000 [2017-01-25] Initial revision.
///
///////////////////////////////////////////////////////////////////////////////

// $Id$

#ifdef __cplusplus
extern "C" {
#endif
#include <ntddk.h>
#include <string.h>
#include <stdio.h>
#ifdef __cplusplus
}; // extern "C"
#endif

#include "Notify.h"
#include <wdm.h>

#ifdef __cplusplus
namespace { // anonymous namespace to limit the scope of this global variable!
#endif
PDRIVER_OBJECT pdoGlobalDrvObj = 0;
#ifdef __cplusplus
}; // anonymous namespace
#endif

/**********************************************************************************************************************************/
PVOID isWait = NULL;
PVOID inputBuffer;
char outString[255] = "test";
char* processString;
/**********************************************************************************************************************************/
char* GetProcessName(ULONG dwPid)  
{  
    HANDLE ProcessHandle;  
    NTSTATUS status;  
    OBJECT_ATTRIBUTES  ObjectAttributes;  
    CLIENT_ID myCid;  
    PEPROCESS EProcess;  
  
    InitializeObjectAttributes(&ObjectAttributes,0,0,0,0);   
  
    myCid.UniqueProcess = (HANDLE)dwPid;  
    myCid.UniqueThread = 0;  
  
    //打开进程，获取句柄  
    status = ZwOpenProcess (&ProcessHandle,PROCESS_ALL_ACCESS,&ObjectAttributes,&myCid);  
    if (!NT_SUCCESS(status))  
    {  
        DbgPrint("打开进程出错/n");  
        return 0;  
    }  
      
    //得到EPROCESS，结构中取进程名  
    status = ObReferenceObjectByHandle(ProcessHandle,FILE_READ_DATA,0,KernelMode,(PVOID *)&EProcess, 0);  
    if (status == STATUS_SUCCESS)  
    {  
        char *ProcessName = (char*)EProcess + 0x174;  
        //char *PsName = PsGetProcessImageFileName(EProcess);  
  
        DbgPrint("ProcessName is %s/n",ProcessName);  
        //DbgPrint("PsName is %s/n",PsName);  
  
        ZwClose(ProcessHandle);
		return ProcessName;
    }  
    else  
    {  
        DbgPrint("Get ProcessName error");  
    } 
	return 0;
}  

/**********************************************************************************************************************************/

VOID ProcessMonitorCallback(
						IN HANDLE hParentId,
						IN HANDLE hProcessId, 
						IN BOOLEAN bCreate)
{
	if(bCreate)
	{
		processString = GetProcessName((ULONG)hProcessId);
		sprintf(outString,"ParentId :%d process name: %s process ID: %d has beed started\n",hParentId, processString, hProcessId);
	}
	else
	{
		processString = GetProcessName((ULONG)hProcessId);
		sprintf(outString,"ParentId :%d process name: %s process ID: %d has beed killed\n",hParentId, processString, hProcessId);
	}
	
	if(isWait != NULL)
	{
		KeSetEvent((PRKEVENT)isWait, 0, FALSE);
	}
}
/**********************************************************************************************************************************/

NTSTATUS NOTIFY_DispatchCreateClose(
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

NTSTATUS NOTIFY_DispatchDeviceControl(
    IN PDEVICE_OBJECT		DeviceObject,
    IN PIRP					Irp
    )
{
	DbgPrint("NOTIFY_DispatchDeviceControl");
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    switch(irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_NOTIFY_OPERATION:
		{
			DbgPrint("IOCTL_NOTIFY_OPERATION");
			RtlCopyMemory(Irp->UserBuffer, outString, sizeof(outString));
			
			DbgPrint("outString = %s",outString);
			break;
		}
	case IOCTL_NOTIFY_FLAG:
		{
			DbgPrint("IOCTL_NOTIFY_FLAG");
			

			inputBuffer = Irp->AssociatedIrp.SystemBuffer;
			DbgPrint("inputBuffer:%08x\n", (HANDLE)inputBuffer);
			status = ObReferenceObjectByHandle(*(HANDLE *)inputBuffer,
					GENERIC_ALL,
					NULL,
					KernelMode,
					&isWait,
					NULL);
			if(isWait!=NULL)
			{
				KeSetEvent((PRKEVENT)isWait, 0, FALSE);
			}

			
			break;
		}
    default:
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        break;
    }

    status = Irp->IoStatus.Status;
	Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID NOTIFY_DriverUnload(
    IN PDRIVER_OBJECT		DriverObject
    )
{
	PsSetCreateProcessNotifyRoutine(ProcessMonitorCallback,TRUE);
	if(isWait!=NULL)
	{
		ZwClose(isWait);
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

	PsSetCreateProcessNotifyRoutine(ProcessMonitorCallback,FALSE);
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
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = NOTIFY_DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NOTIFY_DispatchDeviceControl;
    DriverObject->DriverUnload = NOTIFY_DriverUnload;

    return STATUS_SUCCESS;
}
#ifdef __cplusplus
}; // extern "C"
#endif
