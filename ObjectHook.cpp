///////////////////////////////////////////////////////////////////////////////
///
/// Copyright (c) 2017 - <company name here>
///
/// Original filename: ObjectHook.cpp
/// Project          : ObjectHook
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

#include "ObjectHook.h"

#ifdef __cplusplus
namespace { // anonymous namespace to limit the scope of this global variable!
#endif
PDRIVER_OBJECT pdoGlobalDrvObj = 0;
#ifdef __cplusplus
}; // anonymous namespace
#endif

/********************************************************************************/
#define OBJECT_TO_OBJECT_HEADER(o)CONTAINING_RECORD((o),OBJECT_HEADER,Body)


typedef struct _OBJECT_TYPE_INITIALIZER {
  USHORT Length;
  BOOLEAN UseDefaultObject;
  BOOLEAN CaseInsensitive;
  ULONG InvalidAttributes;
  GENERIC_MAPPING GenericMapping;
  ULONG ValidAccessMask;
  BOOLEAN SecurityRequired;
  BOOLEAN MaintainHandleCount;
  BOOLEAN MaintainTypeList;
  POOL_TYPE PoolType;
  ULONG DefaultPagedPoolCharge;
  ULONG DefaultNonPagedPoolCharge;
  PVOID DumpProcedure;
  PVOID OpenProcedure;
  PVOID CloseProcedure;
  PVOID DeleteProcedure;
  PVOID ParseProcedure;
  PVOID SecurityProcedure;
  PVOID QueryNameProcedure;
  PVOID OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;


typedef struct _OBJECT_TYPE { 
  ERESOURCE Mutex; 
  LIST_ENTRY TypeList; 
  UNICODE_STRING Name; 
  PVOID DefaultObject; 
  ULONG Index; 
  ULONG TotalNumberOfObjects; 
  ULONG TotalNumberOfHandles; 
  ULONG HighWaterNumberOfObjects; 
  ULONG HighWaterNumberOfHandles; 
  OBJECT_TYPE_INITIALIZER TypeInfo; 
#ifdef POOL_TAGGING 
  ULONG Key; 
#endif 
} OBJECT_TYPE, *POBJECT_TYPE;

typedef struct _OBJECT_CREATE_INFORMATION { 
  ULONG Attributes; 
  HANDLE RootDirectory; 
  PVOID ParseContext; 
  KPROCESSOR_MODE ProbeMode; 
  ULONG PagedPoolCharge; 
  ULONG NonPagedPoolCharge; 
  ULONG SecurityDescriptorCharge; 
  PSECURITY_DESCRIPTOR SecurityDescriptor; 
  PSECURITY_QUALITY_OF_SERVICE SecurityQos; 
  SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService; 
} OBJECT_CREATE_INFORMATION, *POBJECT_CREATE_INFORMATION;



typedef struct _OBJECT_HEADER { 
  LONG PointerCount; 
  union { 
    LONG HandleCount; 
    PSINGLE_LIST_ENTRY SEntry; 
  }; 
  POBJECT_TYPE Type; 
  UCHAR NameInfoOffset; 
  UCHAR HandleInfoOffset; 
  UCHAR QuotaInfoOffset; 
  UCHAR Flags; 
  union 
  { 
    POBJECT_CREATE_INFORMATION ObjectCreateInfo; 
    PVOID QuotaBlockCharged; 
  };
  
  PSECURITY_DESCRIPTOR SecurityDescriptor; 
  QUAD Body; 
} OBJECT_HEADER, *POBJECT_HEADER;
POBJECT_TYPE pType= NULL;
POBJECT_HEADER addrs=NULL;
PVOID OldParseProcedure = NULL;


NTSTATUS NewParseProcedure(IN PVOID ParseObject,
             IN PVOID ObjectType,
             IN OUT PACCESS_STATE AccessState,
             IN KPROCESSOR_MODE AccessMode,
             IN ULONG Attributes,
             IN OUT PUNICODE_STRING ObjectName,
             IN OUT PUNICODE_STRING RemainingName,
             IN OUT PVOID Context OPTIONAL,
             IN PSECURITY_QUALITY_OF_SERVICE SecurityQos OPTIONAL,
             OUT PVOID *Object) 
{
	NTSTATUS Status;
	

	__asm
	{
		push eax
		push Object
		push SecurityQos
		push Context
		push RemainingName
		push ObjectName
		push Attributes
		movzx eax, AccessMode
		push eax
		push AccessState
		push ObjectType
		push ParseObject
		call OldParseProcedure
		mov Status, eax
		pop eax
	}

	return Status;

}
NTSTATUS Hook()
{
  NTSTATUS  Status;
  HANDLE hFile;
  UNICODE_STRING Name;
  OBJECT_ATTRIBUTES Attr;
  IO_STATUS_BLOCK ioStaBlock;
  PVOID pObject = NULL;
  
  
  RtlInitUnicodeString(&Name,L"\\Device\\HarddiskVolume1\\1.txt");

  InitializeObjectAttributes(&Attr,&Name,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE ,0,NULL);

  Status = ZwOpenFile(&hFile,GENERIC_ALL,&Attr,&ioStaBlock,0,FILE_NON_DIRECTORY_FILE);
  if (!NT_SUCCESS(Status))
  {
    DbgPrint(("File is Null\n"));
    return Status;
  }
 

  Status = ObReferenceObjectByHandle(hFile,GENERIC_ALL,NULL,KernelMode,&pObject,NULL);

  if (!NT_SUCCESS(Status))
  {
    DbgPrint(("Object is Null\n"));
    return Status;
  }
 
 DbgPrint("pobject is %08X\n",pObject);

 addrs=OBJECT_TO_OBJECT_HEADER(pObject);//获取对象头


pType=addrs->Type;//获取对象类型结构 object-10h

DbgPrint("pType is %08X\n",pType);
OldParseProcedure = pType->TypeInfo.ParseProcedure;//获取服务函数原始地址OBJECT_TYPE+9C位置为打开
DbgPrint("OldParseProcedure addrs is %08X\n",OldParseProcedure);
DbgPrint("addrs is %08X\n",addrs);
//这里最好检查一下OldParseProcedure ，我真的是太懒了。
__asm
  {
    cli;
    mov eax, cr0;
    and eax, not 10000h;
    mov cr0, eax;
  }
pType->TypeInfo.ParseProcedure = NewParseProcedure;//hook
  __asm
  {
    mov eax, cr0;
    or eax, 10000h;
    mov cr0, eax;
    sti;
  }
 Status = ZwClose(hFile);
  return Status;
}

/********************************************************************************/

NTSTATUS OBJECTHOOK_DispatchCreateClose(
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

NTSTATUS OBJECTHOOK_DispatchDeviceControl(
    IN PDEVICE_OBJECT		DeviceObject,
    IN PIRP					Irp
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    switch(irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_OBJECTHOOK_OPERATION:
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

VOID OBJECTHOOK_DriverUnload(
    IN PDRIVER_OBJECT		DriverObject
    )
{
	pType->TypeInfo.ParseProcedure = OldParseProcedure;

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
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = OBJECTHOOK_DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OBJECTHOOK_DispatchDeviceControl;
    DriverObject->DriverUnload = OBJECTHOOK_DriverUnload;


	Hook();

    return STATUS_SUCCESS;
}
#ifdef __cplusplus
}; // extern "C"
#endif
