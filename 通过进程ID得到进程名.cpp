/***
在内核中，通过进程ID，得到进程名称，有多种方法。
我使用了两种方法，第一种是使用ZwOpeProcess得到句柄
然后ObReferenceObjectByHandle函数得到PEPROCESS结构，然后
char *ProcessName = (char*)EProcess + 0x174;
第二种方法是得到PEPROCESS结构之后，使用PsGetProcessImageFileName函数得到进程名。
 
具体代码如下：
*/
#include<ntddk.h>  
#include<wdm.h>  
  
UCHAR* PsGetProcessImageFileName(PEPROCESS Process);  
  
NTSTATUS Unload(IN PDRIVER_OBJECT  DriverObject)  
{  
    DbgPrint("驱动已经卸载/n");     
}   
  
void GetProcessName(ULONG dwPid)  
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
        return;  
    }  
      
    //得到EPROCESS，结构中取进程名  
    status = ObReferenceObjectByHandle(ProcessHandle,FILE_READ_DATA,0,KernelMode,&EProcess, 0);  
    if (status == STATUS_SUCCESS)  
    {  
        char *ProcessName = (char*)EProcess + 0x174;  
        char *PsName = PsGetProcessImageFileName(EProcess);  
  
        DbgPrint("ProcessName is %s/n",ProcessName);  
        DbgPrint("PsName is %s/n",PsName);  
  
        ZwClose(ProcessHandle);  
    }  
    else  
    {  
        DbgPrint("Get ProcessName error");  
    }  
}  
  
NTSTATUS   
  DriverEntry(  
    IN PDRIVER_OBJECT  DriverObject,  
    IN PUNICODE_STRING  RegistryPath  
    )  
{  
    DbgPrint("驱动已经加载了/n");  
    GetProcessName(2044);  
    DriverObject->DriverUnload = Unload;   
    return STATUS_SUCCESS;  
}  
