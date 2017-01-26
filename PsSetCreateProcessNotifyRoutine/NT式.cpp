#include <windows.h>
#include <stdio.h>
#include <winioctl.h>

#define Main_CTL_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define Flag_CTL_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_ANY_ACCESS)
DWORD dwReturned;
char szDebugString[255]="";
DWORD dwErrorCode;
void ColseService(SC_HANDLE hSeriverMgr,SC_HANDLE hSeriverDDK)
{
	dwErrorCode = GetLastError();
	sprintf(szDebugString,"error code = %d",dwErrorCode);
	MessageBox(NULL,szDebugString,"failed!",NULL);
	if(hSeriverDDK)
	{
		CloseServiceHandle(hSeriverDDK);
	}
	if(hSeriverMgr)
	{
		CloseServiceHandle(hSeriverMgr);
	}
}

//服务的名字 sys的路径
void LoadDriver(char* szDriverName,char* szDriverImagePath)
{
	SC_HANDLE hSeriverMgr=NULL;
	SC_HANDLE hSeriverDDK=NULL;

	//打开SCM控制管理器
	hSeriverMgr = OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if(hSeriverMgr==NULL)
	{
		ColseService(hSeriverMgr,hSeriverDDK);
	}

	//创建驱动对应的服务
	hSeriverDDK=CreateService(
				  hSeriverMgr,//服务管理器句柄
		          szDriverName,//驱动文件的注册表名
				  szDriverName,//注册表显示文件名
				  SERVICE_ALL_ACCESS,//加载驱动程序的访问权限
				  SERVICE_KERNEL_DRIVER,//表示加载的服务是驱动程序
				  SERVICE_DEMAND_START,//注册表驱动程序的start值
				  SERVICE_ERROR_IGNORE,//注册表驱动程序的ErrorControl的值
				  szDriverImagePath,//注册表驱动程序的ImagePath的路径
				  NULL,
				  NULL,
				  NULL,
				  NULL,
				  NULL

				);
	if(hSeriverDDK==NULL)
	{
		dwErrorCode = GetLastError();
		if(dwErrorCode==ERROR_SERVICE_EXISTS)
		{
			//服务已经创建，只需要打开就可以了
			hSeriverDDK = OpenService(hSeriverMgr,szDriverName,SERVICE_ALL_ACCESS);
			if(hSeriverDDK==NULL)
			{
				ColseService(hSeriverMgr,hSeriverDDK);
			}
		}
		else
		{
			//由于其他原因创建失败
			ColseService(hSeriverMgr,hSeriverDDK);
		}

	}

	//开启此服务
	dwErrorCode = StartService(hSeriverDDK,NULL,NULL);
	if(!dwErrorCode)//若不成功
	{
		dwErrorCode = GetLastError();
		if(dwErrorCode=!ERROR_SERVICE_ALREADY_RUNNING)
		{
			//原因不是别挂起或已经运行
			ColseService(hSeriverMgr,hSeriverDDK);
		}
	}
}

//卸载驱动程序  
void UnloadDriver(char * szSvrName)  
{
	SC_HANDLE hServiceMgr = NULL;//SCM管理器的句柄
	SC_HANDLE hServiceDDK = NULL;//NT驱动程序的服务句柄
	SERVICE_STATUS SvrSta;
	
	//打开SCM管理器
	hServiceMgr = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );  
	if( hServiceMgr == NULL )  
	{
		//带开SCM管理器失败
		ColseService(hServiceMgr,hServiceDDK);
	}  

	//打开驱动所对应的服务
	hServiceDDK = OpenService( hServiceMgr, szSvrName, SERVICE_ALL_ACCESS );  
	if( hServiceDDK == NULL )  
	{
		//打开驱动所对应的服务失败
		ColseService(hServiceMgr,hServiceDDK);
	}  
	
	//停止驱动程序，如果停止失败，只有重新启动才能，再动态加载。  
	if(!ControlService( hServiceDDK, SERVICE_CONTROL_STOP , &SvrSta ) )  
	{  
		ColseService(hServiceMgr,hServiceDDK);
	}  
	
	//动态卸载驱动程序。  
	if(!DeleteService( hServiceDDK ))  
	{
		ColseService(hServiceMgr,hServiceDDK);
	}	
} 

void show(HANDLE hDevice)
{
	char OutBuffer[255]="";
	DeviceIoControl(hDevice,     //已经打开的设备
					Main_CTL_CODE,////控制码
					NULL,  //输入缓冲区
					0,           //输入缓冲区大小
					&OutBuffer, //输出缓冲区
					255,           //输出缓冲区大小
					&dwReturned, //返回实际字节数
					NULL);
	printf(OutBuffer);
}

int main(int argc, char* argv[])
{
	LoadDriver("Notify","c:\\Notify.sys");
	//UnloadDriver("Notify");
	HANDLE hDevice=CreateFile(
		           "\\\\.\\NOTIFY_DeviceName",  //符号链接
				    GENERIC_READ|GENERIC_WRITE,
					0,
					NULL,
					OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL,
					NULL);
	//判断设备是否打开
	if(hDevice==INVALID_HANDLE_VALUE)
	{
		printf("获取驱动句柄失败: %s with Win32 error code: %d\n","MyDriver", GetLastError() );
		getchar();
		return -1;
	}
	HANDLE isWait;
    isWait = CreateEvent(NULL,false,false,NULL);
	DeviceIoControl(hDevice,     //已经打开的设备
					Flag_CTL_CODE,////控制码
					&isWait,  //输入缓冲区
					4,           //输入缓冲区大小
					NULL, //输出缓冲区
					0,           //输出缓冲区大小
					&dwReturned, //返回实际字节数
					NULL);

	while(1)
	{
		WaitForSingleObject(isWait,INFINITE);
		show(hDevice);
	}
	
	getchar();
	//关闭设备句柄
	CloseHandle(hDevice);
	return 0;
}
