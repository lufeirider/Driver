#include <windows.h>
#include <stdio.h>
#include <winioctl.h>

#define Main_CTL_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define Flag_CTL_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_ANY_ACCESS)
DWORD BytesReturned;

void show(HANDLE hDevice)
{
	char OutBuffer[255]="";
	DeviceIoControl(hDevice,     //已经打开的设备
					Main_CTL_CODE,////控制码
					NULL,  //输入缓冲区
					0,           //输入缓冲区大小    a&b
					&OutBuffer, //输出缓冲区
					255,           //输出缓冲区大小    a+b
					&BytesReturned, //返回实际字节数
					NULL);
	printf(OutBuffer);
}

int main(int argc, char* argv[])
{
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
					4,           //输入缓冲区大小    a&b
					NULL, //输出缓冲区
					0,           //输出缓冲区大小    a+b
					&BytesReturned, //返回实际字节数
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
