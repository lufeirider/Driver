#include <windows.h>
#include <stdio.h>
#include <winioctl.h>

#define Main_CTL_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)


void show(HANDLE hDevice)
{
	DWORD dwReturned;
	char OutBuffer[255]="";
	char InBuffer[255]="111111111111111";
	DeviceIoControl(hDevice,     //已经打开的设备
					Main_CTL_CODE,////控制码
					&InBuffer,  //输入缓冲区
					255,           //输入缓冲区大小
					&OutBuffer, //输出缓冲区
					255,           //输出缓冲区大小
					&dwReturned, //返回实际字节数
					NULL);
	printf(OutBuffer);
}

int main()
{
	HANDLE hDevice=CreateFile(
		           "\\\\.\\TESTIOCODE_DeviceName",  //符号链接
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

	show(hDevice);

	
	getchar();
	//关闭设备句柄
	CloseHandle(hDevice);
	return 0;
}
