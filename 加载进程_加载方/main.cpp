#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include "PETools.h"

/**
 * 再次尝试申请内存
 */
LPVOID AgainTryVirtualAlloc(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize)
{
	LPVOID address = NULL;

	DWORD start = (DWORD)lpAddress;
	DWORD end = 0x7000000;

	//这里我们以 100000 为步长
	for (; start < end; start += 0x100000)
	{
		address = VirtualAllocEx(hProcess, (LPVOID)start, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (address != NULL)
		{
			printf("0x%x 申请成功\n", (DWORD)address);
			return address;
		}
	}

	return address;
}

int main()
{
	setlocale(LC_ALL, "CHS");
	printf("加载方进程启动...\n");

	//获取当前进程、线程句柄
	HANDLE hProcess = GetCurrentProcess();
	HANDLE hThread = GetCurrentThread();

	//获取当前主线程的Context
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(hThread, &ctx);

	//1、设置自已的进程ImageBase一个较大的值，让程序运行在高位
	//正常32位程序基址为 0x400000，我们设置基址为 0x7000000, 十进制为117440512

	//2、将要执行的进程读取进来，按照进程的ImageBase和SizeOfImage分配空间							
	TCHAR exePath[] = { TEXT("I:\\cpp_projects\\LoadProcess\\Debug\\加载进程_被加载方.exe") };

	PETools pe;
	LPVOID fileBuf = NULL;
	LPVOID imageBuf = NULL;

	//读取要运行的exe文件
	pe.ReadPEFile(exePath, &fileBuf);
	DWORD imageBase = pe.GetImageBase(fileBuf);
	DWORD sizeOfImage = pe.GetSizeOfImage(fileBuf);
	DWORD entryPoint = pe.GetEntryPoint(fileBuf);

	printf("imageBase：0x%x\n", imageBase);
	printf("sizeOfImage：0x%x\n", sizeOfImage);
	printf("entryPoint：0x%x\n", entryPoint);

	//在当前进程内存空间的ImageBase处申请内存
	LPVOID address = AgainTryVirtualAlloc(hProcess, (LPVOID)imageBase, sizeOfImage);

	//如果申请到的地址，与ImageBase不一致
	if ((DWORD)address != imageBase)
	{
		printf("申请地址与ImageBase不一致\n");

		DWORD offset = (DWORD)address - imageBase;
		pe.ReviseRelocation(fileBuf, offset);
	}

	printf("address：0x%x\n", (DWORD)address);

	//3、修复IAT表
	//为什么只修复IAT表，重定位表不用修复，因为我们并没有改变程序的ImageBase
	pe.RepairIAT(fileBuf);

	//4、拉伸进程
	pe.FileBufferToImageBuffer(fileBuf, &imageBuf);

	//5、把修复的数据全部COPY到当前进程空间
	WriteProcessMemory(hProcess, address, imageBuf, sizeOfImage, NULL);

	DWORD oep = (DWORD)address + entryPoint;
	printf("oep：0x%x\n", oep);

	ctx.ContextFlags = CONTEXT_FULL;
	ctx.Eip = oep;
	SetThreadContext(hThread, &ctx);

	//__asm {
	//	jmp oep
	//}

	free(fileBuf);
	free(imageBuf);

	return 0;
}