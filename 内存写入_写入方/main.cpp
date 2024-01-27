#include <windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <tchar.h>
#include "PETools.h"

/**
 * 根据进程名称查找进程ID
 */
DWORD FindProcessByName(LPCTSTR processName)
{
	DWORD pid = 0;
	HANDLE hs = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hs == INVALID_HANDLE_VALUE)
	{
		return pid;
	}
	PROCESSENTRY32 ps{ 0 };
	ps.dwSize = sizeof(PROCESSENTRY32);
	BOOL ret = Process32First(hs, &ps);
	while (ret)
	{
		if (_tcsicmp(ps.szExeFile, processName) == 0)
		{
			pid = ps.th32ProcessID;
			return pid;
		}

		ret = Process32Next(hs, &ps);
	}
	return pid;
}

DWORD WINAPI Entry(LPVOID pImageBuffer)
{
	printf("Entry ...\n");
	printf("address：0x%x\n", (DWORD)pImageBuffer);

	PETools pe;
	pe.RepairIAT(pImageBuffer);

	printf("error: %d\n", GetLastError());
	printf("RepairIAT success\n");

	while (TRUE)
	{
		MessageBox(NULL, TEXT("注入成功"), TEXT("注入成功"), MB_OK);
		Sleep(2000);
	}
}

int main()
{
	//获取当前进程句柄
	HMODULE hModule = GetModuleHandle(NULL);
	HANDLE hProcess = GetCurrentProcess();

	MODULEINFO moduleInfo;
	GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo));

	//获取当前进程的ImageBase和SizeOfImage
	DWORD imageBase = (DWORD)moduleInfo.lpBaseOfDll;
	DWORD sizeOfImage = (DWORD)moduleInfo.SizeOfImage;

	printf("imageBase: 0x%x\n", imageBase);
	printf("sizeOfImage: 0x%x\n", sizeOfImage);

	//申请内存
	LPVOID buf = malloc(sizeOfImage);
	if (buf == NULL)
	{
		printf("申请内存失败\n");
		return -1;
	}
	memset(buf, 0, sizeOfImage);

	//将当前进程的代码，读到我们新创建的缓冲区里
	ReadProcessMemory(hProcess, (LPVOID)imageBase, buf, sizeOfImage, NULL);

	//获取要注入进程的hProcess
	DWORD pid = FindProcessByName(TEXT("内存写入_被写入方.exe"));

	//打开要注入的进程
	HANDLE injectProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	//在注入进程中申请内存
	LPVOID address = VirtualAllocEx(injectProcess, NULL, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	printf("address：0x%x\n", (DWORD)(address));

	PETools pe;

	//修复重定位表
	if ((DWORD)address != imageBase)
	{
		DWORD offset = (DWORD)address - imageBase;
		pe.ReviseRelocation(buf, offset);
	}

	//把数据写入到注入进程中
	WriteProcessMemory(injectProcess, address, buf, sizeOfImage, NULL);

	//创建远程线程
	//计算函数在进程A中的地址 = 函数在当前进程的地址 - 当前进程的基址(ImageBase) + 进程A中申请的基址
	DWORD fn = (DWORD)Entry - (DWORD)imageBase + (DWORD)address;

	HANDLE ht = CreateRemoteThread(injectProcess, NULL, 0, (LPTHREAD_START_ROUTINE)fn, address, 0, NULL);

	WaitForSingleObject(ht, INFINITE);

	DWORD exitCode = 0;
	GetExitCodeThread(ht, &exitCode);

	printf("exitCode: %u\n", exitCode);

	return 0;
}