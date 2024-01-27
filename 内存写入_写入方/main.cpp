#include <windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <tchar.h>
#include "PETools.h"

/**
 * ���ݽ������Ʋ��ҽ���ID
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
	printf("address��0x%x\n", (DWORD)pImageBuffer);

	PETools pe;
	pe.RepairIAT(pImageBuffer);

	printf("error: %d\n", GetLastError());
	printf("RepairIAT success\n");

	while (TRUE)
	{
		MessageBox(NULL, TEXT("ע��ɹ�"), TEXT("ע��ɹ�"), MB_OK);
		Sleep(2000);
	}
}

int main()
{
	//��ȡ��ǰ���̾��
	HMODULE hModule = GetModuleHandle(NULL);
	HANDLE hProcess = GetCurrentProcess();

	MODULEINFO moduleInfo;
	GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo));

	//��ȡ��ǰ���̵�ImageBase��SizeOfImage
	DWORD imageBase = (DWORD)moduleInfo.lpBaseOfDll;
	DWORD sizeOfImage = (DWORD)moduleInfo.SizeOfImage;

	printf("imageBase: 0x%x\n", imageBase);
	printf("sizeOfImage: 0x%x\n", sizeOfImage);

	//�����ڴ�
	LPVOID buf = malloc(sizeOfImage);
	if (buf == NULL)
	{
		printf("�����ڴ�ʧ��\n");
		return -1;
	}
	memset(buf, 0, sizeOfImage);

	//����ǰ���̵Ĵ��룬���������´����Ļ�������
	ReadProcessMemory(hProcess, (LPVOID)imageBase, buf, sizeOfImage, NULL);

	//��ȡҪע����̵�hProcess
	DWORD pid = FindProcessByName(TEXT("�ڴ�д��_��д�뷽.exe"));

	//��Ҫע��Ľ���
	HANDLE injectProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	//��ע������������ڴ�
	LPVOID address = VirtualAllocEx(injectProcess, NULL, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	printf("address��0x%x\n", (DWORD)(address));

	PETools pe;

	//�޸��ض�λ��
	if ((DWORD)address != imageBase)
	{
		DWORD offset = (DWORD)address - imageBase;
		pe.ReviseRelocation(buf, offset);
	}

	//������д�뵽ע�������
	WriteProcessMemory(injectProcess, address, buf, sizeOfImage, NULL);

	//����Զ���߳�
	//���㺯���ڽ���A�еĵ�ַ = �����ڵ�ǰ���̵ĵ�ַ - ��ǰ���̵Ļ�ַ(ImageBase) + ����A������Ļ�ַ
	DWORD fn = (DWORD)Entry - (DWORD)imageBase + (DWORD)address;

	HANDLE ht = CreateRemoteThread(injectProcess, NULL, 0, (LPTHREAD_START_ROUTINE)fn, address, 0, NULL);

	WaitForSingleObject(ht, INFINITE);

	DWORD exitCode = 0;
	GetExitCodeThread(ht, &exitCode);

	printf("exitCode: %u\n", exitCode);

	return 0;
}