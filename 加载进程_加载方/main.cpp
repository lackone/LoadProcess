#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include "PETools.h"

/**
 * �ٴγ��������ڴ�
 */
LPVOID AgainTryVirtualAlloc(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize)
{
	LPVOID address = NULL;

	DWORD start = (DWORD)lpAddress;
	DWORD end = 0x7000000;

	//���������� 100000 Ϊ����
	for (; start < end; start += 0x100000)
	{
		address = VirtualAllocEx(hProcess, (LPVOID)start, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (address != NULL)
		{
			printf("0x%x ����ɹ�\n", (DWORD)address);
			return address;
		}
	}

	return address;
}

int main()
{
	setlocale(LC_ALL, "CHS");
	printf("���ط���������...\n");

	//��ȡ��ǰ���̡��߳̾��
	HANDLE hProcess = GetCurrentProcess();
	HANDLE hThread = GetCurrentThread();

	//��ȡ��ǰ���̵߳�Context
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(hThread, &ctx);

	//1���������ѵĽ���ImageBaseһ���ϴ��ֵ���ó��������ڸ�λ
	//����32λ�����ַΪ 0x400000���������û�ַΪ 0x7000000, ʮ����Ϊ117440512

	//2����Ҫִ�еĽ��̶�ȡ���������ս��̵�ImageBase��SizeOfImage����ռ�							
	TCHAR exePath[] = { TEXT("I:\\cpp_projects\\LoadProcess\\Debug\\���ؽ���_�����ط�.exe") };

	PETools pe;
	LPVOID fileBuf = NULL;
	LPVOID imageBuf = NULL;

	//��ȡҪ���е�exe�ļ�
	pe.ReadPEFile(exePath, &fileBuf);
	DWORD imageBase = pe.GetImageBase(fileBuf);
	DWORD sizeOfImage = pe.GetSizeOfImage(fileBuf);
	DWORD entryPoint = pe.GetEntryPoint(fileBuf);

	printf("imageBase��0x%x\n", imageBase);
	printf("sizeOfImage��0x%x\n", sizeOfImage);
	printf("entryPoint��0x%x\n", entryPoint);

	//�ڵ�ǰ�����ڴ�ռ��ImageBase�������ڴ�
	LPVOID address = AgainTryVirtualAlloc(hProcess, (LPVOID)imageBase, sizeOfImage);

	//������뵽�ĵ�ַ����ImageBase��һ��
	if ((DWORD)address != imageBase)
	{
		printf("�����ַ��ImageBase��һ��\n");

		DWORD offset = (DWORD)address - imageBase;
		pe.ReviseRelocation(fileBuf, offset);
	}

	printf("address��0x%x\n", (DWORD)address);

	//3���޸�IAT��
	//Ϊʲôֻ�޸�IAT���ض�λ�����޸�����Ϊ���ǲ�û�иı�����ImageBase
	pe.RepairIAT(fileBuf);

	//4���������
	pe.FileBufferToImageBuffer(fileBuf, &imageBuf);

	//5�����޸�������ȫ��COPY����ǰ���̿ռ�
	WriteProcessMemory(hProcess, address, imageBuf, sizeOfImage, NULL);

	DWORD oep = (DWORD)address + entryPoint;
	printf("oep��0x%x\n", oep);

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