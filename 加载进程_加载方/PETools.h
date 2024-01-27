#pragma once

#include <windows.h>
#include <stdio.h>

class PETools
{
public:
	//��ȡPE�ļ����ڴ���
	DWORD ReadPEFile(IN LPCTSTR filePath, OUT LPVOID* pFileBuffer);
	//���ڴ�ƫ��ת��Ϊ�ļ�ƫ��
	DWORD RvaToFoa(IN LPVOID pFileBuffer, IN DWORD dwRva);
	//���ļ�ƫ��ת��Ϊ�ڴ�ƫ��
	DWORD FoaToRva(IN LPVOID pFileBuffer, IN DWORD dwFoa);
	//�ֽڶ���
	DWORD Align(IN DWORD x, IN DWORD y);
	//�����ļ�bufferΪimageBuffer
	DWORD FileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer);
	//��TCHARת����CHAR
	VOID TCHARToChar(IN LPCTSTR tstr, OUT LPSTR* str);
	//��ȡImageBase
	DWORD GetImageBase(IN LPVOID pFileBuffer);
	//��ȡSizeOfImage
	DWORD GetSizeOfImage(IN LPVOID pFileBuffer);
	//��ȡ��ڵ�
	DWORD GetEntryPoint(IN LPVOID pFileBuffer);
	//�޸�IAT��
	VOID RepairIAT(IN LPVOID pFileBuffer);
	//�����ض�λ��
	VOID ReviseRelocation(IN LPVOID pFileBuffer, IN DWORD offset);
};

