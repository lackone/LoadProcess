#pragma once

#include <windows.h>
#include <stdio.h>

class PETools
{
public:
	//读取PE文件到内存中
	DWORD ReadPEFile(IN LPCTSTR filePath, OUT LPVOID* pFileBuffer);
	//将内存偏移转换为文件偏移
	DWORD RvaToFoa(IN LPVOID pFileBuffer, IN DWORD dwRva);
	//将文件偏移转换为内存偏移
	DWORD FoaToRva(IN LPVOID pFileBuffer, IN DWORD dwFoa);
	//字节对齐
	DWORD Align(IN DWORD x, IN DWORD y);
	//拉伸文件buffer为imageBuffer
	DWORD FileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer);
	//将TCHAR转换成CHAR
	VOID TCHARToChar(IN LPCTSTR tstr, OUT LPSTR* str);
	//获取ImageBase
	DWORD GetImageBase(IN LPVOID pFileBuffer);
	//获取SizeOfImage
	DWORD GetSizeOfImage(IN LPVOID pFileBuffer);
	//获取入口点
	DWORD GetEntryPoint(IN LPVOID pFileBuffer);
	//修复IAT表
	VOID RepairIAT(IN LPVOID pFileBuffer);
	//修正重定位表
	VOID ReviseRelocation(IN LPVOID pFileBuffer, IN DWORD offset);
};

