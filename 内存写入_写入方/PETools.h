#pragma once

#include <windows.h>
#include <stdio.h>

class PETools
{
public:
	//修复IAT表
	VOID RepairIAT(IN LPVOID pImageBuffer);
	//修正重定位表
	VOID ReviseRelocation(IN LPVOID pImageBuffer, IN DWORD offset);
};

