#pragma once

#include <windows.h>
#include <stdio.h>

class PETools
{
public:
	//�����ض�λ��
	VOID ReviseRelocation(IN LPVOID pImageBuffer, IN DWORD offset);
	//�޸�IAT��
	VOID RepairIAT(IN LPVOID pImageBuffer);
};

