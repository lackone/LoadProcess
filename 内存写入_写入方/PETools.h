#pragma once

#include <windows.h>
#include <stdio.h>

class PETools
{
public:
	//�޸�IAT��
	VOID RepairIAT(IN LPVOID pImageBuffer);
	//�����ض�λ��
	VOID ReviseRelocation(IN LPVOID pImageBuffer, IN DWORD offset);
};

