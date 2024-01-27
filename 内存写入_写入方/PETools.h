#pragma once

#include <windows.h>
#include <stdio.h>

class PETools
{
public:
	//RepairIAT
	VOID RepairIAT(IN LPVOID pImageBuffer);
	//ReviseRelocation
	VOID ReviseRelocation(IN LPVOID pImageBuffer, IN DWORD offset);
};

