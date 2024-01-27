#include "PETools.h"

/**
 * 修正重定位表
 */
VOID PETools::ReviseRelocation(IN LPVOID pImageBuffer, IN DWORD offset)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER opt;
	PIMAGE_SECTION_HEADER section;
	PIMAGE_SECTION_HEADER last_section;
	IMAGE_DATA_DIRECTORY* dir;


	dos = PIMAGE_DOS_HEADER(pImageBuffer);
	nt = PIMAGE_NT_HEADERS((LPBYTE)dos + dos->e_lfanew);
	pe = PIMAGE_FILE_HEADER((LPBYTE)nt + 4);
	opt = PIMAGE_OPTIONAL_HEADER((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);
	section = PIMAGE_SECTION_HEADER((LPBYTE)opt + pe->SizeOfOptionalHeader);
	last_section = section + pe->NumberOfSections - 1;
	dir = opt->DataDirectory;

	DWORD relRva = dir[5].VirtualAddress;

	PIMAGE_BASE_RELOCATION relDir = (PIMAGE_BASE_RELOCATION)((LPBYTE)pImageBuffer + relRva);

	while (relDir->SizeOfBlock && relDir->VirtualAddress)
	{
		int nums = (relDir->SizeOfBlock - 8) / 2;

		LPWORD start = LPWORD((LPBYTE)relDir + 8);

		for (int i = 0; i < nums; i++)
		{
			WORD type = ((*start) & 0xF000) >> 12;

			if (type == 3)
			{
				//VirtualAddress+后12位，才是真正的RVA
				DWORD rva = relDir->VirtualAddress + ((*start) & 0x0FFF);

				LPDWORD addr = LPDWORD((LPBYTE)pImageBuffer + rva);

				*addr = *addr + offset;
			}

			start++;
		}

		relDir = (PIMAGE_BASE_RELOCATION)((LPBYTE)relDir + relDir->SizeOfBlock);
	}
}

/**
 * 修复IAT表
 */
VOID PETools::RepairIAT(IN LPVOID pImageBuffer)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS32 nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER32 opt;

	dos = (PIMAGE_DOS_HEADER)pImageBuffer;
	nt = (PIMAGE_NT_HEADERS32)((LPBYTE)dos + dos->e_lfanew);
	pe = (PIMAGE_FILE_HEADER)((LPBYTE)nt + 4);
	opt = (PIMAGE_OPTIONAL_HEADER32)((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);

	IMAGE_DATA_DIRECTORY* dir = opt->DataDirectory;

	DWORD importRva = dir[1].VirtualAddress;

	PIMAGE_IMPORT_DESCRIPTOR importDir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pImageBuffer + importRva);

	FARPROC fn = NULL;

	while (importDir->Name)
	{
		DWORD nameRva = importDir->Name;

		//注意这里不要使用LoadLibrary，会导致模块加载失败
		HMODULE hModule = LoadLibraryA((LPCSTR)((LPBYTE)pImageBuffer + nameRva));
		if (hModule == NULL)
		{
			printf("加载模块%s失败\n", (LPBYTE)pImageBuffer + nameRva);
		}

		//遍历FirstThunk
		DWORD FirstThunkRva = importDir->FirstThunk;
		DWORD OriginalFirstThunkRva = importDir->OriginalFirstThunk;

		PIMAGE_THUNK_DATA32 FirstThunk = PIMAGE_THUNK_DATA32((LPBYTE)pImageBuffer + FirstThunkRva);
		PIMAGE_THUNK_DATA32 OriginalFirstThunk = PIMAGE_THUNK_DATA32((LPBYTE)pImageBuffer + OriginalFirstThunkRva);

		while (OriginalFirstThunk->u1.Ordinal)
		{
			//判断最高位是不是1，如果是，则除去最高位的值，就是函数的导出序号
			if ((OriginalFirstThunk->u1.Ordinal & 0x80000000) == 0x80000000)
			{

				fn = GetProcAddress(hModule, (LPCSTR)(OriginalFirstThunk->u1.Ordinal & 0x7FFFFFFF));
				if (fn == NULL)
				{
					printf("加载函数%d失败\n", OriginalFirstThunk->u1.Ordinal & 0x7FFFFFFF);
				}
				else {
					printf("加载函数%d成功", OriginalFirstThunk->u1.Ordinal & 0x7FFFFFFF);
				}
			}
			else {
				PIMAGE_IMPORT_BY_NAME byname = PIMAGE_IMPORT_BY_NAME((LPBYTE)pImageBuffer + OriginalFirstThunk->u1.AddressOfData);

				fn = GetProcAddress(hModule, byname->Name);
				if (fn == NULL)
				{
					printf("加载函数%s失败\n", byname->Name);
				}
				else {
					printf("加载函数%s成功\n", byname->Name);
				}
			}

			FirstThunk->u1.Function = (DWORD)fn;

			OriginalFirstThunk++;
			FirstThunk++;
		}


		importDir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)importDir + 20);
	}
}