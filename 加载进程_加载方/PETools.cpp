#include "PETools.h"

/**
 * 读取PE文件到内存中，返回值为读取到的字节数
 * filePath 文件路径
 * fileBuffer 读取到的内存buffer
 */
DWORD PETools::ReadPEFile(IN LPCTSTR filePath, OUT LPVOID* pFileBuffer)
{
	//打开文件
	LPSTR str = NULL;
	TCHARToChar(filePath, &str);

	FILE* fp;
	if (fopen_s(&fp, str, "rb") != 0)
	{
		DWORD code = GetLastError();
		return 0;
	}

	//获取文件的大小
	fseek(fp, 0, SEEK_END);
	DWORD fileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	//申请内存
	LPVOID fBuf = malloc(fileSize);
	if (fBuf == NULL)
	{
		fclose(fp);
		return 0;
	}

	//读取数据到申请的内存中
	memset(fBuf, 0, fileSize);
	fread(fBuf, fileSize, 1, fp);

	*pFileBuffer = fBuf;

	//关闭文件，返回文件大小
	fclose(fp);

	free(str);

	return fileSize;
}

/**
 * 将内存偏移转换为文件偏移
 * pFileBuffer 文件buffer
 * dwRva 内存偏移
 */
DWORD PETools::RvaToFoa(IN LPVOID pFileBuffer, IN DWORD dwRva)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS32 nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER32 opt;
	PIMAGE_SECTION_HEADER section;

	dos = (PIMAGE_DOS_HEADER)pFileBuffer;
	nt = (PIMAGE_NT_HEADERS32)((LPBYTE)dos + dos->e_lfanew);
	pe = (PIMAGE_FILE_HEADER)((LPBYTE)nt + 4);
	opt = (PIMAGE_OPTIONAL_HEADER32)((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);
	section = (PIMAGE_SECTION_HEADER)((LPBYTE)opt + pe->SizeOfOptionalHeader);

	//如果RVA小于头部大小，直接返回RVA，因为文件和拉伸后的，头部并不会变
	//如果文件对齐与内存对齐一样，则文件和拉伸后的，也不会变
	if (dwRva < opt->SizeOfHeaders || opt->FileAlignment == opt->SectionAlignment)
	{
		return dwRva;
	}

	//遍历节，判断RVA在哪个节
	for (int i = 0; i < pe->NumberOfSections; i++)
	{
		//判断RVA哪个节
		if (dwRva >= section->VirtualAddress && dwRva < section->VirtualAddress + section->Misc.VirtualSize)
		{
			return section->PointerToRawData + (dwRva - section->VirtualAddress);
		}
		section++;
	}

	return 0;
}

/**
 * 将文件偏移转换为内存偏移
 * pFileBuffer 文件buffer
 * dwFoa 文件偏移
 */
DWORD PETools::FoaToRva(IN LPVOID pFileBuffer, IN DWORD dwFoa)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS32 nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER32 opt;
	PIMAGE_SECTION_HEADER section;

	dos = (PIMAGE_DOS_HEADER)pFileBuffer;
	nt = (PIMAGE_NT_HEADERS32)((LPBYTE)dos + dos->e_lfanew);
	pe = (PIMAGE_FILE_HEADER)((LPBYTE)nt + 4);
	opt = (PIMAGE_OPTIONAL_HEADER32)((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);
	section = (PIMAGE_SECTION_HEADER)((LPBYTE)opt + pe->SizeOfOptionalHeader);

	//如果FOA小于头部大小，直接返回FOA，因为文件和拉伸后的，头部并不会变
	//如果文件对齐与内存对齐一样，则文件和拉伸后的，也不会变
	if (dwFoa < opt->SizeOfHeaders || opt->FileAlignment == opt->SectionAlignment)
	{
		return dwFoa;
	}

	//遍历节，判断FOA在哪个节
	for (int i = 0; i < pe->NumberOfSections; i++)
	{
		if (dwFoa >= section->PointerToRawData && dwFoa < section->PointerToRawData + section->SizeOfRawData)
		{
			return section->VirtualAddress + (dwFoa - section->PointerToRawData);
		}
		section++;
	}

	return 0;
}

/**
 * 字节对齐
 */
DWORD PETools::Align(IN DWORD x, IN DWORD y)
{
	if (x % y == 0)
	{
		return x;
	}
	else
	{
		DWORD n = x / y;
		return (n + 1) * y;
	}
}

/**
 * 将TCHAR转换成CHAR
 */
VOID PETools::TCHARToChar(IN LPCTSTR tstr, OUT LPSTR* str)
{
	int size_needed = WideCharToMultiByte(CP_ACP, 0, tstr, -1, NULL, 0, NULL, NULL);
	LPSTR buf = (LPSTR)malloc(sizeof(CHAR) * size_needed);
	WideCharToMultiByte(CP_ACP, 0, tstr, -1, buf, size_needed, NULL, NULL);
	*str = buf;
}

/**
 * 拉升文件buffer为imageBuffer
 * pFileBuffer 文件buffer
 * pImageBuffer 拉伸后的buffer
 */
DWORD PETools::FileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER opt;
	PIMAGE_SECTION_HEADER section;

	dos = PIMAGE_DOS_HEADER(pFileBuffer);
	nt = PIMAGE_NT_HEADERS((LPBYTE)dos + dos->e_lfanew);
	pe = PIMAGE_FILE_HEADER((LPBYTE)nt + 4);
	opt = PIMAGE_OPTIONAL_HEADER((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);
	section = PIMAGE_SECTION_HEADER((LPBYTE)opt + pe->SizeOfOptionalHeader);

	//1、先申请sizeOfImage的空间
	LPVOID imgBuf = malloc(opt->SizeOfImage);
	if (imgBuf == NULL)
	{
		return 0;
	}
	memset(imgBuf, 0, opt->SizeOfImage);

	//2、拷贝头数据
	memcpy(imgBuf, pFileBuffer, opt->SizeOfHeaders);

	//3、遍历拷贝节
	for (int i = 0; i < pe->NumberOfSections; i++)
	{
		memcpy((LPBYTE)imgBuf + section->VirtualAddress, (LPBYTE)pFileBuffer + section->PointerToRawData, max(section->SizeOfRawData, section->Misc.VirtualSize));
		section++;
	}

	*pImageBuffer = imgBuf;

	return opt->SizeOfImage;
}

/**
 * 获取ImageBase
 */
DWORD PETools::GetImageBase(IN LPVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER opt;

	dos = PIMAGE_DOS_HEADER(pFileBuffer);
	nt = PIMAGE_NT_HEADERS((LPBYTE)dos + dos->e_lfanew);
	pe = PIMAGE_FILE_HEADER((LPBYTE)nt + 4);
	opt = PIMAGE_OPTIONAL_HEADER((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);

	return opt->ImageBase;
}

/**
 * 获取SizeOfImage
 */
DWORD PETools::GetSizeOfImage(IN LPVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER opt;

	dos = PIMAGE_DOS_HEADER(pFileBuffer);
	nt = PIMAGE_NT_HEADERS((LPBYTE)dos + dos->e_lfanew);
	pe = PIMAGE_FILE_HEADER((LPBYTE)nt + 4);
	opt = PIMAGE_OPTIONAL_HEADER((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);

	return opt->SizeOfImage;
}

/**
 * 获取入口点
 */
DWORD PETools::GetEntryPoint(IN LPVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER opt;

	dos = PIMAGE_DOS_HEADER(pFileBuffer);
	nt = PIMAGE_NT_HEADERS((LPBYTE)dos + dos->e_lfanew);
	pe = PIMAGE_FILE_HEADER((LPBYTE)nt + 4);
	opt = PIMAGE_OPTIONAL_HEADER((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);

	return opt->AddressOfEntryPoint;
}

/**
 * 修复IAT表
 */
VOID PETools::RepairIAT(IN LPVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS32 nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER32 opt;

	dos = (PIMAGE_DOS_HEADER)pFileBuffer;
	nt = (PIMAGE_NT_HEADERS32)((LPBYTE)dos + dos->e_lfanew);
	pe = (PIMAGE_FILE_HEADER)((LPBYTE)nt + 4);
	opt = (PIMAGE_OPTIONAL_HEADER32)((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);

	IMAGE_DATA_DIRECTORY* dir = opt->DataDirectory;

	DWORD importFoa = RvaToFoa(pFileBuffer, dir[1].VirtualAddress);

	PIMAGE_IMPORT_DESCRIPTOR importDir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pFileBuffer + importFoa);

	FARPROC fn = NULL;

	while (importDir->Name)
	{
		DWORD nameFoa = RvaToFoa(pFileBuffer, importDir->Name);

		//注意这里不要使用LoadLibrary，会导致模块加载失败
		HMODULE hModule = LoadLibraryA((LPCSTR)((LPBYTE)pFileBuffer + nameFoa));
		if (hModule == NULL)
		{
			printf("加载模块%s失败\n", (LPBYTE)pFileBuffer + nameFoa);
		}

		//遍历FirstThunk
		DWORD FirstThunkFoa = RvaToFoa(pFileBuffer, importDir->FirstThunk);
		DWORD OriginalFirstThunkFoa = RvaToFoa(pFileBuffer, importDir->OriginalFirstThunk);

		PIMAGE_THUNK_DATA32 FirstThunk = PIMAGE_THUNK_DATA32((LPBYTE)pFileBuffer + FirstThunkFoa);
		PIMAGE_THUNK_DATA32 OriginalFirstThunk = PIMAGE_THUNK_DATA32((LPBYTE)pFileBuffer + OriginalFirstThunkFoa);

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
					printf("加载函数%d成功\n", OriginalFirstThunk->u1.Ordinal & 0x7FFFFFFF);
				}
			}
			else {
				PIMAGE_IMPORT_BY_NAME byname = PIMAGE_IMPORT_BY_NAME((LPBYTE)pFileBuffer + RvaToFoa(pFileBuffer, OriginalFirstThunk->u1.AddressOfData));

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

			FirstThunk++;
			OriginalFirstThunk++;
		}


		importDir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)importDir + 20);
	}
}

/**
 * 修正重定位表
 */
VOID PETools::ReviseRelocation(IN LPVOID pFileBuffer, IN DWORD offset)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER opt;
	PIMAGE_SECTION_HEADER section;
	PIMAGE_SECTION_HEADER last_section;
	IMAGE_DATA_DIRECTORY* dir;


	dos = PIMAGE_DOS_HEADER(pFileBuffer);
	nt = PIMAGE_NT_HEADERS((LPBYTE)dos + dos->e_lfanew);
	pe = PIMAGE_FILE_HEADER((LPBYTE)nt + 4);
	opt = PIMAGE_OPTIONAL_HEADER((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);
	section = PIMAGE_SECTION_HEADER((LPBYTE)opt + pe->SizeOfOptionalHeader);
	last_section = section + pe->NumberOfSections - 1;
	dir = opt->DataDirectory;

	DWORD relFoa = RvaToFoa(pFileBuffer, dir[5].VirtualAddress);

	PIMAGE_BASE_RELOCATION relDir = (PIMAGE_BASE_RELOCATION)((LPBYTE)pFileBuffer + relFoa);

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

				LPDWORD addr = LPDWORD((LPBYTE)pFileBuffer + RvaToFoa(pFileBuffer, rva));

				*addr = *addr + offset;
			}

			start++;
		}

		relDir = (PIMAGE_BASE_RELOCATION)((LPBYTE)relDir + relDir->SizeOfBlock);
	}
}