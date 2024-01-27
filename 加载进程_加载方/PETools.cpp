#include "PETools.h"

/**
 * ��ȡPE�ļ����ڴ��У�����ֵΪ��ȡ�����ֽ���
 * filePath �ļ�·��
 * fileBuffer ��ȡ�����ڴ�buffer
 */
DWORD PETools::ReadPEFile(IN LPCTSTR filePath, OUT LPVOID* pFileBuffer)
{
	//���ļ�
	LPSTR str = NULL;
	TCHARToChar(filePath, &str);

	FILE* fp;
	if (fopen_s(&fp, str, "rb") != 0)
	{
		DWORD code = GetLastError();
		return 0;
	}

	//��ȡ�ļ��Ĵ�С
	fseek(fp, 0, SEEK_END);
	DWORD fileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	//�����ڴ�
	LPVOID fBuf = malloc(fileSize);
	if (fBuf == NULL)
	{
		fclose(fp);
		return 0;
	}

	//��ȡ���ݵ�������ڴ���
	memset(fBuf, 0, fileSize);
	fread(fBuf, fileSize, 1, fp);

	*pFileBuffer = fBuf;

	//�ر��ļ��������ļ���С
	fclose(fp);

	free(str);

	return fileSize;
}

/**
 * ���ڴ�ƫ��ת��Ϊ�ļ�ƫ��
 * pFileBuffer �ļ�buffer
 * dwRva �ڴ�ƫ��
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

	//���RVAС��ͷ����С��ֱ�ӷ���RVA����Ϊ�ļ��������ģ�ͷ���������
	//����ļ��������ڴ����һ�������ļ��������ģ�Ҳ�����
	if (dwRva < opt->SizeOfHeaders || opt->FileAlignment == opt->SectionAlignment)
	{
		return dwRva;
	}

	//�����ڣ��ж�RVA���ĸ���
	for (int i = 0; i < pe->NumberOfSections; i++)
	{
		//�ж�RVA�ĸ���
		if (dwRva >= section->VirtualAddress && dwRva < section->VirtualAddress + section->Misc.VirtualSize)
		{
			return section->PointerToRawData + (dwRva - section->VirtualAddress);
		}
		section++;
	}

	return 0;
}

/**
 * ���ļ�ƫ��ת��Ϊ�ڴ�ƫ��
 * pFileBuffer �ļ�buffer
 * dwFoa �ļ�ƫ��
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

	//���FOAС��ͷ����С��ֱ�ӷ���FOA����Ϊ�ļ��������ģ�ͷ���������
	//����ļ��������ڴ����һ�������ļ��������ģ�Ҳ�����
	if (dwFoa < opt->SizeOfHeaders || opt->FileAlignment == opt->SectionAlignment)
	{
		return dwFoa;
	}

	//�����ڣ��ж�FOA���ĸ���
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
 * �ֽڶ���
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
 * ��TCHARת����CHAR
 */
VOID PETools::TCHARToChar(IN LPCTSTR tstr, OUT LPSTR* str)
{
	int size_needed = WideCharToMultiByte(CP_ACP, 0, tstr, -1, NULL, 0, NULL, NULL);
	LPSTR buf = (LPSTR)malloc(sizeof(CHAR) * size_needed);
	WideCharToMultiByte(CP_ACP, 0, tstr, -1, buf, size_needed, NULL, NULL);
	*str = buf;
}

/**
 * �����ļ�bufferΪimageBuffer
 * pFileBuffer �ļ�buffer
 * pImageBuffer ������buffer
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

	//1��������sizeOfImage�Ŀռ�
	LPVOID imgBuf = malloc(opt->SizeOfImage);
	if (imgBuf == NULL)
	{
		return 0;
	}
	memset(imgBuf, 0, opt->SizeOfImage);

	//2������ͷ����
	memcpy(imgBuf, pFileBuffer, opt->SizeOfHeaders);

	//3������������
	for (int i = 0; i < pe->NumberOfSections; i++)
	{
		memcpy((LPBYTE)imgBuf + section->VirtualAddress, (LPBYTE)pFileBuffer + section->PointerToRawData, max(section->SizeOfRawData, section->Misc.VirtualSize));
		section++;
	}

	*pImageBuffer = imgBuf;

	return opt->SizeOfImage;
}

/**
 * ��ȡImageBase
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
 * ��ȡSizeOfImage
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
 * ��ȡ��ڵ�
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
 * �޸�IAT��
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

		//ע�����ﲻҪʹ��LoadLibrary���ᵼ��ģ�����ʧ��
		HMODULE hModule = LoadLibraryA((LPCSTR)((LPBYTE)pFileBuffer + nameFoa));
		if (hModule == NULL)
		{
			printf("����ģ��%sʧ��\n", (LPBYTE)pFileBuffer + nameFoa);
		}

		//����FirstThunk
		DWORD FirstThunkFoa = RvaToFoa(pFileBuffer, importDir->FirstThunk);
		DWORD OriginalFirstThunkFoa = RvaToFoa(pFileBuffer, importDir->OriginalFirstThunk);

		PIMAGE_THUNK_DATA32 FirstThunk = PIMAGE_THUNK_DATA32((LPBYTE)pFileBuffer + FirstThunkFoa);
		PIMAGE_THUNK_DATA32 OriginalFirstThunk = PIMAGE_THUNK_DATA32((LPBYTE)pFileBuffer + OriginalFirstThunkFoa);

		while (OriginalFirstThunk->u1.Ordinal)
		{
			//�ж����λ�ǲ���1������ǣ����ȥ���λ��ֵ�����Ǻ����ĵ������
			if ((OriginalFirstThunk->u1.Ordinal & 0x80000000) == 0x80000000)
			{
				fn = GetProcAddress(hModule, (LPCSTR)(OriginalFirstThunk->u1.Ordinal & 0x7FFFFFFF));
				if (fn == NULL)
				{
					printf("���غ���%dʧ��\n", OriginalFirstThunk->u1.Ordinal & 0x7FFFFFFF);
				}
				else {
					printf("���غ���%d�ɹ�\n", OriginalFirstThunk->u1.Ordinal & 0x7FFFFFFF);
				}
			}
			else {
				PIMAGE_IMPORT_BY_NAME byname = PIMAGE_IMPORT_BY_NAME((LPBYTE)pFileBuffer + RvaToFoa(pFileBuffer, OriginalFirstThunk->u1.AddressOfData));

				fn = GetProcAddress(hModule, byname->Name);
				if (fn == NULL)
				{
					printf("���غ���%sʧ��\n", byname->Name);
				}
				else {
					printf("���غ���%s�ɹ�\n", byname->Name);
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
 * �����ض�λ��
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
				//VirtualAddress+��12λ������������RVA
				DWORD rva = relDir->VirtualAddress + ((*start) & 0x0FFF);

				LPDWORD addr = LPDWORD((LPBYTE)pFileBuffer + RvaToFoa(pFileBuffer, rva));

				*addr = *addr + offset;
			}

			start++;
		}

		relDir = (PIMAGE_BASE_RELOCATION)((LPBYTE)relDir + relDir->SizeOfBlock);
	}
}