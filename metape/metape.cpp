// metape.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>
#include "Tools.h"
#include <stdio.h>
#include <tchar.h>
#include "MemoryModule.h"


static void ChgeHeaderSectionAddr(PVOID pMapedMemData, DWORD TagartBase)
{
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)pMapedMemData;
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)&((const unsigned char *)(dos_header))[dos_header->e_lfanew];
	//chge the image base
	nt_header->OptionalHeader.ImageBase = TagartBase;

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_header);
	for (int i = 0; i<nt_header->FileHeader.NumberOfSections; i++, section++) {
		unsigned char* dest = (unsigned char*)TagartBase + section->VirtualAddress;
		//chge the section addr
		section->Misc.PhysicalAddress = (DWORD)(uintptr_t)dest;
	}
}

BOOL MapedPePerformBaseRelocation(PVOID pMapedMemData, DWORD TagartBase)
{

	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)pMapedMemData;
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)&((const unsigned char *)(dos_header))[dos_header->e_lfanew];
	ptrdiff_t delta = (DWORD)TagartBase - (DWORD)nt_header->OptionalHeader.ImageBase;

	unsigned char *codeBase = (unsigned char*)pMapedMemData;
	PIMAGE_BASE_RELOCATION relocation;
	PIMAGE_DATA_DIRECTORY directory = (PIMAGE_DATA_DIRECTORY)&(nt_header)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (directory->Size == 0) {
		return (delta == 0);
	}
	//if  directory->Size is not zero, but the delta is zero,  the program will do the right thing

	// fix the header
	ChgeHeaderSectionAddr(pMapedMemData, TagartBase);

	relocation = (PIMAGE_BASE_RELOCATION)(codeBase + directory->VirtualAddress);
	for (; relocation->VirtualAddress > 0;) {
		DWORD i;
		unsigned char *dest = codeBase + relocation->VirtualAddress;
		unsigned short *relInfo = (unsigned short *)((unsigned char *)relocation + sizeof(IMAGE_BASE_RELOCATION));
		for (i = 0; i < ((relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2); i++, relInfo++) {
			DWORD *patchAddrHL;
#ifdef _WIN64
			ULONGLONG *patchAddr64;
#endif
			int type, offset;

			// the upper 4 bits define the type of relocation
			type = *relInfo >> 12;
			// the lower 12 bits define the offset
			offset = *relInfo & 0xfff;

			switch (type)
			{
			case IMAGE_REL_BASED_ABSOLUTE:
				// skip relocation
				break;

			case IMAGE_REL_BASED_HIGHLOW:
				// change complete 32 bit address
				patchAddrHL = (DWORD *)(dest + offset);
				*patchAddrHL += (DWORD)delta;
				break;

#ifdef _WIN64
			case IMAGE_REL_BASED_DIR64:
				patchAddr64 = (ULONGLONG *)(dest + offset);
				*patchAddr64 += (ULONGLONG)delta;
				break;
#endif

			default:
				//printf("Unknown relocation: %d\n", type);
				break;
			}
		}

		// advance to next relocation block
		relocation = (PIMAGE_BASE_RELOCATION)(((char *)relocation) + relocation->SizeOfBlock);
	}
	return TRUE;
}

SIZE_T GetMemImageSize(void* ImageBase)
{
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)ImageBase;
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)&((const unsigned char *)(dos_header))[dos_header->e_lfanew];
	SIZE_T imageSize = nt_header->OptionalHeader.SizeOfImage;
	return imageSize;
}
void* pCopyMemImage = 0;
SIZE_T CopyMemImageSize = 0;
int _tmain(int argc, _TCHAR* argv[])
{
	Buffer2File("before_entry_run.data", pCopyMemImage, CopyMemImageSize);
	Buffer2File("crt_has_run.data", &__ImageBase, CopyMemImageSize);

	char szModuleName[0x1100] = { 0 };
	if (GetModuleFileNameA((HMODULE)&__ImageBase, (LPCH)szModuleName, sizeof(szModuleName)-0x100))
	{
		long dataSize = 0;
		void* pNoMapedPeData = File2Buffer(&dataSize, szModuleName);
		HMEMORYMODULE hMemMod = MemoryLoadLibrary(pNoMapedPeData, dataSize);
		PVOID MemModBase = MemryModuleGetBase(hMemMod);
		SIZE_T MemModSize = GetMemImageSize(MemModBase);
		DWORD dwProtect = 0;
		if (VirtualProtectEx(GetCurrentProcess(), MemModBase, MemModSize, PAGE_EXECUTE_READWRITE, &dwProtect)){
			Buffer2File("load_by_memload.data", MemModBase, MemModSize);
		}

		if (MapedPePerformBaseRelocation(pCopyMemImage, (DWORD)MemModBase)){
			Buffer2File("load_by_ntload_and_relo.data", pCopyMemImage, CopyMemImageSize);
			return 0;
		}

	}
	return 0;
}


void* MoveMemImageToNew(void* ImageBase)
{
	SIZE_T imageSize = GetMemImageSize(ImageBase);
	LPVOID pTmp = VirtualAllocEx(
		GetCurrentProcess(), NULL, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pTmp)
		memcpy(pTmp, (void*)&__ImageBase, imageSize);
	return pTmp;
}

int origin_main(void)
{
	pCopyMemImage = MoveMemImageToNew(&__ImageBase);
	CopyMemImageSize = GetMemImageSize(&__ImageBase);
	return _tmainCRTStartup();
}
BOOL WINAPI origin_dll_main(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
    BOOL bReturnValue = TRUE;
	switch( dwReason ) 
    { 
		case DLL_PROCESS_ATTACH:
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }
	return bReturnValue;
}



