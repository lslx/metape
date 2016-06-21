// metape.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>
#include "Tools.h"
#include <stdio.h>
#include <tchar.h>
#include "MemoryModule.h"
#include ".\TitanEngine\scylla_wrapper.h"
#include "PeTool.h"


void* pCopyMemImage = 0;
SIZE_T CopyMemImageSize = 0;
int _tmain(int argc, _TCHAR* argv[])
{
	LogA("what:%d,%s", 25, "fk a");
	LogW(L"what:%d,%s", 25, L"fk w");

	PeTool pe;
	pe.Test();
	MessageBoxA(0, "ssssssssss", "", MB_OK);
	return 0;

	void TitanEngineInit(HINSTANCE hinstDLL);
	TitanEngineInit((HINSTANCE)&__ImageBase);
	Buffer2File("before_entry_run.data", pCopyMemImage, CopyMemImageSize);
	Buffer2File("crt_has_run.data", &__ImageBase, CopyMemImageSize);

	char szModuleName[0x1100] = { 0 };
	if (GetModuleFileNameA((HMODULE)&__ImageBase, (LPCH)szModuleName, sizeof(szModuleName)-0x100))
	{
		DWORD dataSize = 0;
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
			ChgeMapedExe2Dll(pCopyMemImage);
			Buffer2File("load_by_ntload_and_relo_2Dll.data", pCopyMemImage, CopyMemImageSize);
			ChgeMapedDll2Exe(pCopyMemImage);
			PVOID EntryPoint = MapedMemPeGetEntryPoint(&__ImageBase);
			scylla_dumpProcessA(GetCurrentProcessId(), 0, (DWORD_PTR)&__ImageBase, (DWORD_PTR)EntryPoint, "load_by_ntload_scy_save.exe");
			//scylla_dumpProcessA(GetCurrentProcessId(), "load_by_ntload_and_relo_2Dll.data", (DWORD_PTR)pCopyMemImage, 0, "metape2dll.dll");
			return 0;
		}

	}
	return 0;
}

void* MoveMemImageToNew(void* ImageBase)
{
	SIZE_T imageSize = GetMemImageSize(ImageBase);
	LPVOID pTmp = VirtualAllocEx(
		GetCurrentProcess(), NULL, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pTmp)
		memcpy(pTmp, (void*)&__ImageBase, imageSize);
	return pTmp;
}
typedef struct _RunInfo{
	int iMoveCount;
}RunInfo, *PRunInfo;


extern "C" {
	__declspec(dllexport) int origin_main(void)
	{
		LogA("what:%d,%s", 25, "fk a");

		return _tmainCRTStartup();

		PVOID pRunInfo = NULL; 
		char *pRetOnStack = (char*)_AddressOfReturnAddress();
		DWORD * pTmp = (DWORD*)(pRetOnStack - 1024 * 4);
		if (0x0001 == pTmp[0] && 0x0021 == pTmp[1] && 0x0321 == pTmp[3] && 0x4321 == pTmp[4]){
			pRunInfo = (PRunInfo)pTmp[2];
			return _tmainCRTStartup();
		}
		else{
			pRunInfo = LocalAlloc(LPTR, sizeof(RunInfo));
			pCopyMemImage = MoveMemImageToNew(&__ImageBase);
			if (pCopyMemImage && MapedPePerformBaseRelocation(pCopyMemImage, (DWORD)pCopyMemImage)){
				char JmpCode[64] = { /*push dword*/0x68, 0x00, 0x00, 0x00, 0x00, /*jmp eax*/0xFF, 0XE0 };
				void* pCopyEntry = MapedMemPeGetEntryPoint(pCopyMemImage);
				memcpy(&JmpCode[1], pRetOnStack, 4);
				*((unsigned int*)pRetOnStack) = (unsigned int)(JmpCode);
				pTmp[0] = 0x0001; pTmp[1] = 0x0021; pTmp[2] = (DWORD)pRunInfo; pTmp[3] = 0x0321; pTmp[4] = 0x4321;
				return (int)pCopyEntry;
			}
			return 0;
		}
	}
}
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL APIENTRY DllMain_TitanEngine(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
	BOOL bTitanEngineInit = DllMain_TitanEngine(hinstDLL, dwReason, lpReserved);
	if (!bTitanEngineInit)
		return FALSE;
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
extern "C" {
	BOOL WINAPI _DllMainCRTStartup(HANDLE  hDllHandle, DWORD   dwReason, LPVOID  lpreserved);
}
extern "C" {
	__declspec(dllexport) BOOL WINAPI origin_dll_main(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
	{
		return _DllMainCRTStartup(hinstDLL, dwReason, lpReserved);
	}
}



