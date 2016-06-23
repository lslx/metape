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

typedef struct _RunInfo{
	char JmpCodex86[64];
	char JmpCodex64[64];
	int iMoveCount;
	void* pCopyMemImage = 0;
	SIZE_T CopyMemImageSize = 0;

}RunInfo, *PRunInfo;
extern "C" __declspec(dllexport) PRunInfo g_pRunInfo = 0;
void LoadTest()
{
	char szModuleName[0x1100] = "G:\\dev_code\\metape_data\\netpass-x64\\netpass.exe";
	DWORD dataSize = 0;
	void* pNoMapedPeData = File2Buffer(&dataSize, szModuleName);
	HMEMORYMODULE hMemMod = MemoryLoadLibrary(pNoMapedPeData, dataSize);
	PVOID MemModBase = MemryModuleGetBase(hMemMod);
	SIZE_T MemModSize = GetMemImageSize(MemModBase);

}
extern "C" __declspec(dllexport) int WINAPI Run(LPVOID lpMemExeAddr);
int _tmain(int argc, _TCHAR* argv[])
{
	Run((LPVOID)0x00000001);
	return 0;
	LoadTest();
	return 0;
	LogA("in _tmain ");
// 	LogA("what:%d,%s", 25, "fk a");
// 	LogW(L"what:%d,%s", 25, L"fk w");
	MessageBoxA(0, "ssssssssss", "", MB_OK);
	return 0;

	PeTool pe;
	pe.Test();
	MessageBoxA(0, "ssssssssss", "", MB_OK);
	return 0;

	void TitanEngineInit(HINSTANCE hinstDLL);
	TitanEngineInit((HINSTANCE)&__ImageBase);
	Buffer2File("before_entry_run.data", g_pRunInfo->pCopyMemImage, g_pRunInfo->CopyMemImageSize);
	Buffer2File("crt_has_run.data", &__ImageBase, g_pRunInfo->CopyMemImageSize);

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

		if (MapedPePerformBaseRelocation(g_pRunInfo->pCopyMemImage, (DWORD)MemModBase)){
			Buffer2File("load_by_ntload_and_relo.data", g_pRunInfo->pCopyMemImage, g_pRunInfo->CopyMemImageSize);
			ChgeMapedExe2Dll(g_pRunInfo->pCopyMemImage);
			Buffer2File("load_by_ntload_and_relo_2Dll.data", g_pRunInfo->pCopyMemImage, g_pRunInfo->CopyMemImageSize);
			ChgeMapedDll2Exe(g_pRunInfo->pCopyMemImage);
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

#pragma comment(linker,"/subsystem:\"Windows\" /entry:\"mainCRTStartup\"")

extern "C" {
	__declspec(dllexport) int origin_main(void)
	{
// 		LogA("what:%d,%s", 25, "fk a");
// 		LogW(L"what:%d,%s", 25, L"fk a");

		return _tmainCRTStartup();
		PRunInfo& g_p = g_pRunInfo;
		if (g_p){// run from the copy code
			return _tmainCRTStartup();
		}
		else{// first run load by sys
			char *pRetOnStack = (char*)_AddressOfReturnAddress();
			void *pTmp = MoveMemImageToNew(&__ImageBase);// g_p assign after this to keep copy clean
			g_p = (PRunInfo)VirtualAlloc(NULL, sizeof(RunInfo), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			g_p->pCopyMemImage = pTmp;
			if (g_p->pCopyMemImage && MapedPePerformBaseRelocation(g_p->pCopyMemImage, (DWORD)g_p->pCopyMemImage)){
				LogA("image copy to:%p", g_p->pCopyMemImage);
				PRunInfo* ppPRunInfoInCopy = (PRunInfo*)MapedMemPeGetVarAddress(g_p->pCopyMemImage, "g_pRunInfo");
				*ppPRunInfoInCopy = g_p;// patch the copy image
				void* pCopyEntry = MapedMemPeGetEntryPoint(g_p->pCopyMemImage);
#ifdef _WIN64
				char JmpCodex64[64] = {
					0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// mov rcx, 1122334455667788h
					0x48, 0x89, 0x4C, 0x24, 0xF8,//mov qword ptr [rsp-8],rcx
					0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// mov rdx, 1122334455667788h
					0xFF, 0xE2 //jmp rdx
				};
				memcpy(&JmpCodex64[2], pRetOnStack, 8);
				memcpy(&JmpCodex64[17], &pCopyEntry, 8);
				memcpy(&g_p->JmpCodex64, &JmpCodex64, 64);
				*((void**)pRetOnStack) = (void*)(g_p->JmpCodex64);
#else
				char JmpCodex86[64] = {
					0x68, 0x00, 0x00, 0x00, 0x00, //push 11223344h
					0xB8, 0x00, 0x00, 0x00, 0x00, //mov eax,11223344h
					0xFF, 0XE0 }; //jmp eax
				memcpy(&JmpCodex86[1], pRetOnStack, 4);
				memcpy(&JmpCodex86[6], &pCopyEntry, 4);
				memcpy(&g_p->JmpCodex86, &JmpCodex86, 64);
				*((void**)pRetOnStack) = (void*)(g_p->JmpCodex86);
#endif

			}
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



