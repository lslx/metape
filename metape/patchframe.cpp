// patchframe.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include <CommCtrl.h>
#include "MemoryModule.h"
#define WIN32_LEAN_AND_MEAN
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <assert.h>
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <malloc.h>
#include "detours/detours.h"
#include "Tools.h"
#define  LogA 
// 重定向函数
#include <list>
typedef std::list<HMEMORYMODULE> ListMemMod;
typedef std::list<HMEMORYRSRC> ListMemRsrc;
typedef std::list<HCUSTOMMODULE> ListCustMod;
typedef std::list<HGLOBAL> ListResHand;

ListMemMod listMemMod;
ListMemRsrc listMemRsrc;// FindResource return the value , need free  ? fix me
ListCustMod listCustMod;
ListResHand listResHand;

// the define copy from MemoryModule.c
typedef struct {
	PIMAGE_NT_HEADERS headers;
	unsigned char *codeBase;
	HCUSTOMMODULE *modules;
	int numModules;
	BOOL initialized;
	BOOL isDLL;
	BOOL isRelocated;
	CustomAllocFunc alloc;
	CustomFreeFunc free;
	CustomLoadLibraryFunc loadLibrary;
	CustomGetProcAddressFunc getProcAddress;
	CustomFreeLibraryFunc freeLibrary;
	void *userdata;
	void * exeEntry;
	DWORD pageSize;
} MEMORYMODULE, *PMEMORYMODULE;
#define ALIGN_VALUE_UP(value, alignment)    (((value) + (alignment) - 1) & ~((alignment) - 1))
HMODULE GetAny_temp(){
	LogA("in GetAny_temp");
	if (!listMemMod.size())
		return 0;
	PMEMORYMODULE pMemMod = (PMEMORYMODULE)*listMemMod.begin();
	return (HMODULE)pMemMod->codeBase;
}

bool AddResHand(HGLOBAL hResHand){
	LogA("in AddResHand");
	if (!hResHand)
		return false;
	std::list<HGLOBAL>::iterator it = std::find(listResHand.begin(), listResHand.end(), hResHand);
	if (it != listResHand.end())
		return false;
	listResHand.push_back(hResHand);
	return true;
}
bool RemoveResHand(HGLOBAL hResHand){
	LogA("in RemoveResHand");
	if (!hResHand)
		return false;
	std::list<HGLOBAL>::iterator it = std::find(listResHand.begin(), listResHand.end(), hResHand);
	if (it == listResHand.end())
		return false;
	listMemMod.remove(hResHand);
	return true;
}
bool IsResHandLoad(HGLOBAL hResHand){
	LogA("in IsResHandLoad");
	if (!hResHand)
		return false;
	std::list<HGLOBAL>::iterator it = std::find(listResHand.begin(), listResHand.end(), hResHand);
	if (it == listResHand.end())
		return false;
	return true;
}
// ------------------------     fix me  multi thread
bool AddMemMod(HMEMORYMODULE hMemMod){
	LogA("in AddMemMod");
	if (!hMemMod)
		return false;
	std::list<HMEMORYMODULE>::iterator it = std::find(listMemMod.begin(), listMemMod.end(), hMemMod);
	if (it != listMemMod.end())
		return false;
	listMemMod.push_back(hMemMod);
	return true;
}
bool RemoveMemMod(HMEMORYMODULE hMemMod){
	LogA("in RemoveMemMod");
	if (!hMemMod)
		return false;
	std::list<HMEMORYMODULE>::iterator it = std::find(listMemMod.begin(), listMemMod.end(), hMemMod);
	if (it == listMemMod.end())
		return false;
	listMemMod.remove(hMemMod);
	return true;
}
bool IsMemModLoad_ByBase(LPVOID lpBaseAddr){
	LogA("in IsMemModLoad_ByBase");
	if (!lpBaseAddr)
		return false;
	for (std::list<HMEMORYMODULE>::iterator it = listMemMod.begin(); it != listMemMod.end(); it++)
	{
		PMEMORYMODULE pMemMod = (PMEMORYMODULE)*it;
		if (pMemMod->codeBase == lpBaseAddr)
			return true;

	}
	return false;
}
HMEMORYMODULE GetHMemModHandle(LPVOID lpBaseAddr){
	LogA("in GetHMemModHandle");
	if (!lpBaseAddr)
		return 0;
	for (std::list<HMEMORYMODULE>::iterator it = listMemMod.begin(); it != listMemMod.end(); it++)
	{
		if (((PMEMORYMODULE)*it)->codeBase == lpBaseAddr)
			return *it;
	}
	return 0;
}
bool IsMemModLoad_ByMemHand(HMEMORYMODULE hMemMod){
	LogA("in IsMemModLoad_ByMemHand");
	if (!hMemMod)
		return false;
	std::list<HMEMORYMODULE>::iterator it = std::find(listMemMod.begin(), listMemMod.end(), hMemMod);
	if (it == listMemMod.end())
		return false;
	return true;
}
LPVOID GetHMemModBase(HMEMORYMODULE hMemModHandle){
	LogA("in GetHMemModBase");
	if (!hMemModHandle)
		return 0;
	for (std::list<HMEMORYMODULE>::iterator it = listMemMod.begin(); it != listMemMod.end(); it++)
	{
		PMEMORYMODULE pMemMod = (PMEMORYMODULE)*it;
		if (hMemModHandle == *it)
			return ((PMEMORYMODULE)*it)->codeBase;

	}
	return 0;
}
//typedef std::list<HMEMORYRSRC> ListMemRsrc;
bool AddMemRsrc(HMEMORYRSRC hMemRsrc){
	LogA("in %s",__FUNCTION__);
	if (!hMemRsrc)
		return false;
	std::list<HMEMORYRSRC>::iterator it = std::find(listMemRsrc.begin(), listMemRsrc.end(), hMemRsrc);
	if (it != listMemRsrc.end())
		return false;
	listMemRsrc.push_back(hMemRsrc);
	return true;
}
bool RemoveMemRsrc(HMEMORYRSRC hMemRsrc){
	LogA("in %s", __FUNCTION__);
	if (!hMemRsrc)
		return false;
	std::list<HMEMORYRSRC>::iterator it = std::find(listMemRsrc.begin(), listMemRsrc.end(), hMemRsrc);
	if (it == listMemRsrc.end())
		return false;
	listMemRsrc.remove(hMemRsrc);
	return true;
}
bool IsMemRsrcLoad(HMEMORYRSRC hMemRsrc){
	LogA("in %s", __FUNCTION__);
	if (!hMemRsrc)
		return false;
	std::list<HMEMORYRSRC>::iterator it = std::find(listMemRsrc.begin(), listMemRsrc.end(), hMemRsrc);
	if (it == listMemRsrc.end())
		return false;
	return true;
}


// why not hook the iat ? because if you call 3rd dll and the 3rd dll maybe call we care fuctions
//--
// need fix
//*GetAny_temp 函数应该管理一个列表
//*hk_GetModuleHandleExA 中应该判断lpModuleName的指针指向是地址还是字串
typedef HMODULE (WINAPI *PF_GetModuleHandleA)(LPCSTR lpModuleName);
PF_GetModuleHandleA pPF_GetModuleHandleA = 0;
HANDLE WINAPI hk_GetModuleHandleA(LPCSTR lpModuleName){
	LogA("in %s", __FUNCTION__);
	if (!lpModuleName){
		HMEMORYMODULE	hMemMod = GetAny_temp();
			return hMemMod;
	}
	else{
		HANDLE hhh = pPF_GetModuleHandleA(lpModuleName);
			return hhh;
	}
}
//--
typedef HMODULE (WINAPI *PF_GetModuleHandleW)(LPCWSTR lpModuleName);
PF_GetModuleHandleW pPF_GetModuleHandleW = 0;
HANDLE WINAPI hk_GetModuleHandleW(LPCWSTR lpModuleName){
	LogA("in %s", __FUNCTION__);
	if (!lpModuleName)
	{
		HMEMORYMODULE	hMemMod = GetAny_temp();
		return hMemMod;
	}
	else
		return pPF_GetModuleHandleW(lpModuleName);
}
//--
typedef BOOL(WINAPI *PF_GetModuleHandleExA)(DWORD dwFlags, LPCSTR lpModuleName, HMODULE * phModule);
PF_GetModuleHandleExA pPF_GetModuleHandleExA = 0; 
BOOL WINAPI hk_GetModuleHandleExA(DWORD dwFlags, LPCSTR lpModuleName, HMODULE * phModule){
	LogA("in %s", __FUNCTION__);
	if (!lpModuleName)
	{
		HMEMORYMODULE	hMemMod = GetAny_temp();
		*phModule = (HMODULE)hMemMod;
		return TRUE;
	}
	else
		return pPF_GetModuleHandleExA(dwFlags, lpModuleName, phModule);

}
//--
typedef BOOL(WINAPI *PF_GetModuleHandleExW)(DWORD dwFlags, LPCWSTR lpModuleName, HMODULE * phModule);
PF_GetModuleHandleExW pPF_GetModuleHandleExW = 0; 
BOOL WINAPI hk_GetModuleHandleExW(DWORD dwFlags, LPCWSTR lpModuleName, HMODULE * phModule){
	LogA("in %s", __FUNCTION__);
	if (!lpModuleName)
	{
		HMEMORYMODULE	hMemMod = GetAny_temp();
		*phModule = (HMODULE)hMemMod;
		return TRUE;
	}
	else
		return pPF_GetModuleHandleExW(dwFlags, lpModuleName, phModule);
}

// #define EXE_FILE ("C:\\Users\\Administrator\\Desktop\\netpass\\netpass_unpack.exe")
// #define EXE_FILE_W (L"C:\\Users\\Administrator\\Desktop\\netpass\\netpass_unpack.exe")
// #define EXE_FILE_dumy ("netpass_unpack.exed")
// #define EXE_FILE_W_dumy (L"netpass_unpack.exed")
// #define EXE_FILE ("netpass_unpack.exe")
// #define EXE_FILE_W (L"netpass_unpack.exe")

#define EXE_FILE_dumy ("C:\\Windows\\SysWOW64\\taskmgr.exed")
#define EXE_FILE_W_dumy (L"C:\\Windows\\SysWOW64\\taskmgr.exed")
#define EXE_FILE ("C:\\Windows\\SysWOW64\\taskmgr.exe")
#define EXE_FILE_W (L"C:\\Windows\\SysWOW64\\taskmgr.exe")

//--
typedef DWORD(WINAPI *PF_GetModuleFileNameA)(HMODULE hModule, LPSTR lpFilename,DWORD nSize);
PF_GetModuleFileNameA pPF_GetModuleFileNameA = 0;
DWORD WINAPI hk_GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize){
	LogA("in %s", __FUNCTION__);
	if (!hModule){
		CHAR szBuffer[MAX_PATH];
		GetCurrentDirectoryA(MAX_PATH, szBuffer);
		strcpy(lpFilename, szBuffer);
		strcat(lpFilename, EXE_FILE_dumy);
		return sizeof(EXE_FILE_dumy);// fix me the size
	}
	return pPF_GetModuleFileNameA(hModule, lpFilename, nSize);
}
//--
typedef DWORD(WINAPI *PF_GetModuleFileNameW)(HMODULE hModule, LPWSTR lpFilename,DWORD nSize);
PF_GetModuleFileNameW pPF_GetModuleFileNameW = 0;
DWORD WINAPI hk_GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize){
	LogA("in %s", __FUNCTION__);
	if (!hModule){
		WCHAR szBuffer[MAX_PATH];
		GetCurrentDirectoryW(MAX_PATH, szBuffer);
		wcscpy(lpFilename, szBuffer);
		wcscat(lpFilename, EXE_FILE_W_dumy);
		return sizeof(EXE_FILE_W_dumy);
	}
	return pPF_GetModuleFileNameW(hModule, lpFilename, nSize);
}
//--
typedef DWORD(WINAPI *PF_GetModuleFileNameExA)(HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize);
PF_GetModuleFileNameExA pPF_GetModuleFileNameExA = 0;
DWORD WINAPI hk_GetModuleFileNameExA(HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize){
	LogA("in %s", __FUNCTION__);
	if (GetCurrentProcess() == hProcess && !hModule){
		strcpy(lpFilename, EXE_FILE_dumy);
		return sizeof(EXE_FILE_dumy);
	}
	return pPF_GetModuleFileNameExA(hProcess, hModule, lpFilename, nSize);
}
//--
typedef DWORD(WINAPI *PF_GetModuleFileNameExW)(HANDLE hProcess, HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
PF_GetModuleFileNameExW pPF_GetModuleFileNameExW = 0;
DWORD WINAPI hk_GetModuleFileNameExW(HANDLE hProcess, HMODULE hModule, LPWSTR lpFilename, DWORD nSize){
	LogA("in %s", __FUNCTION__);
	if (GetCurrentProcess() == hProcess && !hModule){
		DebugBreak();
		wcscpy(lpFilename, EXE_FILE_W_dumy);
		return sizeof(EXE_FILE_dumy);
	}

	return pPF_GetModuleFileNameExW(hProcess, hModule, lpFilename, nSize);
}
typedef FARPROC (WINAPI *PF_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
PF_GetProcAddress pPF_GetProcAddress = 0;
FARPROC WINAPI hk_GetProcAddress(HMODULE hModule, LPCSTR lpProcName){
	LogA("in %s", __FUNCTION__);
	return pPF_GetProcAddress(hModule, lpProcName);
}
//--- 
typedef HACCEL(WINAPI *PF_LoadAcceleratorsA)(HINSTANCE hInstance, LPCSTR lpTableName);
PF_LoadAcceleratorsA pPF_LoadAcceleratorsA = 0;
HACCEL WINAPI hk_LoadAcceleratorsA(HINSTANCE hInstance, LPCSTR lpTableName){
	LogA("in %s", __FUNCTION__);
	return pPF_LoadAcceleratorsA(hInstance, lpTableName);
}
typedef HACCEL(WINAPI *PF_LoadAcceleratorsW)(HINSTANCE hInstance, LPCWSTR lpTableName);
PF_LoadAcceleratorsW pPF_LoadAcceleratorsW = 0;
HACCEL WINAPI hk_LoadAcceleratorsW(HINSTANCE hInstance, LPCWSTR lpTableName){
	LogA("in %s", __FUNCTION__);
	return pPF_LoadAcceleratorsW(hInstance, lpTableName);
}
typedef HCURSOR (WINAPI *PF_LoadCursorA)(HINSTANCE hInstance,  LPCSTR lpCursorName);
PF_LoadCursorA pPF_LoadCursorA = 0;
HCURSOR WINAPI hk_LoadCursorA(HINSTANCE hInstance, LPCSTR lpCursorName){
	LogA("in %s", __FUNCTION__);
	return pPF_LoadCursorA(hInstance, lpCursorName);
}
typedef HCURSOR(WINAPI *PF_LoadCursorW)(HINSTANCE hInstance, LPCWSTR lpCursorName);
PF_LoadCursorW pPF_LoadCursorW = 0;
HCURSOR WINAPI hk_LoadCursorW(HINSTANCE hInstance, LPCWSTR lpCursorName){
	LogA("in %s", __FUNCTION__);
	return pPF_LoadCursorW(hInstance, lpCursorName);
}
typedef HICON(WINAPI *PF_LoadIconA)(HINSTANCE hInstance, LPCSTR lpIconName);
PF_LoadIconA pPF_LoadIconA = 0;
HICON WINAPI hk_LoadIconA(HINSTANCE hInstance, LPCSTR lpIconName){
	LogA("in %s", __FUNCTION__);
	return pPF_LoadIconA(hInstance, lpIconName);
}
typedef HICON(WINAPI *PF_LoadIconW)(HINSTANCE hInstance, LPCWSTR lpIconName);
PF_LoadIconW pPF_LoadIconW = 0;
HICON WINAPI hk_LoadIconW(HINSTANCE hInstance, LPCWSTR lpIconName){
	LogA("in %s", __FUNCTION__);
	return pPF_LoadIconW(hInstance, lpIconName);
}
typedef HANDLE (WINAPI *PF_LoadImageA)(HINSTANCE hInst, LPCSTR name, UINT type, int cx, int cy, UINT fuLoad);
PF_LoadImageA pPF_LoadImageA = 0;
HANDLE WINAPI hk_LoadImageA(HINSTANCE hInst, LPCSTR name, UINT type, int cx, int cy, UINT fuLoad){
	LogA("in %s", __FUNCTION__);
	return pPF_LoadImageA(hInst, name, type, cx, cy, fuLoad);
}
typedef HANDLE(WINAPI *PF_LoadImageW)(HINSTANCE hInst, LPCWSTR name, UINT type, int cx, int cy, UINT fuLoad);
PF_LoadImageW pPF_LoadImageW = 0;
HANDLE WINAPI hk_LoadImageW(HINSTANCE hInst, LPCWSTR name, UINT type, int cx, int cy, UINT fuLoad){
	LogA("in %s", __FUNCTION__);
	return pPF_LoadImageW(hInst, name, type, cx, cy, fuLoad);
}
typedef HMENU (WINAPI *PF_LoadMenuA)(HINSTANCE hInstance, LPCSTR lpMenuName);
PF_LoadMenuA pPF_LoadMenuA = 0;
HMENU WINAPI hk_LoadMenuA(HINSTANCE hInstance, LPCSTR lpMenuName){
	LogA("in %s", __FUNCTION__);
	return pPF_LoadMenuA(hInstance, lpMenuName);
}
typedef HMENU(WINAPI *PF_LoadMenuW)(HINSTANCE hInstance, LPCWSTR lpMenuName);
PF_LoadMenuW pPF_LoadMenuW = 0;
HMENU WINAPI hk_LoadMenuW(HINSTANCE hInstance, LPCWSTR lpMenuName){
	LogA("in %s", __FUNCTION__);
	return pPF_LoadMenuW(hInstance, lpMenuName);
}
// typedef HGLOBAL (WINAPI *PF_LoadResource)(HMODULE hModule, HRSRC hResInfo);
// PF_LoadResource pPF_LoadResource = 0;
// HGLOBAL WINAPI hk_LoadResource(HMODULE hModule, HRSRC hResInfo)
// {
// 	return pPF_LoadResource(hModule, hResInfo);
// }
typedef int (WINAPI *PF_LoadStringA)(HINSTANCE hInstance, UINT uID, LPSTR lpBuffer, int cchBufferMax);
PF_LoadStringA pPF_LoadStringA = 0;
int WINAPI hk_LoadStringA(HINSTANCE hInstance, UINT uID, LPSTR lpBuffer, int cchBufferMax){
	LogA("in %s", __FUNCTION__);
	return pPF_LoadStringA(hInstance, uID, lpBuffer, cchBufferMax);
}
typedef int (WINAPI *PF_LoadStringW)(HINSTANCE hInstance, UINT uID, LPWSTR lpBuffer, int cchBufferMax);
PF_LoadStringW pPF_LoadStringW = 0;
int WINAPI hk_LoadStringW(HINSTANCE hInstance, UINT uID, LPWSTR lpBuffer, int cchBufferMax){
	LogA("in %s", __FUNCTION__);
	return pPF_LoadStringW(hInstance, uID, lpBuffer, cchBufferMax);
}
typedef HMODULE (WINAPI *PF_LoadLibraryA)(LPCSTR lpLibFileName);
PF_LoadLibraryA pPF_LoadLibraryA = 0;
HMODULE WINAPI hk_LoadLibraryA(LPCSTR lpLibFileName){
	LogA("in %s", __FUNCTION__);
	return pPF_LoadLibraryA(lpLibFileName);
}
typedef HMODULE (WINAPI *PF_LoadLibraryW)(LPCWSTR lpLibFileName);
PF_LoadLibraryW pPF_LoadLibraryW = 0;
HMODULE WINAPI hk_LoadLibraryW(LPCWSTR lpLibFileName){
	LogA("in %s", __FUNCTION__);
	return pPF_LoadLibraryW(lpLibFileName);
}
typedef HMODULE (WINAPI *PF_LoadLibraryExA)(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
PF_LoadLibraryExA pPF_LoadLibraryExA = 0;
HMODULE WINAPI hk_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags){
	LogA("in %s", __FUNCTION__);
	return pPF_LoadLibraryExA(lpLibFileName, hFile, dwFlags);
}
typedef HMODULE(WINAPI *PF_LoadLibraryExW)(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
PF_LoadLibraryExW pPF_LoadLibraryExW = 0;
HMODULE WINAPI hk_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags){
	LogA("in %s", __FUNCTION__);
	return pPF_LoadLibraryExW(lpLibFileName, hFile, dwFlags);
}

//--------------- 简化处理
typedef HRSRC (WINAPI *PF_FindResourceA)(HMODULE hModule, LPCSTR lpName, LPCSTR lpType);
PF_FindResourceA pPF_FindResourceA = 0;
HRSRC WINAPI hk_FindResourceA(HMODULE hModule, LPCSTR lpName, LPCSTR lpType){
	LogA("in %s", __FUNCTION__);
	if (IsMemModLoad_ByBase(hModule)){
		HMEMORYMODULE hMemModHandle = GetHMemModHandle(hModule);
		// MemoryFindResource now proj set is mbcs
		HMEMORYRSRC hMemRsrc = MemoryFindResource(hMemModHandle, lpName, lpType);
		AddMemRsrc(hMemRsrc);
		return (HRSRC)hMemRsrc;
	}else
		return pPF_FindResourceA(hModule, lpName, lpType);
}
typedef HRSRC(WINAPI *PF_FindResourceW)(HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType);
PF_FindResourceW pPF_FindResourceW = 0;
HRSRC WINAPI hk_FindResourceW(HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType){
	LogA("in %s", __FUNCTION__);
	if (IsMemModLoad_ByBase(hModule)){
		HMEMORYMODULE hMemModHandle = GetHMemModHandle(hModule);
		// MemoryFindResource now proj set is mbcs
		LPVOID lpNameA = VirtualAlloc(NULL, wcslen(lpName) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		WideCharToMultiByte(CP_ACP, NULL, lpName, -1, (LPSTR)lpNameA, (int)wcslen(lpName) + 1, NULL, NULL);

		LPVOID lpTypeA = VirtualAlloc(NULL, wcslen(lpType) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		WideCharToMultiByte(CP_ACP, NULL, lpType, -1, (LPSTR)lpTypeA, (int)wcslen(lpType) + 1, NULL, NULL);

		HMEMORYRSRC hMemRsrc = MemoryFindResource(hMemModHandle, (LPCSTR)lpNameA, (LPCSTR)lpTypeA);
		AddMemRsrc(hMemRsrc);
		VirtualFree(lpNameA, NULL, MEM_RELEASE);
		VirtualFree(lpTypeA, NULL, MEM_RELEASE);
		return (HRSRC)hMemRsrc;
	}
	else
		return pPF_FindResourceW(hModule, lpName, lpType);
}
typedef HRSRC (WINAPI *PF_FindResourceExA)(HMODULE hModule, LPCSTR lpType, LPCSTR lpName, WORD wLanguage);
PF_FindResourceExA pPF_FindResourceExA = 0;
HRSRC WINAPI hk_FindResourceExA(HMODULE hModule, LPCSTR lpType, LPCSTR lpName, WORD wLanguage){
	LogA("in %s", __FUNCTION__);
	if (IsMemModLoad_ByBase(hModule)){
		HMEMORYMODULE hMemModHandle = GetHMemModHandle(hModule);
		// MemoryFindResource now proj set is mbcs
		HMEMORYRSRC hMemRsrc = MemoryFindResourceEx(hMemModHandle, lpName, lpType, wLanguage);
		AddMemRsrc(hMemRsrc);
		return (HRSRC)hMemRsrc;
	}
	else
		return pPF_FindResourceExA(hModule, lpType, lpName, wLanguage);
}
typedef HRSRC(WINAPI *PF_FindResourceExW)(HMODULE hModule, LPCWSTR lpType, LPCWSTR lpName, WORD wLanguage);
PF_FindResourceExW pPF_FindResourceExW = 0;
HRSRC WINAPI hk_FindResourceExW(HMODULE hModule, LPCWSTR lpType, LPCWSTR lpName, WORD wLanguage){
	LogA("in %s", __FUNCTION__);
	if (IsMemModLoad_ByBase(hModule)){
		HMEMORYMODULE hMemModHandle = GetHMemModHandle(hModule);
		HMEMORYRSRC hMemRsrc = MemoryFindResourceEx(hMemModHandle, (LPCSTR)lpName, (LPCSTR)lpType, wLanguage);
		AddMemRsrc(hMemRsrc);//--
		return (HRSRC)hMemRsrc;
	}
	else
		return pPF_FindResourceExW(hModule, lpType, lpName, wLanguage);
}
typedef DWORD (WINAPI *PF_SizeofResource)(HMODULE hModule, HRSRC hResInfo);
PF_SizeofResource pPF_SizeofResource = 0;
DWORD WINAPI hk_SizeofResource(HMODULE hModule, HRSRC hResInfo){
	LogA("in %s", __FUNCTION__);
	if (IsMemModLoad_ByBase(hModule)){
		HMEMORYMODULE hMemModHandle = GetHMemModHandle(hModule);
		if (IsMemRsrcLoad(hResInfo)){
			DWORD dwSize = MemorySizeofResource(hMemModHandle, hResInfo);
			return dwSize;
		}
	}
	else
		return pPF_SizeofResource(hModule, hResInfo);
}

typedef HGLOBAL(WINAPI *PF_LoadResource)(HMODULE hModule, HRSRC hResInfo);
PF_LoadResource pPF_LoadResource = 0;
HGLOBAL WINAPI hk_LoadResource(HMODULE hModule, HRSRC hResInfo){
	LogA("in %s", __FUNCTION__);
	if (IsMemModLoad_ByBase(hModule)){
		HMEMORYMODULE hMemModHandle = GetHMemModHandle(hModule);
		if (IsMemRsrcLoad(hResInfo)){
			LPVOID hRes = MemoryLoadResource(hMemModHandle, hResInfo);
			AddResHand(hRes);
			return hRes;
		}
	}
	else
		return pPF_LoadResource(hModule, hResInfo);
}
typedef LPVOID (WINAPI *PF_LockResource)(HGLOBAL hResData);
PF_LockResource pPF_LockResource = 0;
LPVOID WINAPI hk_LockResource(HGLOBAL hResData){
	LogA("in %s", __FUNCTION__);
	if (IsResHandLoad(hResData)){
		//DebugBreak();// do what ? fix me
		return hResData;
	}
	else
		return pPF_LockResource(hResData);
}
typedef BOOL (WINAPI *PF_FreeResource)(HGLOBAL hResData);
PF_FreeResource pPF_FreeResource = 0;
BOOL WINAPI hk_FreeResource(HGLOBAL hResData){
	LogA("in %s", __FUNCTION__);
	if (IsResHandLoad(hResData)){
		RemoveResHand(hResData);
		//DebugBreak();// add mem free ? fix me
		return TRUE;
	}
	else
		return pPF_FreeResource(hResData);
}
typedef BOOL (WINAPI *PF_EnumResourceTypesA)(HMODULE hModule, ENUMRESTYPEPROCA lpEnumFunc, LONG_PTR lParam);
PF_EnumResourceTypesA pPF_EnumResourceTypesA = 0;
BOOL WINAPI hk_EnumResourceTypesA(HMODULE hModule, ENUMRESTYPEPROCA lpEnumFunc, LONG_PTR lParam){
	LogA("in %s", __FUNCTION__);
	return pPF_EnumResourceTypesA(hModule, lpEnumFunc, lParam);
}
typedef BOOL(WINAPI *PF_EnumResourceTypesW)(HMODULE hModule, ENUMRESTYPEPROCW lpEnumFunc, LONG_PTR lParam);
PF_EnumResourceTypesW pPF_EnumResourceTypesW = 0;
BOOL WINAPI hk_EnumResourceTypesW(HMODULE hModule, ENUMRESTYPEPROCW lpEnumFunc, LONG_PTR lParam){
	LogA("in %s", __FUNCTION__);
	return pPF_EnumResourceTypesW(hModule, lpEnumFunc, lParam);
}

typedef BOOL (WINAPI *PF_EnumResourceNamesA)(HMODULE hModule, LPCSTR lpType, ENUMRESNAMEPROCA lpEnumFunc, LONG_PTR lParam);
PF_EnumResourceNamesA pPF_EnumResourceNamesA = 0;
BOOL WINAPI hk_EnumResourceNamesA(HMODULE hModule, LPCSTR lpType, ENUMRESNAMEPROCA lpEnumFunc, LONG_PTR lParam){
	LogA("in %s", __FUNCTION__);
	return pPF_EnumResourceNamesA(hModule, lpType, lpEnumFunc, lParam);
}
typedef BOOL(WINAPI *PF_EnumResourceNamesW)(HMODULE hModule, LPCWSTR lpType, ENUMRESNAMEPROCW lpEnumFunc, LONG_PTR lParam);
PF_EnumResourceNamesW pPF_EnumResourceNamesW = 0;
BOOL WINAPI hk_EnumResourceNamesW(HMODULE hModule, LPCWSTR lpType, ENUMRESNAMEPROCW lpEnumFunc, LONG_PTR lParam){
	LogA("in %s", __FUNCTION__);
	return pPF_EnumResourceNamesW(hModule, lpType, lpEnumFunc, lParam);
}
typedef VOID (WINAPI *PF_ExitProcess)(UINT uExitCode);
PF_ExitProcess pPF_ExitProcess = 0;
VOID WINAPI hk_ExitProcess(UINT uExitCode){
	LogA("in %s", __FUNCTION__);
	pPF_ExitProcess(uExitCode);
}
//--------------- 简化处理 end
//for hide windows
typedef HWND (WINAPI *PF_CreateWindowExA)(DWORD dwExStyle,LPCSTR lpClassName,LPCSTR lpWindowName,DWORD dwStyle,
int X,int Y,int nWidth,int nHeight,HWND hWndParent,HMENU hMenu,HINSTANCE hInstance,LPVOID lpParam);
PF_CreateWindowExA pPF_CreateWindowExA = 0;

bool bHide = true;
HWND WINAPI hk_CreateWindowExA(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle,
	int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam){
	LogA("in %s", __FUNCTION__);
	if (bHide){
		if (lpClassName && 0 == strcmp(lpClassName, "NetPass")){
			dwExStyle = dwExStyle | WS_EX_TOOLWINDOW;
			//dwStyle = dwStyle |~WS_VISIBLE; 
		}

	}

	HWND hWnd = pPF_CreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle,
		X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);

	return hWnd;
}
typedef BOOL (WINAPI *PF_ShowWindow)(HWND hWnd, int nCmdShow);
PF_ShowWindow pPF_ShowWindow = 0;
BOOL WINAPI hk_ShowWindow(HWND hWnd, int nCmdShow){
	LogA("in %s", __FUNCTION__);
	if (bHide){
		return pPF_ShowWindow(hWnd, SW_HIDE);
	}
	else{
		return pPF_ShowWindow(hWnd, nCmdShow);	
	}
}


typedef HWND(WINAPI *PF_CreateWindowExW)(DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle,
	int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam);
PF_CreateWindowExW pPF_CreateWindowExW = 0;
HWND WINAPI hk_CreateWindowExW(DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle,
	int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam){
	LogA("in %s", __FUNCTION__);
// 	if (lpClassName && 0 == wcscmp(lpClassName, L"Netpass"))
// 		dwExStyle = WS_EX_NOACTIVATE;

	return pPF_CreateWindowExW(dwExStyle, lpClassName, lpWindowName, dwStyle,
		X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}
typedef LRESULT (WINAPI *PF_SendMessageA)(HWND hWnd,UINT Msg,WPARAM wParam,LPARAM lParam);
PF_SendMessageA pPF_SendMessageA = 0;
LRESULT WINAPI hk_SendMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam){
	LogA("in %s", __FUNCTION__);
	if (LVM_SETITEMTEXTA == Msg){
		LPLVITEMA pItem = (LPLVITEMA)lParam;
		Buffer2FileAdd("test2.txt", (char*)pItem->pszText, strlen(pItem->pszText));
		Buffer2FileAdd("test2.txt", "\r\n", 2);
		return pPF_SendMessageA(hWnd, Msg, wParam, lParam);
	}
	return pPF_SendMessageA(hWnd, Msg, wParam, lParam);
}
typedef LRESULT(WINAPI *PF_SendMessageW)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
PF_SendMessageW pPF_SendMessageW = 0;
LRESULT WINAPI hk_SendMessageW(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam){
	LogA("in %s", __FUNCTION__);
	if (LVM_SETITEMTEXTW == Msg){
		LPLVITEMW pItem = (LPLVITEMW)lParam;
		// should chge to mbcs and write. fix me
		Buffer2FileAdd("test3.txt", (char*)pItem->pszText, wcslen(pItem->pszText));
		Buffer2FileAdd("test3.txt", "\r\n", 2);
		return pPF_SendMessageW(hWnd, Msg, wParam, lParam);// ListView_SetItemText
	}
	return pPF_SendMessageW(hWnd, Msg, wParam, lParam); //DrawTextW
}


//SetWindowTextA
// ListView_SetItemText
// SendMessage



// hide windows end

void hook(){
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)(pPF_CreateWindowExA = CreateWindowExA), hk_CreateWindowExA);
	DetourAttach(&(PVOID&)(pPF_CreateWindowExW = CreateWindowExW), hk_CreateWindowExW);
	DetourAttach(&(PVOID&)(pPF_ShowWindow = ShowWindow), hk_ShowWindow);
	DetourAttach(&(PVOID&)(pPF_SendMessageA = SendMessageA), hk_SendMessageA);
	DetourAttach(&(PVOID&)(pPF_SendMessageW = SendMessageW), hk_SendMessageW);


	DetourAttach(&(PVOID&)(pPF_GetModuleHandleA = GetModuleHandleA), hk_GetModuleHandleA);
	DetourAttach(&(PVOID&)(pPF_GetModuleHandleW = GetModuleHandleW), hk_GetModuleHandleW);
	DetourAttach(&(PVOID&)(pPF_GetModuleHandleExA = GetModuleHandleExA), hk_GetModuleHandleExA);
	DetourAttach(&(PVOID&)(pPF_GetModuleHandleExW = GetModuleHandleExW), hk_GetModuleHandleExW);

	DetourAttach(&(PVOID&)(pPF_GetModuleFileNameA = GetModuleFileNameA), hk_GetModuleFileNameA);
	DetourAttach(&(PVOID&)(pPF_GetModuleFileNameW = GetModuleFileNameW), hk_GetModuleFileNameW);
// 	DetourAttach(&(PVOID&)(pPF_GetModuleFileNameExA = GetModuleFileNameExA), hk_GetModuleFileNameExA);
// 	DetourAttach(&(PVOID&)(pPF_GetModuleFileNameExW = GetModuleFileNameExW), hk_GetModuleFileNameExW);

	DetourAttach(&(PVOID&)(pPF_GetProcAddress = GetProcAddress), hk_GetProcAddress);
	DetourAttach(&(PVOID&)(pPF_LoadAcceleratorsA = LoadAcceleratorsA), hk_LoadAcceleratorsA);
	DetourAttach(&(PVOID&)(pPF_LoadAcceleratorsW = LoadAcceleratorsW), hk_LoadAcceleratorsW);
	DetourAttach(&(PVOID&)(pPF_LoadCursorA = LoadCursorA), hk_LoadCursorA);
	DetourAttach(&(PVOID&)(pPF_LoadCursorW = LoadCursorW), hk_LoadCursorW);
	DetourAttach(&(PVOID&)(pPF_LoadIconA = LoadIconA), hk_LoadIconA);
	DetourAttach(&(PVOID&)(pPF_LoadIconW = LoadIconW), hk_LoadIconW);
	DetourAttach(&(PVOID&)(pPF_LoadImageA = LoadImageA), hk_LoadImageA);
	DetourAttach(&(PVOID&)(pPF_LoadImageW = LoadImageW), hk_LoadImageW);
	DetourAttach(&(PVOID&)(pPF_LoadMenuA = LoadMenuA), hk_LoadMenuA);
	DetourAttach(&(PVOID&)(pPF_LoadMenuW = LoadMenuW), hk_LoadMenuW);
// 	DetourAttach(&(PVOID&)(pPF_LoadResource = LoadResource), hk_LoadResource);
	DetourAttach(&(PVOID&)(pPF_LoadStringA = LoadStringA), hk_LoadStringA);
	DetourAttach(&(PVOID&)(pPF_LoadStringW = LoadStringW), hk_LoadStringW);
	DetourAttach(&(PVOID&)(pPF_LoadLibraryA = LoadLibraryA), hk_LoadLibraryA);
	DetourAttach(&(PVOID&)(pPF_LoadLibraryW = LoadLibraryW), hk_LoadLibraryW);
	DetourAttach(&(PVOID&)(pPF_LoadLibraryExA = LoadLibraryExA), hk_LoadLibraryExA);
	DetourAttach(&(PVOID&)(pPF_LoadLibraryExW = LoadLibraryExW), hk_LoadLibraryExW);

	DetourAttach(&(PVOID&)(pPF_FindResourceA = FindResourceA), hk_FindResourceA);
	DetourAttach(&(PVOID&)(pPF_FindResourceW = FindResourceW), hk_FindResourceW);
	DetourAttach(&(PVOID&)(pPF_FindResourceExA = FindResourceExA), hk_FindResourceExA);
	DetourAttach(&(PVOID&)(pPF_FindResourceExW = FindResourceExW), hk_FindResourceExW);
	DetourAttach(&(PVOID&)(pPF_SizeofResource = SizeofResource), hk_SizeofResource);
	DetourAttach(&(PVOID&)(pPF_LoadResource = LoadResource), hk_LoadResource);
	DetourAttach(&(PVOID&)(pPF_LockResource = LockResource), hk_LockResource);
	DetourAttach(&(PVOID&)(pPF_FreeResource = FreeResource), hk_FreeResource);

	DetourAttach(&(PVOID&)(pPF_EnumResourceTypesA = EnumResourceTypesA), hk_EnumResourceTypesA);
	DetourAttach(&(PVOID&)(pPF_EnumResourceTypesW = EnumResourceTypesW), hk_EnumResourceTypesW);
	DetourAttach(&(PVOID&)(pPF_EnumResourceNamesA = EnumResourceNamesA), hk_EnumResourceNamesA);
	DetourAttach(&(PVOID&)(pPF_EnumResourceNamesW = EnumResourceNamesW), hk_EnumResourceNamesW);
	DetourAttach(&(PVOID&)(pPF_ExitProcess = ExitProcess), hk_ExitProcess);

	DetourTransactionCommit();
}
void unhook(){
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)pPF_CreateWindowExA, hk_CreateWindowExA);
	DetourDetach(&(PVOID&)pPF_CreateWindowExW, hk_CreateWindowExW);
	DetourDetach(&(PVOID&)pPF_ShowWindow, hk_ShowWindow);
	DetourDetach(&(PVOID&)pPF_SendMessageA, hk_SendMessageA);
	DetourDetach(&(PVOID&)pPF_SendMessageW, hk_SendMessageW);


	DetourDetach(&(PVOID&)pPF_GetModuleHandleA, hk_GetModuleHandleA);
	DetourDetach(&(PVOID&)pPF_GetModuleHandleW, hk_GetModuleHandleW);
	DetourDetach(&(PVOID&)pPF_GetModuleHandleExA, hk_GetModuleHandleExA);
	DetourDetach(&(PVOID&)pPF_GetModuleHandleExW, hk_GetModuleHandleExW);

	DetourDetach(&(PVOID&)pPF_GetModuleFileNameA, hk_GetModuleFileNameA);
	DetourDetach(&(PVOID&)pPF_GetModuleFileNameW, hk_GetModuleFileNameW);
// 	DetourDetach(&(PVOID&)pPF_GetModuleFileNameExA, hk_GetModuleFileNameExA);
// 	DetourDetach(&(PVOID&)pPF_GetModuleFileNameExW, hk_GetModuleFileNameExW);

	DetourDetach(&(PVOID&)pPF_GetProcAddress , hk_GetProcAddress);
	DetourDetach(&(PVOID&)pPF_LoadAcceleratorsA , hk_LoadAcceleratorsA);
	DetourDetach(&(PVOID&)pPF_LoadAcceleratorsW , hk_LoadAcceleratorsW);
	DetourDetach(&(PVOID&)pPF_LoadCursorA , hk_LoadCursorA);
	DetourDetach(&(PVOID&)pPF_LoadCursorW , hk_LoadCursorW);
	DetourDetach(&(PVOID&)pPF_LoadIconA , hk_LoadIconA);
	DetourDetach(&(PVOID&)pPF_LoadIconW , hk_LoadIconW);
	DetourDetach(&(PVOID&)pPF_LoadImageA , hk_LoadImageA);
	DetourDetach(&(PVOID&)pPF_LoadImageW , hk_LoadImageW);
	DetourDetach(&(PVOID&)pPF_LoadMenuA , hk_LoadMenuA);
	DetourDetach(&(PVOID&)pPF_LoadMenuW , hk_LoadMenuW);
// 	DetourDetach(&(PVOID&)pPF_LoadResource , hk_LoadResource);
	DetourDetach(&(PVOID&)pPF_LoadStringA , hk_LoadStringA);
	DetourDetach(&(PVOID&)pPF_LoadStringW , hk_LoadStringW);
	DetourDetach(&(PVOID&)pPF_LoadLibraryA , hk_LoadLibraryA);
	DetourDetach(&(PVOID&)pPF_LoadLibraryW , hk_LoadLibraryW);
	DetourDetach(&(PVOID&)pPF_LoadLibraryExA , hk_LoadLibraryExA);
	DetourDetach(&(PVOID&)pPF_LoadLibraryExW , hk_LoadLibraryExW);

	DetourDetach(&(PVOID&)pPF_FindResourceA, hk_FindResourceA);
	DetourDetach(&(PVOID&)pPF_FindResourceW, hk_FindResourceW);
	DetourDetach(&(PVOID&)pPF_FindResourceExA, hk_FindResourceExA);
	DetourDetach(&(PVOID&)pPF_FindResourceExW, hk_FindResourceExW);
	DetourDetach(&(PVOID&)pPF_SizeofResource, hk_SizeofResource);
	DetourDetach(&(PVOID&)pPF_LoadResource, hk_LoadResource);
	DetourDetach(&(PVOID&)pPF_LockResource, hk_LockResource);
	DetourDetach(&(PVOID&)pPF_FreeResource, hk_FreeResource);

	DetourDetach(&(PVOID&)pPF_EnumResourceTypesA, hk_EnumResourceTypesA);
	DetourDetach(&(PVOID&)pPF_EnumResourceTypesW, hk_EnumResourceTypesW);
	DetourDetach(&(PVOID&)pPF_EnumResourceNamesA, hk_EnumResourceNamesA);
	DetourDetach(&(PVOID&)pPF_EnumResourceNamesW, hk_EnumResourceNamesW);
	DetourDetach(&(PVOID&)pPF_ExitProcess, hk_ExitProcess);

	DetourTransactionCommit();
}

//GetModuleHandleA  --> GetModuleHandleW --> GetModuleHandleExW ,(GetModuleHandleExA   no test)
//some times its this call list , but not all the time, so, you must hook them all (4 functions)
//

// GetModuleFileNameExA  not call GetModuleFileNameExW
// GetModuleFileNameA  not call  GetModuleFileNameW
// so, you must hook  that all 4 functions

static LPVOID g_pMemEXE = 0;
LPVOID MemoryMyAlloc(LPVOID address, SIZE_T size, DWORD allocationType, DWORD protect, void* userdata){
	UNREFERENCED_PARAMETER(userdata);
	if ((LPVOID)0x400000 == address){
		return g_pMemEXE;
	}
	if ((LPVOID)0x400000 <= address && (char*)address + size <= (char*)0x400000 + 1024*1024*5){
		return address;
	}
	return VirtualAlloc(address, size, allocationType, protect);
}
HMEMORYMODULE LoadMemExe(char* data, long size){

	HMEMORYMODULE handle;

	//handle = MemoryLoadLibrary(data, size);
	handle = MemoryLoadLibraryEx(data, size, MemoryDefaultAlloc, MemoryDefaultFree, MemoryDefaultLoadLibrary,
		MemoryDefaultGetProcAddress, MemoryDefaultFreeLibrary, NULL);

	if (handle == NULL)
	{
		_tprintf(_T("Can't load library from memory.\n"));
		return 0;
	}
	AddMemMod(handle);
	return handle;
}
extern "C" __declspec(dllexport) int WINAPI WaitAndExit(LPVOID lpReserved){
	Sleep(3000);
	ExitProcess(0);
}
extern "C" LPVOID lpMyReserved = 0;
#include <psapi.h>
char ExeMod[] = {
#ifdef _WIN64
#include "G:\dev_code\metape_data\netpass-x64\netpass.exe.txt"
#else
#include "G:\dev_code_x\patchframe\LdrEx\netpass_unpack.txt"
#endif
};
int iExeModLen = sizeof(ExeMod);
extern "C" __declspec(dllexport) int WINAPI Run(LPVOID lpMemExeAddr){



	char *data;
	long size;
// 	data = (char*)ReadLibrary(&size, EXE_FILE);
// 	if (data)
// 	{
		//HMEMORYMODULE hMemMod = LoadMemExe(data, size);
		for (int i = 0; i < iExeModLen; i++)
		{
			ExeMod[i] = ExeMod[i] ^ 'x';
		}

		HMEMORYMODULE hMemMod = LoadMemExe(ExeMod, iExeModLen);
// 		LPVOID pBase = MemryModuleGetBase(hMemMod);
// 		DWORD  nSize = MemryModuleGetSize(hMemMod);
// 		LogA("in run, pBase:%p,nSize:0x%x ",pBase,nSize);
// 		Buffer2File("dump.data", pBase, nSize);
		hook();
		if (IsMemModLoad_ByMemHand(hMemMod)){
			CloseHandle(CreateThread(NULL, 8192, (LPTHREAD_START_ROUTINE)WaitAndExit, 0, 0, 0));
			MemoryCallEntryPoint(hMemMod);
		}

		// 	MemoryFreeLibrary(hMemMod);
		unhook();
// 	}

	return 0;


	// for test
	HMODULE hMod = 0;
	GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, L"kernel32.dll",&hMod);
	GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, "kernel32.dll", &hMod);
	hMod = GetModuleHandleW(L"kernel32.dll");
	hMod = GetModuleHandleA("kernel32.dll");

	HMODULE xx = GetModuleHandleA("psapi.dll");
	{
		WCHAR BufferW[MAX_PATH];
		GetModuleFileNameExW(GetCurrentProcess(), hMod, BufferW, sizeof(BufferW)* sizeof(WCHAR));
		CHAR Buffer[MAX_PATH];
		GetModuleFileNameExA(GetCurrentProcess(), hMod, Buffer, sizeof(BufferW)* sizeof(CHAR));

		GetModuleFileNameW(hMod, BufferW, sizeof(BufferW)* sizeof(WCHAR));
		GetModuleFileNameA(hMod, Buffer, sizeof(BufferW)* sizeof(CHAR));

	}


	return 0;
}
bool isRuning(LPVOID lpReserved)
{
	typedef struct _procstruct
	{
		//int isFirstCalled;
		HMODULE passMod;
		//char *path;
		int CmdLine;
		void * dllAddr;
		int dllSize;
		HANDLE msg_event;

	}ProcStruct, *PProcStruct;

	HANDLE mutex = ::CreateMutex(NULL, FALSE, "f5DSbklsFkw14X_mutex");//随便敲的
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		SetEvent(((PProcStruct)lpReserved)->msg_event);
		if (mutex != NULL)
		{
			CloseHandle(mutex);
			mutex = NULL;
		}
		return true;
	}
	return false;
}

void StartRun(LPVOID lpReserved)
{

	CloseHandle(CreateThread(NULL, 8192, (LPTHREAD_START_ROUTINE)Run, (LPVOID)lpReserved, 0, 0));
	//CloseHandle(CreateThread(NULL, 8192, (LPTHREAD_START_ROUTINE)GetTableText, (LPVOID)lpReserved, 0, 0));
	return;
}