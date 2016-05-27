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

void OutputA(const char * strOutputString, ...);
void OutputW(const wchar_t * strOutputString, ...);

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

typedef struct  {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR  Buffer;
} ANSI_STRING, *PANSI_STRING;
typedef struct  {
	USHORT Length;
	USHORT MaximumLength;
	PWCHAR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
extern "C" IMAGE_DOS_HEADER __ImageBase;
#endif //__TOOLS_H____h_