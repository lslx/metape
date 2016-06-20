#include "Tools.h"
#include <windows.h>
#include <Shlwapi.h>
#include <regex>


#if 0

	void log(char* str, char* at)
	{
		FILE *pFile = NULL;
		fopen_s(&pFile, "log.txt", "a+");
		if (!pFile)
		{
			printf("log error.......\n");
		}

		char* buf = (char*)malloc(1024);
		if (!buf)
		{
			return;
		}
		strcpy_s(buf, 1024, at);
		strcat_s(buf, 1024, str);
		strcat_s(buf, 1024, "\r\n");
		fwrite(buf, 1, sizeof(buf), pFile);

		//std::string temp;
		//temp.assign(at);
		////temp.assign(buf);
		//temp.append(str);
		//temp.append("\r\n");
		//if (!temp.empty())
		//{
		//	fwrite(temp.c_str(), 1, temp.size(), pFile);
		//}

		fclose(pFile);
	}
#endif


void log(std::string str, char* at)
	{
		std::ofstream ofs("log.txt", std::ios::app);
		if (at)
		{
			ofs << at;
		}
		if (!str.empty())
		{
			ofs << str.c_str() << "\r\n";
		}
		ofs.close();
	}

void OutputA(const char * strOutputString, ...)
{
	char strBuffer[4096] = { 0 };
	va_list vlArgs;
	va_start(vlArgs, strOutputString);
	_vsnprintf_s(strBuffer, sizeof(strBuffer)-1, strOutputString, vlArgs);
	va_end(vlArgs);
	OutputDebugStringA(strBuffer);
}
void OutputW(const wchar_t * strOutputString, ...)
{
	wchar_t strBuffer[4096] = { 0 };
	va_list vlArgs;
	va_start(vlArgs, strOutputString);
	_vsnwprintf_s(strBuffer, sizeof(strBuffer)-1, strOutputString, vlArgs);
	va_end(vlArgs);
	OutputDebugStringW(strBuffer);
}

bool IsLoadByShellcode()
{
	MEMORY_BASIC_INFORMATION memInfo;
	if (VirtualQueryEx(GetCurrentProcess(), (LPVOID)&IsLoadByShellcode, &memInfo, sizeof(memInfo))){
		if (memInfo.Type == MEM_IMAGE)
			return false;
	}
	return true;
}
void ByteAlign(std::string& strOutShellCode)
{
	size_t len = strOutShellCode.size();
	size_t lenAdd = 8 - len % 8;
	if (lenAdd > 0){
		std::string strAddData;
		strAddData.assign(lenAdd, '\0');
		strOutShellCode += strAddData;
	}
}
bool ReadBinFile(const std::string& strFile, std::string& strData)
{
	log("Entry ReadBinFile", AT);

	std::ifstream ifile(strFile, std::ifstream::binary);
	if (!ifile.is_open())
		return false;
	ifile.seekg(0, ifile.end);
	std::streamoff len = ifile.tellg();
	ifile.seekg(0, ifile.beg);
	strData.clear();
	strData.reserve((int)len);
	strData.assign(std::istreambuf_iterator<char>(ifile), std::istreambuf_iterator<char>());
	ifile.close();
	return (len == strData.size());
}
bool WriteBinFile(const std::string& strFile, std::string& strData){
	std::ofstream ofile(strFile, std::ifstream::binary);
	if (!ofile.is_open())
		return false;
	ofile.write(strData.data(), strData.size());
	std::streamoff len = ofile.tellp();
	ofile.close();
	return (len == strData.size());
}
std::wstring GetAppPathW()//含有反斜杠
{
	std::wstring strAppPath; // 保存结果
	WCHAR szModuleFileName[MAX_PATH]; // 全路径名
	WCHAR drive[_MAX_DRIVE]; // 盘符名称
	WCHAR dir[_MAX_DIR]; // 目录
	WCHAR fname[_MAX_FNAME]; // 进程名字
	WCHAR ext[_MAX_EXT]; //后缀，一般为exe或者是dll
	if (NULL == GetModuleFileNameW(NULL, szModuleFileName, MAX_PATH)) //获得当前进程的文件路径
		return L"";
	_wsplitpath_s(szModuleFileName, drive, dir, fname, ext); //分割该路径，得到盘符，目录，文件名，后缀名
	strAppPath = drive;
	strAppPath += dir;
	return strAppPath;
}
std::string GetAppPathA(){
	char cache_buf[_MAX_PATH];
	std::wstring conv_path = GetAppPathW();
	WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, conv_path.c_str(), -1, cache_buf, sizeof(cache_buf), NULL, NULL);
	std::string result = cache_buf;
	return result;
}
std::wstring GetAppPathNameW()//含有反斜杠
{
	WCHAR szModuleFileName[MAX_PATH]; // 全路径名
	if (NULL == GetModuleFileNameW(NULL, szModuleFileName, MAX_PATH)) //获得当前进程的文件路径
		return L"";
	return szModuleFileName;
}
std::string GetAppPathNameA(){
	char cache_buf[_MAX_PATH];
	std::wstring conv_path = GetAppPathNameW();
	WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, conv_path.c_str(), -1, cache_buf, sizeof(cache_buf), NULL, NULL);
	std::string result = cache_buf;
	return result;
}
std::map<std::string, std::string> ParsePathFileA(const char* szPathFile){
	char drive[_MAX_DRIVE] = { 0 };
	char dir[_MAX_DIR] = { 0 };
	char fname[_MAX_FNAME] = { 0 };
	char ext[_MAX_EXT] = { 0 };
	_splitpath_s(szPathFile, drive, sizeof(drive) / sizeof(char),
		dir, sizeof(dir) / sizeof(char), fname, sizeof(fname) / sizeof(char),
		ext, sizeof(ext) / sizeof(char));

	std::map<std::string, std::string> mapPath;
	mapPath["drive"] = drive;
	mapPath["dir"] = dir;
	mapPath["fname"] = fname;
	mapPath["ext"] = ext;
	return mapPath;
}
std::map<std::string, std::string> ParsePathFileA(const std::string& strPathFile){
	return ParsePathFileA(strPathFile.c_str());
}
std::string BuildPathFileA(std::map<std::string, std::string>& mapPathFile){
	//mapPathFile.count("drive");
	std::string strPathFile;
	strPathFile = mapPathFile["drive"] + "\\";
	if (1 == mapPathFile.count("dir"))
		strPathFile += mapPathFile["dir"]+ "\\";
	strPathFile += mapPathFile["fname"] + mapPathFile["ext"];

	return strPathFile;
}
void buildCmdLineStr(int argc, char* argv[], std::string& strOutCmdLine)
{
	strOutCmdLine.clear();
	int iCmdLnBufLen = 0;
	iCmdLnBufLen += sizeof(int)* 2;
	for (int i = 0; i < argc; i++){
		for (int j = 0; argv[i][j]; j++){
			iCmdLnBufLen++;
		}
		iCmdLnBufLen++;
	}
	char* pBuf = new char[iCmdLnBufLen];
	StCmdLinePass* pStCmdLinePass = (StCmdLinePass*)pBuf;
	pStCmdLinePass->iLen = sizeof(int)* 2 + iCmdLnBufLen;
	pStCmdLinePass->iArgc = argc;
	for (int i = 0, ix = 0; i < argc; i++){
		int j = 0;
		for (; argv[i][j]; j++){
			pStCmdLinePass->szsCmdLines[ix++] = argv[i][j];
		}
		pStCmdLinePass->szsCmdLines[ix++] = argv[i][j];
	}
	strOutCmdLine.assign(pBuf, iCmdLnBufLen);
	delete[]pBuf;
}
void parseCmdLine(char* pCmdLine, std::vector<std::string>& vecCmdLine)
{
	std::string strCmdLine = pCmdLine;//after -
	if ('"' == strCmdLine.c_str()[strCmdLine.size() - 1])
		strCmdLine = strCmdLine.substr(1, strCmdLine.size() - 2);
	for (size_t argvStartPos = 0, argvEndPos = 0; argvStartPos < strCmdLine.size();)
	{
		if ('"' == strCmdLine.c_str()[argvStartPos]){
			argvEndPos = strCmdLine.find('"', argvStartPos);
		}
		else{
			argvEndPos = strCmdLine.find(' ', argvStartPos);
		}
		std::string strArgvx = strCmdLine.substr(argvStartPos, argvEndPos - argvStartPos);
		vecCmdLine.push_back(strArgvx);
		if (std::string::npos == argvEndPos)
			break;
		argvStartPos = argvEndPos + 1;
	}
}
bool RegSet(unsigned long hPreKey, const std::wstring& strSubPath, const std::wstring& strName, const std::wstring& strValue)
{
	log("Entry RegSet Do IFEO", AT);

	bool bRet = false;
	HKEY hKey = 0;
	DWORD state = 0;     //   RegCreateKeyExW 可连续创建
	if (ERROR_SUCCESS == RegCreateKeyExW((HKEY)hPreKey, strSubPath.c_str(), 0, 0, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, 0, &hKey, &state))
	{
		if (ERROR_SUCCESS == RegSetValueExW(hKey, strName.c_str(), 0, REG_SZ, (BYTE*)strValue.c_str(), (DWORD)strValue.size() * 2)){
			bRet = true;
		}
		RegCloseKey(hKey);
	}
	return bRet;
}
bool RegGet(unsigned long hPreKey, const std::wstring& strSubPath, const std::wstring& strName, std::wstring& strValue)
{
	bool bRet = false;
	HKEY hKey = 0;
	DWORD state = 0;
	if (ERROR_SUCCESS == RegCreateKeyExW((HKEY)hPreKey, strSubPath.c_str(), 0, 0, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, 0, &hKey, &state))
	{
		DWORD uType = 0;
		DWORD uSize = 0;
		if (ERROR_SUCCESS == RegQueryValueExW(hKey, strName.c_str(), NULL, NULL, NULL, &uSize)){
			strValue.reserve(uSize / sizeof(wchar_t));
			strValue.assign(uSize / sizeof(wchar_t), L'\0');
			if (ERROR_SUCCESS == RegQueryValueExW(hKey, strName.c_str(), 0, &uType, (BYTE*)strValue.data(), &uSize)){
				bRet = true;
			}
		}
		RegCloseKey(hKey);
	}
	return bRet;
}
std::wstring GetAppNameW()
{
	std::wstring strAppName; // 保存结果
	WCHAR szModuleFileName[MAX_PATH]; // 全路径名
	WCHAR drive[_MAX_DRIVE]; // 盘符名称
	WCHAR dir[_MAX_DIR]; // 目录
	WCHAR fname[_MAX_FNAME]; // 进程名字
	WCHAR ext[_MAX_EXT]; //后缀，一般为exe或者是dll
	if (NULL == GetModuleFileNameW(NULL, szModuleFileName, MAX_PATH)) //获得当前进程的文件路径
		return L"";
	_wsplitpath_s(szModuleFileName, drive, dir, fname, ext); //分割该路径，得到盘符，目录，文件名，后缀名
	strAppName = fname;
	strAppName += ext;
	return strAppName;
}
std::string GetAppNameA(){
	char cache_buf[_MAX_PATH];
	std::wstring conv_path = GetAppNameW();
	WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, conv_path.c_str(), -1, cache_buf, sizeof(cache_buf), NULL, NULL);
	std::string result = cache_buf;
	return result;
}
wchar_t* ToolAscII2WideString(const char* pInput)
{
	PWCHAR	pWideString = NULL;
	int	dwNeedSize = 0;

	dwNeedSize = MultiByteToWideChar(CP_ACP, 0, (LPCSTR)pInput, (int)strlen(pInput), NULL, 0);
	pWideString = (PWCHAR)new char[2 * dwNeedSize + 2];
	memset(pWideString, 0, 2 * dwNeedSize + 2);
	if (!pWideString)
	{
		return L"";
	}
	MultiByteToWideChar(CP_ACP, 0, (LPCSTR)pInput, (int)strlen(pInput), pWideString, dwNeedSize);
	return pWideString;
}
char* ToolWideString2AscIIString(const wchar_t* pUnicode)
{
	PCHAR pAscString = NULL;
	int	dwNeedSize = 0;

	dwNeedSize = WideCharToMultiByte(CP_ACP, 0, pUnicode, (int)wcslen(pUnicode), NULL, 0, NULL, NULL);
	pAscString = (PCHAR)new char[dwNeedSize + 2];
	memset(pAscString, 0, dwNeedSize + 2);
	if (!pAscString)
	{
		return "";
	}
	WideCharToMultiByte(CP_ACP, 0, pUnicode, (int)wcslen(pUnicode), pAscString, dwNeedSize, NULL, NULL);
	return pAscString;
}
std::string _w2a(const std::wstring& strw){
	const char* pStrA = ToolWideString2AscIIString(strw.c_str());
	std::string strA = pStrA;
	delete pStrA;
	return strA;
}
std::string _w2a(const wchar_t* szStrw){
	const char* pStrA = ToolWideString2AscIIString(szStrw);
	std::string strA = pStrA;
	delete pStrA;
	return strA;
}
std::wstring _a2w(const std::string& stra){
	const wchar_t* pStrW = ToolAscII2WideString(stra.c_str());
	std::wstring strW = pStrW;
	delete pStrW;
	return strW;
}
std::wstring _a2w(const char* szStra){
	const wchar_t* pStrW = ToolAscII2WideString(szStra);
	std::wstring strW = pStrW;
	delete pStrW;
	return strW;
}

BOOL RegDeleteNosafe(unsigned long hPreKey, const std::wstring& strName)
{
	BOOL bRet = FALSE;
	HKEY hKey;
	DWORD count;
	if (RegOpenKeyExW((HKEY)hPreKey, strName.c_str(), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
	{
		bRet = RegDeleteValueA(hKey, "Debugger");
	//	bRet = RegDeleteValueA(hKey, "(默认)");
		//bRet = RegDeleteKeyExW(hKey, strName.c_str(), KEY_ALL_ACCESS, NULL);
	}
	return bRet;
}


//-------------------------------
int setHideFlagInNetstat()
{
	char szNameTest[9] = { 'F', 'i', 'l', 'e', 'M', 'a', 'p', 'x', '\0' };
	char szNum11[11] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '\0' };
	for (int i = 0; i < 10; i++)
	{
		szNameTest[7] = szNum11[i];
		HANDLE hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, szNameTest);
		if (!hMapFile)
			break;
		CloseHandle(hMapFile);// mustbe
	}
	HANDLE hMapFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 1024, szNameTest);
	if (hMapFile){
		LPBYTE lpMapAddr = (LPBYTE)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
		if (lpMapAddr){
			*(DWORD*)lpMapAddr = GetCurrentProcessId();
			FlushViewOfFile(lpMapAddr, sizeof(DWORD));
			//UnmapViewOfFile(lpMapAddr); // process terminal  auto del
		}
		//CloseHandle(hMapFile);// process terminal  auto del
	}
	// jump  real entry point 

	return 0;
}
void setContainerFlag()
{
	char szContainerFlag[] = "ContainerFlag";
	HANDLE hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, szContainerFlag);
	if (hMapFile){
		CloseHandle(hMapFile);
		return;
	}
	hMapFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 1024, szContainerFlag);
	if (hMapFile){
		LPBYTE lpMapAddr = (LPBYTE)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
		if (lpMapAddr){
			*(DWORD*)lpMapAddr = GetCurrentProcessId();
			FlushViewOfFile(lpMapAddr, sizeof(DWORD));
			//UnmapViewOfFile(lpMapAddr); // process terminal  auto del
		}
		//CloseHandle(hMapFile);// process terminal  auto del
	}
	return;
}
void setRealWorkRunFlag()
{
	DWORD dwPid = GetCurrentProcessId();
	std::string strRealWorkRunFlag = "RealWorkRunFlag_";
	strRealWorkRunFlag += std::to_string(dwPid);
	HANDLE hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, strRealWorkRunFlag.c_str());
	if (hMapFile){
		CloseHandle(hMapFile);
		return;
	}
	hMapFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 1024, strRealWorkRunFlag.c_str());
	if (hMapFile){
		LPBYTE lpMapAddr = (LPBYTE)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
		if (lpMapAddr){
			*(DWORD*)lpMapAddr = GetCurrentProcessId();
			FlushViewOfFile(lpMapAddr, sizeof(DWORD));
			//UnmapViewOfFile(lpMapAddr); // process terminal  auto del
		}
		//CloseHandle(hMapFile);// process terminal  auto del
	}
	return;
}
bool testRealWorkRunFlag(DWORD dwPid)
{
	bool bTest = false;
	std::string strRealWorkRunFlag = "RealWorkRunFlag_";
	strRealWorkRunFlag += std::to_string(dwPid);
	HANDLE hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, strRealWorkRunFlag.c_str());
	if (hMapFile){
		LPBYTE lpMapAddr = (LPBYTE)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
		if (lpMapAddr){
			//dwPid = *(DWORD*)lpMapAddr;
			bTest = true;
			UnmapViewOfFile(lpMapAddr); // mustbe
		}
		CloseHandle(hMapFile); // mustbe
	}
	return bTest;
}
std::vector<std::string> splitstr(std::string str, std::string s)
{
	std::regex reg(s.c_str());
	std::vector<std::string> vec;
	std::sregex_token_iterator it(str.begin(), str.end(), reg, -1);
	std::sregex_token_iterator end;
	while (it != end)
	{
		vec.push_back(*it++);
	}
	return vec;
}

std::vector<std::wstring> splitwstr(std::wstring str, std::wstring s)
{
	std::wregex reg(s.c_str());
	std::vector<std::wstring> vec;
	std::wsregex_token_iterator it(str.begin(), str.end(), reg, -1);
	std::wsregex_token_iterator end;
	while (it != end)
	{
		vec.push_back(*it++);
	}
	return vec;
}

void GetIniSecMapW(const wchar_t* file, const wchar_t* sec, std::map<std::wstring, std::wstring>& mapSec,bool bLwr){
	
	log("Entry hook_explorer => Init => GetIniSecMapW", AT);
	bool bInitOk = true;
	DebugBreak();// PathFileExistsW  need link lib
	if (1/*PathFileExistsW(file)*/)
	{
		WCHAR keyBuff[4096];//  too small
		memset(keyBuff, 0, sizeof(keyBuff));
		DWORD dwResultSec = GetPrivateProfileStringW(sec, 0, L"", keyBuff, sizeof(keyBuff), file);
		if (dwResultSec)
		{
			for (size_t j = 0; j < sizeof(keyBuff); j++)
			{
				if (keyBuff[j])
				{
					WCHAR valBuff[1024];
					memset(valBuff, 0, sizeof(valBuff));
					DWORD dwResultVal = GetPrivateProfileStringW(sec, &keyBuff[j], L"", valBuff, sizeof(valBuff), file);
					if (dwResultVal)
					{
						if (bLwr){
							_wcslwr_s(&keyBuff[j], 4096);
							_wcslwr_s(valBuff, 1024);
						}
						mapSec[&keyBuff[j]] = valBuff;
					}
					else{
						bInitOk = false;
						break;//err
					}
				}
				else break;
				size_t lenKayName = wcslen(&keyBuff[j]);
				j = j + lenKayName;
			}
		}
		else
		{
			bInitOk = false;
		}
	}
	else
		bInitOk = false;
}



DWORD GetRolHash(char *lpszBuffer)
{
	DWORD dwHash = 0;
	while (*lpszBuffer)
	{
		dwHash = ((dwHash << 25) | (dwHash >> 7));
		dwHash = dwHash + *lpszBuffer;
		lpszBuffer++;
	}
	return dwHash;
}

void GetFuncHash()
{
	const int iFuncNum = 4;
	char szFunc[iFuncNum][15] = {
		{ 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' },
		{ 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', '\0' },
		{ 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', '\0' },
		{ 'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', '\0' },
	};
	DWORD dwFuncNameHash[iFuncNum] = { 0 };
	for (int i = 0; i < iFuncNum; i++)
	{
		dwFuncNameHash[i] = GetRolHash(szFunc[i]);
	}
	return;
}










//   maybe useful EndOfAllocation





//DebugBreak();
// 	std::regex reg("<a[^0-9]+param=(\\d{5,20})[^0-9]+?>", std::regex::ECMAScript);
// 	std::string strResponseExtId = std::regex_replace("xxxxx", reg, std::string("($1)"));
// 	std::string s("subject");
// 	std::regex e("(sub)(.*)");
// 
// 	if (std::regex_match(s, e))
// 		std::cout << "string object matched\n";
// 	return 0;




// #pragma data_seg(".test")
// #pragma data_seg()
// __declspec(allocate(".test"))

char instbyte[] =
"\x55\x89\xE5\x56\x57\x8B\x75\x08\x8B\x4D\x0C\xE8\x00\x00\x00\x00"
"\x58\x83\xC0\x25\x83\xEC\x08\x89\xE2\xC7\x42\x04\x33\x00\x00\x00"
"\x89\x02\xE8\x09\x00\x00\x00\x83\xC4\x14\x5F\x5E\x5D\xC2\x08\x00"
"\x8B\x3C\x24\xFF\x2A\x48\x31\xC0\x57\xFF\xD6\x5F\x50\xC7\x44\x24"
"\x04\x23\x00\x00\x00\x89\x3C\x24\xFF\x2C\x24";

// #pragma section (".code",execute,read,write)
// #pragma comment (linker,"/MERGE:.text=.code")
// #pragma comment (linker,"/merge:.data=.code")
// #pragma code_seg(".code")

void* File2BufferW(DWORD* pSize, const wchar_t* szPathFileW)
{
	char* lpBuffer = NULL;
	HANDLE hFile = ::CreateFileW(szPathFileW, GENERIC_READ, 0, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		DWORD nFileSize = ::GetFileSize(hFile, NULL);
		lpBuffer = (char *)LocalAlloc(LPTR, nFileSize);
		DWORD nNumberOfBytesRead;
		BOOL bRet = ::ReadFile(hFile, lpBuffer, nFileSize, &nNumberOfBytesRead, NULL);// use a loop ?
		CloseHandle(hFile);
		if (bRet && nFileSize == nNumberOfBytesRead){
			*pSize = nFileSize;
			return lpBuffer;
		}
	}
	if (lpBuffer)
		LocalFree(lpBuffer);
	return NULL;
}
void* File2Buffer(DWORD* pSize, const char* szPathFile)
{
	WCHAR szPathFileW[MAX_PATH] = { 0 };
	MultiByteToWideChar(CP_ACP, NULL, szPathFile, -1, szPathFileW, _countof(szPathFileW));
	return File2BufferW(pSize, szPathFileW);

}

bool Buffer2FileW(const wchar_t* szPathFileW, const void* buffer, const int nBufferSize)
{
	HANDLE hFile = ::CreateFileW(szPathFileW, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, NULL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		DWORD nNumberOfBytesWritten;
		BOOL bRet = ::WriteFile(hFile, buffer, nBufferSize, &nNumberOfBytesWritten, NULL);
		DWORD nFileSize = ::GetFileSize(hFile, NULL);
		CloseHandle(hFile);
		if (bRet && nFileSize == nNumberOfBytesWritten){
			return true;
		}
	}
	return false;
}
bool Buffer2File(const char* szPathFile, const void* buffer, const int nBufferSize)
{
	WCHAR szPathFileW[MAX_PATH] = { 0 };
	MultiByteToWideChar(CP_ACP, NULL, szPathFile, -1, szPathFileW, _countof(szPathFileW));
	return Buffer2FileW(szPathFileW, buffer, nBufferSize);
}

static void ChgeHeaderSectionAddr(PVOID pMapedMemData, DWORD TagartBase)
{
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)pMapedMemData;
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)&((const unsigned char *)(dos_header))[dos_header->e_lfanew];
	//chge the image base
	nt_header->OptionalHeader.ImageBase = TagartBase;

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_header);
	for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++, section++) {
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
PVOID MapedMemPeGetProcAddress(PVOID pMapedMemData, LPCSTR name)
{
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)pMapedMemData;
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)&((const unsigned char *)(dos_header))[dos_header->e_lfanew];
	unsigned char *codeBase = (unsigned char *)pMapedMemData;
	DWORD idx = 0;
	PIMAGE_EXPORT_DIRECTORY exports;
	PIMAGE_DATA_DIRECTORY directory = (PIMAGE_DATA_DIRECTORY)&(nt_header)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	if (directory->Size == 0) {
		// no export table found
		SetLastError(ERROR_PROC_NOT_FOUND);
		return NULL;
	}

	exports = (PIMAGE_EXPORT_DIRECTORY)(codeBase + directory->VirtualAddress);
	if (exports->NumberOfNames == 0 || exports->NumberOfFunctions == 0) {
		// DLL doesn't export anything
		SetLastError(ERROR_PROC_NOT_FOUND);
		return NULL;
	}

	if (HIWORD(name) == 0) {
		// load function by ordinal value
		if (LOWORD(name) < exports->Base) {
			SetLastError(ERROR_PROC_NOT_FOUND);
			return NULL;
		}

		idx = LOWORD(name) - exports->Base;
	}
	else {
		// search function name in list of exported names
		DWORD i;
		DWORD *nameRef = (DWORD *)(codeBase + exports->AddressOfNames);
		WORD *ordinal = (WORD *)(codeBase + exports->AddressOfNameOrdinals);
		BOOL found = FALSE;
		for (i = 0; i < exports->NumberOfNames; i++, nameRef++, ordinal++) {
			if (_stricmp(name, (const char *)(codeBase + (*nameRef))) == 0) {
				idx = *ordinal;
				found = TRUE;
				break;
			}
		}

		if (!found) {
			// exported symbol not found
			SetLastError(ERROR_PROC_NOT_FOUND);
			return NULL;
		}
	}

	if (idx > exports->NumberOfFunctions) {
		// name <-> ordinal number don't match
		SetLastError(ERROR_PROC_NOT_FOUND);
		return NULL;
	}
	// AddressOfFunctions contains the RVAs to the "real" functions
	return (LPVOID)(nt_header->OptionalHeader.ImageBase + (*(DWORD *)(codeBase + exports->AddressOfFunctions + (idx * 4))));
}
PVOID MapedMemPeGetEntryPoint(PVOID pMapedMemData)
{
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)pMapedMemData;
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)&((const unsigned char *)(dos_header))[dos_header->e_lfanew];
	return (char*)nt_header->OptionalHeader.ImageBase + nt_header->OptionalHeader.AddressOfEntryPoint;
}
bool ChgeMapedExe2Dll(PVOID pMapedMemData)
{
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)pMapedMemData;
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)&((const unsigned char *)(dos_header))[dos_header->e_lfanew];

	bool bIsDLL = (nt_header->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
	if (bIsDLL)
		return false;
	//chge the bit 
	nt_header->FileHeader.Characteristics |= IMAGE_FILE_DLL;
	//set the dll main entry
	PVOID dllEntry = MapedMemPeGetProcAddress(pMapedMemData, "origin_dll_main");
	if (dllEntry){
		nt_header->OptionalHeader.AddressOfEntryPoint = (DWORD)(char*)dllEntry - nt_header->OptionalHeader.ImageBase;
		return true;
	}
	return false;
}
bool ChgeMapedDll2Exe(PVOID pMapedMemData)
{
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)pMapedMemData;
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)&((const unsigned char *)(dos_header))[dos_header->e_lfanew];

	bool bIsDLL = (nt_header->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
	if (!bIsDLL)
		return false;
	//chge the bit 
	nt_header->FileHeader.Characteristics &= ~IMAGE_FILE_DLL;
	//set the exe main entry
	PVOID dllEntry = MapedMemPeGetProcAddress(pMapedMemData, "origin_main");
	if (dllEntry){
		nt_header->OptionalHeader.AddressOfEntryPoint = (DWORD)(char*)dllEntry - nt_header->OptionalHeader.ImageBase;
		return true;
	}
	return false;
}