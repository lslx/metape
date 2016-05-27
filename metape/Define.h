#ifndef __DEFINE_H____shellexe
#define __DEFINE_H____shellexe
#include <windows.h>

struct ShellPara
{
	BYTE *cshellBase;
	BYTE *Kernel32Base;
	BYTE *SelfPeFileBase;
	BYTE *SelfPeMapedBase;
	BYTE *pShellEntryInPe;
	BYTE *pLoadLibraryA;
	BYTE *pGetProcAddress;
	BYTE *pVirtualAlloc;
	BYTE *pVirtualFree;
	BYTE *CmdLineAddress;
	BYTE *pPayload;
};
struct StCmdLinePass
{
	int  iLen;
	int  iArgc;
	char szsCmdLines[1];
};
struct ShellRunPara
{
	BYTE *pPayload;
	StCmdLinePass CmdLinePass;
};


// #ifdef _WIN64
// typedef ShellPara64                  ShellPara;
// #else
// typedef ShellPara32                  ShellPara;
// #endif













#endif //__DEFINE_H____shellexe