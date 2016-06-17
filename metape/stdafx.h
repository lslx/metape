// stdafx.h : 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 特定于项目的包含文件
//

#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include "targetver.h"


// TODO:  在此处引用程序需要的其他头文件
#include "TitanEngine/Titan_stdafx.h"


// my define:
#ifdef _UNICODE
#define _tmainCRTStartup    wmainCRTStartup
#else  /* _UNICODE */
#define _tmainCRTStartup    mainCRTStartup
#endif  /* _UNICODE */
extern "C" int	_tmainCRTStartup(void);

extern "C" IMAGE_DOS_HEADER __ImageBase;



