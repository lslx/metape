#include "stdafx.h"
#include "stdafx.h"
#include "Global.Engine.h"
#include "Global.Garbage.h"
#include "Global.Injector.h"
#include "Global.Engine.Extension.h"
#include "Global.Engine.Threading.h"

void TitanEngineInit(HINSTANCE hinstDLL){
	engineHandle = hinstDLL;
	EngineInit();
	EmptyGarbage();
	for (int i = 0; i < UE_MAX_RESERVED_MEMORY_LEFT; i++)
		engineReservedMemoryLeft[i] = NULL;
}
void TitanEngineInit(bool bReleaseCallBack){
	if (bReleaseCallBack)
		ExtensionManagerPluginReleaseCallBack();
	RemoveDirectoryW(engineSzEngineGarbageFolder);
	CriticalSectionLocker::Deinitialize(); //delete critical sections
}
// Global.Engine.Entry:
BOOL APIENTRY DllMain_TitanEngine(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch(fdwReason)
    {
    case DLL_PROCESS_ATTACH:
		TitanEngineInit(hinstDLL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break; //this bug has been here since 2010
    case DLL_PROCESS_DETACH:
		TitanEngineInit((bool)lpvReserved);
        break;
    }
    return TRUE;
}