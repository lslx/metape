/*
*
* Copyright (c) 2014
*
* cypher <the.cypher@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 3 as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "stdafx.h"
#include "scylla_wrapper.h"
#include "ApiReader.h"
#include "ProcessLister.h"
#include "ImportRebuilder.h"
#include "IATSearch.h"
#include "StringConversion.h"
#include "SystemInformation.h"

static std::map<DWORD_PTR, ImportModuleThunk> moduleList;
static int moduleCount = 0;
static int importCount = 0;

void updateCounts()
{
    std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module;
    std::map<DWORD_PTR, ImportThunk>::iterator it_import;

    moduleCount = 0;
    importCount = 0;

    it_module = moduleList.begin();
    while (it_module != moduleList.end())
    {
        ImportModuleThunk &moduleThunk = it_module->second;

        it_import = moduleThunk.thunkList.begin();
        while (it_import != moduleThunk.thunkList.end())
        {
            ImportThunk &importThunk = it_import->second;

            importCount++;
            it_import++;
        }

        moduleCount++;
        it_module++;
    }
}

extern "C" SCYLLA_WRAPPER_API int scylla_searchIAT(DWORD pid, DWORD_PTR &iatStart, DWORD &iatSize, DWORD_PTR searchStart = 0xDEADBEEF, bool advancedSearch = false)
{
    ApiReader apiReader;
    DWORD_PTR searchAddress = 0;
    DWORD_PTR addressIAT = 0, addressIATAdv = 0;
    DWORD sizeIAT = 0, sizeIATAdv = 0;
    IATSearch iatSearch;
    ProcessLister processLister;

    NativeWinApi::initialize();
    SystemInformation::getSystemInformation();

    //need to find correct process by PID
    Process *processPtr = 0;
    std::vector<Process>& processList = processLister.getProcessListSnapshotNative();
    for(std::vector<Process>::iterator it = processList.begin(); it != processList.end(); ++it) {
        if(it->PID == pid) {
            processPtr = &(*it);
            break;
        }
    }

    if(!processPtr) return SCY_ERROR_PROCOPEN;

    //init process access
    ProcessAccessHelp::closeProcessHandle();
    apiReader.clearAll();

    if (!ProcessAccessHelp::openProcessHandle(processPtr->PID))
    {
        return SCY_ERROR_PROCOPEN;
    }

    ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);

    ProcessAccessHelp::selectedModule = 0;
    ProcessAccessHelp::targetSizeOfImage = ProcessAccessHelp::getSizeOfImageProcess(ProcessAccessHelp::hProcess, ProcessAccessHelp::targetImageBase);
    ProcessAccessHelp::targetImageBase = processPtr->imageBase;

    apiReader.readApisFromModuleList();

    int retVal = SCY_ERROR_IATNOTFOUND;

    //now actually do some searching
    if(searchStart!=0xDEADBEEF)
    {
        searchAddress = searchStart;
        if (searchAddress)
        {

            if (advancedSearch)
            {
                if (iatSearch.searchImportAddressTableInProcess(searchAddress, &addressIATAdv, &sizeIATAdv, true))
                {
                    //Scylla::windowLog.log(L"IAT Search Advanced: IAT VA " PRINTF_DWORD_PTR_FULL L" RVA " PRINTF_DWORD_PTR_FULL L" Size 0x%04X (%d)", addressIATAdv, addressIATAdv - ProcessAccessHelp::targetImageBase, sizeIATAdv, sizeIATAdv);

                    iatStart = addressIATAdv;
                    iatSize = sizeIATAdv;

                    retVal = SCY_ERROR_SUCCESS;
                }
            }


            if (iatSearch.searchImportAddressTableInProcess(searchAddress, &addressIAT, &sizeIAT, false))
            {
                //Scylla::windowLog.log(L"IAT Search Normal: IAT VA " PRINTF_DWORD_PTR_FULL L" RVA " PRINTF_DWORD_PTR_FULL L" Size 0x%04X (%d)", addressIAT, addressIAT - ProcessAccessHelp::targetImageBase, sizeIAT, sizeIAT);

                iatStart = addressIAT;
                iatSize = sizeIAT;

                retVal = SCY_ERROR_SUCCESS;
            }

        }
    } else {
        return SCY_ERROR_IATSEARCH;
    }

    processList.clear();
    ProcessAccessHelp::closeProcessHandle();
    apiReader.clearAll();

    return retVal;
}

extern "C" SCYLLA_WRAPPER_API int scylla_getImports(DWORD_PTR iatAddr, DWORD iatSize, DWORD pid, LPVOID invalidImportCallback)
{
    //some things we need
    ApiReader apiReader;
    ProcessLister processLister;
    typedef void*(*fCallback)(LPVOID invalidImport);
    fCallback myCallback = (fCallback)invalidImportCallback;

    NativeWinApi::initialize();
    SystemInformation::getSystemInformation();

    //need to find correct process by PID
    Process *processPtr = 0;
    std::vector<Process>& processList = processLister.getProcessListSnapshotNative();
    for(std::vector<Process>::iterator it = processList.begin(); it != processList.end(); ++it) {
        if(it->PID == pid) {
            processPtr = &(*it);
            break;
        }
    }

    if(!processPtr) return SCY_ERROR_PROCOPEN;

    //init process access
    ProcessAccessHelp::closeProcessHandle();
    apiReader.clearAll();

    if (!ProcessAccessHelp::openProcessHandle(processPtr->PID))
    {
        return SCY_ERROR_PROCOPEN;
    }

    ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);

    ProcessAccessHelp::selectedModule = 0;
    ProcessAccessHelp::targetSizeOfImage = ProcessAccessHelp::getSizeOfImageProcess(ProcessAccessHelp::hProcess, ProcessAccessHelp::targetImageBase);
    ProcessAccessHelp::targetImageBase = processPtr->imageBase;

    apiReader.readApisFromModuleList();

    //parse IAT
    apiReader.readAndParseIAT(iatAddr, iatSize, moduleList);

    //callback for invalid imports
    if(invalidImportCallback != NULL) {
        std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module;
        std::map<DWORD_PTR, ImportThunk>::iterator it_import;

        it_module = moduleList.begin();
        while (it_module != moduleList.end())
        {
            ImportModuleThunk &moduleThunk = it_module->second;

            it_import = moduleThunk.thunkList.begin();
            while (it_import != moduleThunk.thunkList.end())
            {
                ImportThunk &importThunk = it_import->second;

                if(!importThunk.valid) {
                    DWORD_PTR apiAddr = (DWORD_PTR)myCallback((LPVOID)importThunk.apiAddressVA);

                    //we trust the users return value
                    if(apiAddr != NULL) {
                        importThunk.apiAddressVA = apiAddr;
                        importThunk.valid = true;
                    }
                }
                it_import++;
            }

            it_module++;
        }
    }

    updateCounts();

    return SCY_ERROR_SUCCESS;
}

extern "C" SCYLLA_WRAPPER_API bool scylla_addModule(const WCHAR* moduleName, DWORD_PTR firstThunk)
{
    ApiReader apiReader;

    return apiReader.addModuleToModuleList(moduleName, firstThunk);
}

extern "C" SCYLLA_WRAPPER_API bool scylla_addImport(const WCHAR* importName, DWORD_PTR thunkVA)
{
    ApiReader apiReader;
    ApiInfo *apiFound = 0;
    DWORD apiVA = 0;
    bool suspect = false;

    if (ProcessAccessHelp::readMemoryFromProcess(thunkVA,sizeof(DWORD_PTR),(LPVOID)&apiVA)) {
        apiFound = apiReader.getApiByVirtualAddress(apiVA, &suspect);
        apiReader.addFoundApiToModuleList(thunkVA, apiFound, false, suspect);

        return true;
    }

    return false;
}

extern "C" SCYLLA_WRAPPER_API bool scylla_importsValid()
{
    std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module;
    std::map<DWORD_PTR, ImportThunk>::iterator it_import;
    bool valid = true;

    it_module = moduleList.begin();
    while (it_module != moduleList.end())
    {
        ImportModuleThunk &moduleThunk = it_module->second;

        it_import = moduleThunk.thunkList.begin();
        while (it_import != moduleThunk.thunkList.end())
        {
            ImportThunk &importThunk = it_import->second;

            if(!importThunk.valid) {
                valid = false;
                break;;
            }
            it_import++;
        }

        it_module++;
    }

    return valid;
}

extern "C" SCYLLA_WRAPPER_API bool scylla_cutImport(DWORD_PTR apiAddr)
{
    std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module;
    std::map<DWORD_PTR, ImportThunk>::iterator it_import;

    it_module = moduleList.begin();
    while (it_module != moduleList.end())
    {
        ImportModuleThunk &moduleThunk = it_module->second;

        it_import = moduleThunk.thunkList.begin();
        while (it_import != moduleThunk.thunkList.end())
        {
            ImportThunk &importThunk = it_import->second;

            //we found the API Addr to be cut
            if(importThunk.apiAddressVA == apiAddr) {
                moduleThunk.thunkList.erase(it_import);

                //whole module empty now?
                if(moduleThunk.thunkList.empty()) {
                    moduleList.erase(it_module);
                } else { //maybe the module is valid now?
                    if (moduleThunk.isValid() && moduleThunk.moduleName[0] == L'?')
                    {
                        //update module name
                        wcscpy_s(moduleThunk.moduleName, moduleThunk.thunkList.begin()->second.moduleName);
                    }

                    moduleThunk.firstThunk = moduleThunk.thunkList.begin()->second.rva;
                }

                updateCounts();

                return true;
            }
            it_import++;
        }

        it_module++;
    }

    return false;
}

extern "C" SCYLLA_WRAPPER_API int scylla_fixDump(WCHAR* dumpFile, WCHAR* iatFixFile, WCHAR* sectionName)
{
    WCHAR dumpedFilePath[MAX_PATH];
    WCHAR fixedFilePath[MAX_PATH];

    wcscpy_s(fixedFilePath, iatFixFile);
    wcscpy_s(dumpedFilePath, dumpFile);

    //add IAT section to dump
    ImportRebuilder importRebuild(dumpedFilePath, sectionName);
    importRebuild.enableOFTSupport();

    if (importRebuild.rebuildImportTable(fixedFilePath, moduleList))
    {
        return SCY_ERROR_SUCCESS;
    }
    else
    {
        return SCY_ERROR_IATWRITE;
    }
}

extern "C" SCYLLA_WRAPPER_API int scylla_fixMappedDump(DWORD_PTR iatVA, DWORD_PTR FileMapVA, HANDLE hFileMap)
{
    ImportRebuilder importRebuild(iatVA, FileMapVA, hFileMap, L".test");
    importRebuild.enableOFTSupport();

    if (importRebuild.rebuildMappedImportTable(iatVA, moduleList))
    {
        return SCY_ERROR_SUCCESS;
    }
    else
    {
        return SCY_ERROR_IATWRITE;
    }

    return SCY_ERROR_SUCCESS;
}

extern "C" SCYLLA_WRAPPER_API int scylla_getModuleCount()
{
    return moduleCount;
}

extern "C" SCYLLA_WRAPPER_API int scylla_getImportCount()
{
    return importCount;
}

extern "C" SCYLLA_WRAPPER_API void scylla_enumImportTree(LPVOID enumCallback)
{
    std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module;
    std::map<DWORD_PTR, ImportThunk>::iterator it_import;
    typedef void(*fCallback)(LPVOID importDetail);
    fCallback myCallback = (fCallback)enumCallback;
    ImportEnumData myImportEnumData;
    myImportEnumData.DLLName = (char*)malloc(sizeof(char)*MAX_PATH);
    myImportEnumData.APIName = (char*)malloc(sizeof(char)*MAX_PATH);

    if(enumCallback == NULL || moduleList.empty()) {
        return;
    }

    it_module = moduleList.begin();
    while (it_module != moduleList.end())
    {
        ImportModuleThunk &moduleThunk = it_module->second;

        //module
        myImportEnumData.NewDll = true;
        myImportEnumData.NumberOfImports = moduleThunk.thunkList.size();
        StringConversion::ToASCII(moduleThunk.moduleName, myImportEnumData.DLLName, sizeof(char)*MAX_PATH);
        myImportEnumData.BaseImportThunk = moduleThunk.firstThunk;

        it_import = moduleThunk.thunkList.begin();
        while (it_import != moduleThunk.thunkList.end())
        {
            ImportThunk &importThunk = it_import->second;

            //import
            myImportEnumData.ImageBase = 0;
            myImportEnumData.ImportThunk = importThunk.apiAddressVA;
            strcpy_s(myImportEnumData.APIName, sizeof(char)*MAX_PATH, importThunk.name);

            myCallback(&myImportEnumData);

            myImportEnumData.NewDll = false;

            it_import++;
        }

        it_module++;
    }
}

extern "C" SCYLLA_WRAPPER_API long scylla_estimatedIATSize()
{
    //faking a file to be rebuild
    ImportRebuilder importRebuild(L"", L"");

    return importRebuild.getIATSectionSize(moduleList);
}

extern "C" SCYLLA_WRAPPER_API DWORD_PTR scylla_findImportWriteLocation(char* importName)
{
    std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module;
    std::map<DWORD_PTR, ImportThunk>::iterator it_import;

    it_module = moduleList.begin();
    while (it_module != moduleList.end())
    {
        ImportModuleThunk &moduleThunk = it_module->second;

        it_import = moduleThunk.thunkList.begin();
        while (it_import != moduleThunk.thunkList.end())
        {
            ImportThunk &importThunk = it_import->second;

            if(_stricmp(importName, importThunk.name)) {
                //returns VA
                return importThunk.va;
            }
        }
        it_import++;
    }

    it_module++;

    return NULL;
}

extern "C" SCYLLA_WRAPPER_API DWORD_PTR scylla_findOrdinalImportWriteLocation(DWORD_PTR ordinalNumber)
{
    std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module;
    std::map<DWORD_PTR, ImportThunk>::iterator it_import;

    it_module = moduleList.begin();
    while (it_module != moduleList.end())
    {
        ImportModuleThunk &moduleThunk = it_module->second;

        it_import = moduleThunk.thunkList.begin();
        while (it_import != moduleThunk.thunkList.end())
        {
            ImportThunk &importThunk = it_import->second;

            if(importThunk.ordinal == ordinalNumber) {
                return importThunk.va;
            }
        }
        it_import++;
    }

    it_module++;

    return NULL;
}

extern "C" SCYLLA_WRAPPER_API DWORD_PTR scylla_findImportNameByWriteLocation(DWORD_PTR thunkVA)
{
    std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module;
    std::map<DWORD_PTR, ImportThunk>::iterator it_import;

    it_module = moduleList.begin();
    while (it_module != moduleList.end())
    {
        ImportModuleThunk &moduleThunk = it_module->second;

        it_import = moduleThunk.thunkList.begin();
        while (it_import != moduleThunk.thunkList.end())
        {
            ImportThunk &importThunk = it_import->second;

            if(importThunk.va == thunkVA) {
                return (DWORD_PTR)importThunk.name;
            }
        }
        it_import++;
    }

    it_module++;

    return NULL;
}

extern "C" SCYLLA_WRAPPER_API DWORD_PTR scylla_findModuleNameByWriteLocation(DWORD_PTR thunkVA)
{
    std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module;
    std::map<DWORD_PTR, ImportThunk>::iterator it_import;

    it_module = moduleList.begin();
    while (it_module != moduleList.end())
    {
        ImportModuleThunk &moduleThunk = it_module->second;

        it_import = moduleThunk.thunkList.begin();
        while (it_import != moduleThunk.thunkList.end())
        {
            ImportThunk &importThunk = it_import->second;

            if(importThunk.va == thunkVA) {
                return (DWORD_PTR)importThunk.moduleName;
            }
        }
        it_import++;
    }

    it_module++;

    return NULL;
}

BOOL DumpProcessW(const WCHAR * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR * fileResult)
{
    PeParser * peFile = 0;

    if (fileToDump)
    {
        peFile = new PeParser(fileToDump, true);
    }
    else
    {
        peFile = new PeParser(imagebase, true);
    }

    return peFile->dumpProcess(imagebase, entrypoint, fileResult);
}

extern "C" SCYLLA_WRAPPER_API bool scylla_dumpProcessW(DWORD_PTR pid, const WCHAR * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR * fileResult)
{
	NativeWinApi::initialize();// add by fhc
    if (ProcessAccessHelp::openProcessHandle((DWORD)pid))
    {
        return DumpProcessW(fileToDump, imagebase, entrypoint, fileResult);
    }
    else
    {
        return FALSE;
    }
}

extern "C" SCYLLA_WRAPPER_API bool scylla_dumpProcessA(DWORD_PTR pid, const char * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const char * fileResult)
{
    WCHAR fileToDumpW[MAX_PATH];
    WCHAR fileResultW[MAX_PATH];

    if (fileResult == 0)
    {
        return FALSE;
    }

    if (MultiByteToWideChar(CP_ACP, 0, fileResult, -1, fileResultW, _countof(fileResultW)) == 0)
    {
        return FALSE;
    }

    if (fileToDump != 0)
    {
        if (MultiByteToWideChar(CP_ACP, 0, fileToDump, -1, fileToDumpW, _countof(fileToDumpW)) == 0)
        {
            return FALSE;
        }

        return scylla_dumpProcessW(pid, fileToDumpW, imagebase, entrypoint, fileResultW);
    }
    else
    {
        return scylla_dumpProcessW(pid, 0, imagebase, entrypoint, fileResultW);
    }
}

extern "C" SCYLLA_WRAPPER_API bool scylla_rebuildFileW(const WCHAR * fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup)
{

    if (createBackup)
    {
        if (!ProcessAccessHelp::createBackupFile(fileToRebuild))
        {
            return FALSE;
        }
    }

    PeParser peFile(fileToRebuild, true);
    if (peFile.readPeSectionsFromFile())
    {
        peFile.setDefaultFileAlignment();
        if (removeDosStub)
        {
            peFile.removeDosStub();
        }
        peFile.alignAllSectionHeaders();
        peFile.fixPeHeader();

        if (peFile.savePeFileToDisk(fileToRebuild))
        {
            if (updatePeHeaderChecksum)
            {
                PeParser::updatePeHeaderChecksum(fileToRebuild, (DWORD)ProcessAccessHelp::getFileSize(fileToRebuild));
            }
            return TRUE;
        }
    }

    return FALSE;
}

extern "C" SCYLLA_WRAPPER_API bool scylla_rebuildFileA(const char * fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup)
{
    WCHAR fileToRebuildW[MAX_PATH];
    if (MultiByteToWideChar(CP_ACP, 0, fileToRebuild, -1, fileToRebuildW, _countof(fileToRebuildW)) == 0)
    {
        return FALSE;
    }

    return scylla_rebuildFileW(fileToRebuildW, removeDosStub, updatePeHeaderChecksum, createBackup);
}