#include "PeTool.h"
#include "Tools.h"
bool PeTool::InitFromNotMapedPeBuffer(void *pData, DWORD nSize){
	unsigned char* pReadPtr = (unsigned char*)pData;

	//get dos header
	_pDosHeader = (PIMAGE_DOS_HEADER)LocalAlloc(LPTR, sizeof(IMAGE_DOS_HEADER));
	memcpy(_pDosHeader, pReadPtr, sizeof(IMAGE_DOS_HEADER));
	pReadPtr += sizeof(IMAGE_DOS_HEADER);

	//get dos stub
	_dwDosStubSize = _pDosHeader->e_lfanew - sizeof(IMAGE_DOS_HEADER);
	_pDosStub = (BYTE *)LocalAlloc(LPTR, _dwDosStubSize);
	memcpy(_pDosStub, pReadPtr, _dwDosStubSize);
	pReadPtr += _dwDosStubSize;

	//get nt header
	PIMAGE_NT_HEADERS32 pNTHeader32Tmp = (PIMAGE_NT_HEADERS32)((unsigned char*)pData + _pDosHeader->e_lfanew);
	_dwNtHeaderSize = sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+pNTHeader32Tmp->FileHeader.SizeOfOptionalHeader;
	if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == pNTHeader32Tmp->OptionalHeader.Magic){
		_pNTHeader32 = (PIMAGE_NT_HEADERS32)LocalAlloc(LPTR, _dwNtHeaderSize);
		memcpy(_pNTHeader32, pReadPtr, _dwNtHeaderSize);
	}
	else if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == pNTHeader32Tmp->OptionalHeader.Magic){
		_pNTHeader64 = (PIMAGE_NT_HEADERS64)LocalAlloc(LPTR, _dwNtHeaderSize);
		memcpy(_pNTHeader64, pReadPtr, _dwNtHeaderSize);
	}
	else
		return false;
	pReadPtr += _dwNtHeaderSize;

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeader32Tmp);
	WORD nSection = _pNTHeader32->FileHeader.NumberOfSections;

	//get File Align Gap, the vector first maybe not the first in the memory ,so use loop
	DWORD firstRawOffset = 0;// GetFileAlign();
	for (WORD i = 0; i < nSection; i++){
		if (pSectionHeader[i].PointerToRawData){//maybe zero (e.g.  .textbss )
			if (!firstRawOffset)
				firstRawOffset = pSectionHeader[i].PointerToRawData;
			else if (pSectionHeader[i].PointerToRawData < firstRawOffset)
				firstRawOffset = pSectionHeader[i].PointerToRawData;
		}
	}
	_dwAlignGapLen = firstRawOffset - ((char*)&pSectionHeader[nSection] - pData);
	if (_dwAlignGapLen){
		_pAlignGap = (BYTE*)LocalAlloc(LPTR, _dwAlignGapLen);;
		memcpy_s(_pAlignGap, _dwAlignGapLen,
			&pSectionHeader[nSection], _dwAlignGapLen);
	}

	//get section headers and sections data with the gap data
	_listPeSection.clear();
	_listPeSection.reserve(nSection);
	for (WORD i = 0; i < nSection; i++){
		PeFileSection peFileSection;
		memcpy_s(&peFileSection.sectionHeader, sizeof(IMAGE_SECTION_HEADER), pSectionHeader,sizeof(IMAGE_SECTION_HEADER));
		peFileSection.dataSize = pSectionHeader->SizeOfRawData;
		if (pSectionHeader->SizeOfRawData){
			DWORD dwToFileAlignUp = ALIGN_VALUE_UP(pSectionHeader->SizeOfRawData, GetFileAlign());
			peFileSection.data = (BYTE*)LocalAlloc(LPTR, dwToFileAlignUp);
			memcpy_s(peFileSection.data, dwToFileAlignUp,(unsigned char*)pData + pSectionHeader->PointerToRawData, dwToFileAlignUp);
		}
		_listPeSection.push_back(peFileSection);
		pSectionHeader++;
	}

	//get overlay data, maybe the sections not sort by RawOffset(e.g. Petite), so use the loop
	DWORD lastRawOffset = 0, lastRawSize = 0;
	for (std::vector<PeFileSection>::iterator it = _listPeSection.begin(); it != _listPeSection.end(); it++){
		if (((*it).sectionHeader.PointerToRawData + (*it).sectionHeader.SizeOfRawData) >(lastRawOffset + lastRawSize)){
			lastRawOffset = (*it).sectionHeader.PointerToRawData;
			lastRawSize = (*it).sectionHeader.SizeOfRawData;
		}
	}
	DWORD _dwOverlaySize = nSize - (lastRawSize + lastRawOffset);
	if (_dwOverlaySize){// if has overlay data
		_pOverlayData = (BYTE*)LocalAlloc(LPTR, _dwOverlaySize);
		memcpy_s(_pOverlayData, _dwOverlaySize,
			(char*)pData + lastRawOffset + lastRawSize, _dwAlignGapLen);
	}
	return true;
}
bool PeTool::InitFromPeFileW(wchar_t* szPathFileW){
	DWORD nSize;
	unsigned char* pData = (unsigned char*)File2BufferW(&nSize, szPathFileW);
	if (!pData)
		return false;
	return InitFromNotMapedPeBuffer(pData, nSize);
}
bool PeTool::InitFromPeFile(char* szPathFile){
	WCHAR szPathFileW[MAX_PATH] = { 0 };
	MultiByteToWideChar(CP_ACP, NULL, szPathFile, -1, szPathFileW, _countof(szPathFileW));
	return InitFromPeFileW(szPathFileW);;
}
void* PeTool::SaveToPeBuffer(DWORD *nSize){
	DWORD nNeedSize = 0;
	nNeedSize += sizeof(IMAGE_DOS_HEADER);
	nNeedSize += _dwDosStubSize;
	nNeedSize += _dwNtHeaderSize;
	if (IsPe32())
		nNeedSize += _pNTHeader32->FileHeader.NumberOfSections*sizeof(IMAGE_SECTION_HEADER);
	else 
		nNeedSize += _pNTHeader64->FileHeader.NumberOfSections*sizeof(IMAGE_SECTION_HEADER);
	nNeedSize += _dwAlignGapLen;
	
	BYTE* pOutPe = (BYTE*)LocalAlloc(LPTR, nNeedSize);
	return 0;
}
bool PeTool::SaveToPeFileW(wchar_t* szPathFileW){
	bool bSaveSuccess = false;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	while (true){
		if (INVALID_HANDLE_VALUE == (hFile = ::CreateFileW(szPathFileW, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, NULL, NULL)))
			break;
		BOOL bWrite = FALSE; LPCVOID lpWriteBuffer = NULL; DWORD nWrite = 0; DWORD nWritten = 0;

		//write dos header
		lpWriteBuffer = _pDosHeader;
		nWrite = sizeof(IMAGE_DOS_HEADER);
		bWrite = ::WriteFile(hFile, lpWriteBuffer, nWrite, &nWritten, NULL);
		if (!bWrite || nWrite != nWritten)
			break;

		//write dos stub
		lpWriteBuffer = _pDosStub;
		nWrite = _dwDosStubSize;
		bWrite = ::WriteFile(hFile, lpWriteBuffer, nWrite, &nWritten, NULL);
		if (!bWrite || nWrite != nWritten)
			break;

		//write nt header 
		lpWriteBuffer = (char*)_pNTHeader32 ? (char*)_pNTHeader32 : (char*)_pNTHeader64;
		nWrite = (char*)_pNTHeader32 ? sizeof(IMAGE_NT_HEADERS32) : sizeof(IMAGE_NT_HEADERS64);
		bWrite = ::WriteFile(hFile, lpWriteBuffer, nWrite, &nWritten, NULL);
		if (!bWrite || nWrite != nWritten)
			break;

		//write section headers
		bool bWrittenSectionHeaders = true;
		for (std::vector<PeFileSection>::iterator it = _listPeSection.begin(); it != _listPeSection.end(); it++){
			lpWriteBuffer = &(*it).sectionHeader;
			nWrite = sizeof(IMAGE_SECTION_HEADER);
			bWrite = ::WriteFile(hFile, lpWriteBuffer, nWrite, &nWritten, NULL);
			if (!bWrite || nWrite != nWritten){
				bWrittenSectionHeaders = false; break;
			}
		}
		if (!bWrittenSectionHeaders)
			break;

		//write file align gap
		lpWriteBuffer = _pAlignGap;
		nWrite = _dwAlignGapLen;
		bWrite = ::WriteFile(hFile, lpWriteBuffer, nWrite, &nWritten, NULL);
		if (!bWrite || nWrite != nWritten)
			break;

		//write sections
		bool bWrittenSections = true;
		for (std::vector<PeFileSection>::iterator it = _listPeSection.begin(); it != _listPeSection.end(); it++){
			if (!(*it).data)
				continue;
			lpWriteBuffer = (*it).data;
			nWrite = (*it).dataSize;
			bWrite = ::WriteFile(hFile, lpWriteBuffer, nWrite, &nWritten, NULL);
			if (!bWrite || nWrite != nWritten){
				bWrittenSections = false; break;
			}
		}
		if (!bWrittenSections)
			break;

		//write overlay data
		if (_pOverlayData){
			lpWriteBuffer = _pOverlayData;
			nWrite = _dwOverlaySize;
			bWrite = ::WriteFile(hFile, lpWriteBuffer, nWrite, &nWritten, NULL);
			if (!bWrite || nWrite != nWritten)
				break;
		}

		bSaveSuccess = true;
		break;
	}
	if (!bSaveSuccess && INVALID_HANDLE_VALUE != hFile )
		DeleteFileW(szPathFileW);
	if (INVALID_HANDLE_VALUE != hFile)
		CloseHandle(hFile);
	return bSaveSuccess;
}

bool PeTool::SaveToPeFile(char* szPathFile){
	WCHAR szPathFileW[MAX_PATH] = { 0 };
	MultiByteToWideChar(CP_ACP, NULL, szPathFile, -1, szPathFileW, _countof(szPathFileW));
	return SaveToPeFileW(szPathFileW);;
}

bool PeTool::InitFromPeBuffer(void *pData, DWORD nSize){
	unsigned char* pReadPtr = (unsigned char*)pData;

	//get dos header
	_pDosHeader = (PIMAGE_DOS_HEADER)LocalAlloc(LPTR, sizeof(IMAGE_DOS_HEADER));
	memcpy(_pDosHeader, pReadPtr, sizeof(IMAGE_DOS_HEADER));
	pReadPtr += sizeof(IMAGE_DOS_HEADER);

	//get dos stub
	_dwDosStubSize = _pDosHeader->e_lfanew - sizeof(IMAGE_DOS_HEADER);
	_pDosStub = (BYTE *)LocalAlloc(LPTR, _dwDosStubSize);
	memcpy(_pDosStub, pReadPtr, _dwDosStubSize);
	pReadPtr += _dwDosStubSize;

	//get nt header
	PIMAGE_NT_HEADERS32 pNTHeader32Tmp = (PIMAGE_NT_HEADERS32)((unsigned char*)pData + _pDosHeader->e_lfanew);
	if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == pNTHeader32Tmp->OptionalHeader.Magic){
		_pNTHeader32 = (PIMAGE_NT_HEADERS32)LocalAlloc(LPTR, sizeof(IMAGE_NT_HEADERS32));
		memcpy(_pNTHeader32, pReadPtr, sizeof(IMAGE_NT_HEADERS32));
		pReadPtr += sizeof(IMAGE_NT_HEADERS32);
	}
	else if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == pNTHeader32Tmp->OptionalHeader.Magic){
		_pNTHeader64 = (PIMAGE_NT_HEADERS64)LocalAlloc(LPTR, sizeof(IMAGE_NT_HEADERS64));
		memcpy(_pNTHeader64, pReadPtr, sizeof(IMAGE_NT_HEADERS64));
		pReadPtr += sizeof(IMAGE_NT_HEADERS64);
	}
	else
		return false;

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeader32Tmp);
	WORD nSection = _pNTHeader32->FileHeader.NumberOfSections;

	//get File Align Gap
	for (WORD i = 0; i < nSection; i++){
		if (pSectionHeader[i].PointerToRawData){
			_dwAlignGapLen = (char*)pSectionHeader[i].PointerToRawData - (char*)((char*)&pSectionHeader[nSection]-pData);
			if (_dwAlignGapLen){
				_pAlignGap = (BYTE*)LocalAlloc(LPTR, _dwAlignGapLen);;
				memcpy_s(_pAlignGap, _dwAlignGapLen,
					&pSectionHeader[nSection], _dwAlignGapLen);
			}
			break;
		}
	}

	//get section headers and sections data
	_listPeSection.clear();
	_listPeSection.reserve(nSection);
	for (WORD i = 0; i < nSection; i++){
		PeFileSection peFileSection;
		memcpy_s(&peFileSection.sectionHeader, sizeof(IMAGE_SECTION_HEADER), pSectionHeader,sizeof(IMAGE_SECTION_HEADER));
		peFileSection.dataSize = pSectionHeader->SizeOfRawData;
		if (pSectionHeader->SizeOfRawData){
			DWORD dwToFileAlignUp = ALIGN_VALUE_UP(pSectionHeader->SizeOfRawData, GetFileAlign());
			peFileSection.data = (BYTE*)LocalAlloc(LPTR, dwToFileAlignUp);
			memcpy_s(peFileSection.data, dwToFileAlignUp,(unsigned char*)pData + pSectionHeader->PointerToRawData, dwToFileAlignUp);
		}
		_listPeSection.push_back(peFileSection);
		pSectionHeader++;
	}
	
	//
	LocalFree(pData);
	pData = 0;
	return true;
}
void Test_CompareFile(char* szPathFileX,char* szPathFileY)
{
	DWORD nSizeX;
	char* pDataX = (char*)File2Buffer(&nSizeX, szPathFileX);
	DWORD nSizeY;
	char* pDataY = (char*)File2Buffer(&nSizeY, szPathFileY);
	if (nSizeX != nSizeY)
		DebugBreak();
	for (DWORD n = 0; n < nSizeX; n++)
	{
		if (pDataX[n] != pDataY[n])
			DebugBreak();
	}
}
void Test_CompareBuffer(char* pBufferX, DWORD nBufferLenX, char* pBufferY, DWORD nBufferLenY)
{
	if (nBufferLenX != nBufferLenY)
		DebugBreak();
	for (DWORD n = 0; n < nBufferLenX; n++)
	{
		if (pBufferX[n] != pBufferY[n])
			DebugBreak();
	}
}

void PeTool::Test()
{
	char szModuleName[0x1100] = { 0 };
	if (GetModuleFileNameA(GetModuleHandleA(NULL), (LPCH)szModuleName, sizeof(szModuleName)-0x100))
	{
		PeTool pe;
		pe.InitFromPeFile(szModuleName);
		char szModuleNameSave[0x1100] = { 0 };
		strcpy(szModuleNameSave, szModuleName);
		strcat(szModuleNameSave, ".save.exe");
		pe.SaveToPeFile(szModuleNameSave);
		Test_CompareFile(szModuleName, szModuleNameSave);
	}
	ExitProcess(0);
}

