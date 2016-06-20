#include "PeTool.h"
#include "Tools.h"
#include <algorithm>
bool SortByPointerToRawData(const PeFileSection& d1, const PeFileSection& d2)
{
	return d1.sectionHeader.PointerToRawData < d2.sectionHeader.PointerToRawData;
}
bool SortByVirtualAddress(const PeFileSection& d1, const PeFileSection& d2)
{
	return d1.sectionHeader.VirtualAddress < d2.sectionHeader.VirtualAddress;
}
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

	//get section headers and sections data without the gap data
	_listPeSection.clear();
	_listPeSection.reserve(nSection);
	for (WORD i = 0; i < nSection; i++){
		PeFileSection peFileSection;
		memcpy_s(&peFileSection.sectionHeader, sizeof(IMAGE_SECTION_HEADER), pSectionHeader,sizeof(IMAGE_SECTION_HEADER));
		peFileSection.dataSize = pSectionHeader->SizeOfRawData;
		if (pSectionHeader->SizeOfRawData){
			peFileSection.data = (BYTE*)LocalAlloc(LPTR, peFileSection.dataSize);
			memcpy_s(peFileSection.data, peFileSection.dataSize, (unsigned char*)pData + pSectionHeader->PointerToRawData, peFileSection.dataSize);
		}
		_listPeSection.push_back(peFileSection);
		pSectionHeader++;
	}

	//get sections gap data
	std::vector<PeFileSection> listPeSectionSort;
	for (std::vector<PeFileSection>::iterator it = _listPeSection.begin(); it != _listPeSection.end(); it++){
		if ((*it).data)
			listPeSectionSort.push_back(*it);
	}
	std::sort(listPeSectionSort.begin(), listPeSectionSort.end(), SortByPointerToRawData);
	for (std::vector<PeFileSection>::iterator it = listPeSectionSort.begin(); it != listPeSectionSort.end(); it++){

		DWORD dwCurSectionEnd = (*it).sectionHeader.PointerToRawData + (*it).sectionHeader.SizeOfRawData;
		DWORD dwNextSectionBegin = 0;
		if (it + 1 != listPeSectionSort.end()){
			dwNextSectionBegin = (*(it+1)).sectionHeader.PointerToRawData;
		}
		else{
			if (IsPe32())
				dwNextSectionBegin = _pNTHeader32->OptionalHeader.SizeOfImage;
			else dwNextSectionBegin = _pNTHeader64->OptionalHeader.SizeOfImage;

		}
		if (dwNextSectionBegin > dwCurSectionEnd){
			(*it).dwAlignGapLen = dwNextSectionBegin - dwCurSectionEnd;
			(*it).pAlignGap = (BYTE*)LocalAlloc(LPTR, (*it).dwAlignGapLen);
			memcpy_s((*it).pAlignGap, (*it).dwAlignGapLen, (unsigned char*)pData + pSectionHeader->PointerToRawData, (*it).dwAlignGapLen);
			break;
		}
		else{
			if (it + 1 != listPeSectionSort.end()){
				;// sections overlay
			}
			else{
				;//header data has err
			}
		}
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
DWORD PeTool::CalcSizeByPeContent()
{
	DWORD nNeedSize = 0;
	nNeedSize += sizeof(IMAGE_DOS_HEADER);
	nNeedSize += _dwDosStubSize;
	nNeedSize += _dwNtHeaderSize;
	if (IsPe32())
		nNeedSize += _pNTHeader32->FileHeader.NumberOfSections*sizeof(IMAGE_SECTION_HEADER);
	else
		nNeedSize += _pNTHeader64->FileHeader.NumberOfSections*sizeof(IMAGE_SECTION_HEADER);
	nNeedSize += _dwAlignGapLen;
	for (std::vector<PeFileSection>::iterator it = _listPeSection.begin(); it != _listPeSection.end(); it++){
		nNeedSize += (*it).dataSize;
		nNeedSize += (*it).dwAlignGapLen;
	}
	nNeedSize += _dwOverlaySize;
	return nNeedSize;
}
void* PeTool::SaveToPeBuffer(DWORD *nSize){
	DWORD nLeftSize = CalcSizeByPeContent();
	*nSize = nLeftSize;
	BYTE* pOutPe = (BYTE*)LocalAlloc(LPTR, nLeftSize);

	LPCVOID lpCopyBuffer = NULL; DWORD nCopy = 0;
	unsigned char* pWritePtr = (unsigned char*)pOutPe;
	//write dos header
	memcpy_s(pWritePtr, nLeftSize, _pDosHeader, sizeof(IMAGE_DOS_HEADER));
	pWritePtr += sizeof(IMAGE_DOS_HEADER);
	nLeftSize -= sizeof(IMAGE_DOS_HEADER);

	//write dos stub
	memcpy_s(pWritePtr, nLeftSize, _pDosStub, _dwDosStubSize);
	pWritePtr += _dwDosStubSize;
	nLeftSize -= _dwDosStubSize;

	//write nt header 
	lpCopyBuffer = (char*)_pNTHeader32 ? (char*)_pNTHeader32 : (char*)_pNTHeader64;
	nCopy = (char*)_pNTHeader32 ? sizeof(IMAGE_NT_HEADERS32) : sizeof(IMAGE_NT_HEADERS64);
	memcpy_s(pWritePtr, nLeftSize, lpCopyBuffer, nCopy);
	pWritePtr += nCopy;
	nLeftSize -= nCopy;

	//write section headers
	bool bWrittenSectionHeaders = true;
	for (std::vector<PeFileSection>::iterator it = _listPeSection.begin(); it != _listPeSection.end(); it++){
		memcpy_s(pWritePtr, nLeftSize, &(*it).sectionHeader, sizeof(IMAGE_SECTION_HEADER));
		pWritePtr += sizeof(IMAGE_SECTION_HEADER);
		nLeftSize -= sizeof(IMAGE_SECTION_HEADER);
	}

	//write file align gap
	memcpy_s(pWritePtr, nLeftSize, _pAlignGap, _dwAlignGapLen);
	pWritePtr += _dwAlignGapLen;
	nLeftSize -= _dwAlignGapLen;

	//write sections and gap data, do not need sort 
	bool bWrittenSections = true;
	for (std::vector<PeFileSection>::iterator it = _listPeSection.begin(); it != _listPeSection.end(); it++){
		if (!(*it).data)
			continue;
		memcpy_s(pWritePtr, nLeftSize, (*it).data, (*it).dataSize);
		pWritePtr += (*it).dataSize;
		nLeftSize -= (*it).dataSize;
		if (!(*it).pAlignGap)
			continue;
		memcpy_s(pWritePtr, nLeftSize, (*it).pAlignGap, (*it).dwAlignGapLen);
		pWritePtr += (*it).dwAlignGapLen;
		nLeftSize -= (*it).dwAlignGapLen;
	}
	//write overlay data
	if (_pOverlayData){
		memcpy_s(pWritePtr, nLeftSize, _pOverlayData, _dwOverlaySize);
		pWritePtr += _dwOverlaySize;
		nLeftSize -= _dwOverlaySize;
	}

	return pOutPe;
}
bool PeTool::SaveToPeFileW(wchar_t* szPathFileW){
	DWORD nSize = 0;
	PVOID pOutPe = SaveToPeBuffer(&nSize);
	bool bRet = Buffer2FileW(szPathFileW, pOutPe, nSize);
	LocalFree(pOutPe);
	return bRet;
}

bool PeTool::SaveToPeFile(char* szPathFile){
	WCHAR szPathFileW[MAX_PATH] = { 0 };
	MultiByteToWideChar(CP_ACP, NULL, szPathFile, -1, szPathFileW, _countof(szPathFileW));
	return SaveToPeFileW(szPathFileW);;
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
		DWORD nSize;
		char* pData = (char*)File2Buffer(&nSize, szModuleName);
		PeTool pe;
		pe.InitFromNotMapedPeBuffer(pData, nSize);
		char szModuleNameSave[0x1100] = { 0 };
		strcpy(szModuleNameSave, szModuleName);
		strcat(szModuleNameSave, ".save.exe");
		pe.SaveToPeFile(szModuleNameSave);
		Test_CompareFile(szModuleName, szModuleNameSave);
	}
	ExitProcess(0);
}

