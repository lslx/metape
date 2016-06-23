#include "PeTool.h"
#include "Tools.h"
#include <algorithm>
bool SortByPointerToRawData(const PeFileSection& d1, const PeFileSection& d2){
	return d1.sectionHeader.PointerToRawData < d2.sectionHeader.PointerToRawData;
}
bool SortByVirtualAddress(const PeFileSection& d1, const PeFileSection& d2){
	return d1.sectionHeader.VirtualAddress < d2.sectionHeader.VirtualAddress;
}
void Report_DosHeader(IMAGE_DOS_HEADER* pdosHeader){
	LogA("Report dos header detail from :0x%04X,size:0x%x:(%d)", pdosHeader,
		sizeof(IMAGE_DOS_HEADER), sizeof(IMAGE_DOS_HEADER));
	if (!pdosHeader){
		LogA("Error: dos header pointer is Null !");
		return;
	}
	IMAGE_DOS_HEADER& p = *pdosHeader;
	LogA("    e_magic : 0x%04X", p.e_magic);
	LogA("    e_cblp : 0x%04X", p.e_cblp);
	LogA("    e_cp : 0x%04X", p.e_cp);
	LogA("    e_crlc : 0x%04X", p.e_crlc);
	LogA("    e_cparhdr : 0x%04X", p.e_cparhdr);
	LogA("    e_minalloc : 0x%04X", p.e_minalloc);
	LogA("    e_maxalloc : 0x%04X", p.e_maxalloc);
	LogA("    e_ss : 0x%04X", p.e_ss);
	LogA("    e_sp : 0x%04X", p.e_sp);
	LogA("    e_csum : 0x%04X", p.e_csum);
	LogA("    e_ip : 0x%04X", p.e_ip);
	LogA("    e_cs : 0x%04X", p.e_cs);
	LogA("    e_lfarlc : 0x%04X", p.e_lfarlc);
	LogA("    e_res[4] : 0x%04X,0x%04X,0x%04X,0x%04X,", p.e_res[0], p.e_res[1], p.e_res[2], p.e_res[3]);
	LogA("    e_oemid : 0x%04X", p.e_oemid);
	LogA("    e_oeminfo : 0x%04X", p.e_oeminfo);
	LogA("    e_res2[10] : 0x%04X,0x%04X,0x%04X,0x%04X,0x%04X,0x%04X,0x%04X,0x%04X,0x%04X,0x%04X,", p.e_res2[0],
		p.e_res2[1], p.e_res2[2],p.e_res2[3], p.e_res2[4], p.e_res2[5], p.e_res2[6], p.e_res2[7], p.e_res2[8], p.e_res2[9]);
	LogA("    e_lfanew : 0x%08lX", p.e_lfanew);
}
void Reprt_DosStub(void* pDosStub,DWORD nSize){
	LogA("Report dos stub detail from :0x%04X,size:0x%x:(%d)", pDosStub,nSize,nSize);
	if (!pDosStub){
		LogA("Error: dos stub pointer is Null !");
		return;
	}
	HexDump((char*)pDosStub, nSize);
}
void Report_NtHeader32(IMAGE_NT_HEADERS32 *pNtHeader32){
	LogA("Report nt header 32 detail from :0x%04X,size:0x%x:(%d)", pNtHeader32,
		sizeof(IMAGE_NT_HEADERS32), sizeof(IMAGE_NT_HEADERS32));
	if (!pNtHeader32){
		LogA("Error: nt header 32 pointer is Null !");
		return;
	}
	IMAGE_NT_HEADERS32& p = *pNtHeader32;
	LogA("Signature : 0x%08X", p.Signature);
	LogA("FileHeader : offset:0x%08X,len:0x%08X", sizeof(p.Signature), sizeof(IMAGE_FILE_HEADER));
	IMAGE_FILE_HEADER& pfh = p.FileHeader;
	LogA("    Machine : 0x%04X", pfh.Machine);
	LogA("    NumberOfSections : 0x%04X", pfh.NumberOfSections);
	LogA("    TimeDateStamp : 0x%08X", pfh.TimeDateStamp);
	LogA("    PointerToSymbolTable : 0x%08X", pfh.PointerToSymbolTable);
	LogA("    NumberOfSymbols : 0x%08X", pfh.NumberOfSymbols);
	LogA("    SizeOfOptionalHeader : 0x%04X", pfh.SizeOfOptionalHeader);
	LogA("    Characteristics : 0x%04X", pfh.Characteristics);
	IMAGE_OPTIONAL_HEADER32& poh = p.OptionalHeader;
	LogA("OptionalHeader : offset:0x%08X,len:0x%08X", sizeof(p.Signature) + sizeof(IMAGE_FILE_HEADER), sizeof(IMAGE_OPTIONAL_HEADER32));
	LogA("Standard fields :");
	LogA("    Magic : 0x%04X", poh.Magic);
	LogA("    MajorLinkerVersion : 0x%01X", poh.MajorImageVersion);
	LogA("    MinorLinkerVersion : 0x%01X", poh.MinorLinkerVersion);
	LogA("    SizeOfCode : 0x%08X", poh.SizeOfCode);
	LogA("    SizeOfInitializedData : 0x%08X", poh.SizeOfInitializedData);
	LogA("    SizeOfUninitializedData : 0x%08X", poh.SizeOfUninitializedData);
	LogA("    AddressOfEntryPoint : 0x%08X", poh.AddressOfEntryPoint);
	LogA("    BaseOfCode : 0x%08X", poh.BaseOfCode);
	LogA("    BaseOfData : 0x%08X", poh.BaseOfData);
	LogA("NT additional fields :");
	LogA("    ImageBase : 0x%08X", poh.ImageBase);
	LogA("    SectionAlignment : 0x%08X", poh.SectionAlignment);
	LogA("    FileAlignment : 0x%08X", poh.FileAlignment);
	LogA("    MajorOperatingSystemVersion : 0x%04X", poh.MajorOperatingSystemVersion);
	LogA("    MinorOperatingSystemVersion : 0x%04X", poh.MinorOperatingSystemVersion);
	LogA("    MajorImageVersion : 0x%04X", poh.MajorImageVersion);
	LogA("    MinorImageVersion : 0x%04X", poh.MinorImageVersion);
	LogA("    MajorSubsystemVersion : 0x%04X", poh.MajorSubsystemVersion);
	LogA("    MinorSubsystemVersion : 0x%04X", poh.MinorSubsystemVersion);
	LogA("    Win32VersionValue : 0x%08X", poh.Win32VersionValue);
	LogA("    SizeOfImage : 0x%08X", poh.SizeOfImage);
	LogA("    SizeOfHeaders : 0x%08X", poh.SizeOfHeaders);
	LogA("    CheckSum : 0x%08X", poh.CheckSum);
	LogA("    Subsystem : 0x%04X", poh.Subsystem);
	LogA("    DllCharacteristics : 0x%04X", poh.DllCharacteristics);
	LogA("    SizeOfStackReserve : 0x%08X", poh.SizeOfStackReserve);
	LogA("    SizeOfStackCommit : 0x%08X", poh.SizeOfStackCommit);
	LogA("    SizeOfHeapReserve : 0x%08X", poh.SizeOfHeapReserve);
	LogA("    SizeOfHeapCommit : 0x%08X", poh.SizeOfHeapCommit);
	LogA("    LoaderFlags : 0x%08X", poh.LoaderFlags);
	LogA("    NumberOfRvaAndSizes : 0x%08X", poh.NumberOfRvaAndSizes);
	LogA("    image data directory :");
	;
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++){
		LogA("        VirtualAddress : 0x%08X , Size : 0x%08X", poh.DataDirectory[i].VirtualAddress,
			poh.DataDirectory[i].Size);
	}
}
void Report_NtHeader64(IMAGE_NT_HEADERS64 *pNtHeader64){
	LogA("Report nt header 64 detail from :0x%04X,size:0x%x:(%d)", pNtHeader64,
		sizeof(IMAGE_NT_HEADERS64), sizeof(IMAGE_NT_HEADERS64));
	if (!pNtHeader64){
		LogA("Error: nt header 32 pointer is Null !");
		return;
	}
	IMAGE_NT_HEADERS64& p = *pNtHeader64;
	LogA("Signature : 0x%08X", p.Signature);
	LogA("FileHeader : offset:0x%08X,len:0x%08X", sizeof(p.Signature), sizeof(IMAGE_FILE_HEADER));
	IMAGE_FILE_HEADER& pfh = p.FileHeader;
	LogA("    Machine : 0x%04X", pfh.Machine);
	LogA("    NumberOfSections : 0x%04X", pfh.NumberOfSections);
	LogA("    TimeDateStamp : 0x%08X", pfh.TimeDateStamp);
	LogA("    PointerToSymbolTable : 0x%08X", pfh.PointerToSymbolTable);
	LogA("    NumberOfSymbols : 0x%08X", pfh.NumberOfSymbols);
	LogA("    SizeOfOptionalHeader : 0x%04X", pfh.SizeOfOptionalHeader);
	LogA("    Characteristics : 0x%04X", pfh.Characteristics);
	IMAGE_OPTIONAL_HEADER64& poh = p.OptionalHeader;
	LogA("OptionalHeader : offset:0x%08X,len:0x%08X", sizeof(p.Signature) + sizeof(IMAGE_FILE_HEADER), sizeof(IMAGE_OPTIONAL_HEADER32));
	LogA("Standard fields :");
	LogA("    Magic : 0x%04X", poh.Magic);
	LogA("    MajorLinkerVersion : 0x%01X", poh.MajorImageVersion);
	LogA("    MinorLinkerVersion : 0x%01X", poh.MinorLinkerVersion);
	LogA("    SizeOfCode : 0x%08X", poh.SizeOfCode);
	LogA("    SizeOfInitializedData : 0x%08X", poh.SizeOfInitializedData);
	LogA("    SizeOfUninitializedData : 0x%08X", poh.SizeOfUninitializedData);
	LogA("    AddressOfEntryPoint : 0x%08X", poh.AddressOfEntryPoint);
	LogA("    BaseOfCode : 0x%08X", poh.BaseOfCode);
	//LogA("    BaseOfData : 0x%08X", poh.BaseOfData);//--64 del
	LogA("NT additional fields :");
	LogA("    ImageBase : 0x%08llX", poh.ImageBase);//--64
	LogA("    SectionAlignment : 0x%08X", poh.SectionAlignment);
	LogA("    FileAlignment : 0x%08X", poh.FileAlignment);
	LogA("    MajorOperatingSystemVersion : 0x%04X", poh.MajorOperatingSystemVersion);
	LogA("    MinorOperatingSystemVersion : 0x%04X", poh.MinorOperatingSystemVersion);
	LogA("    MajorImageVersion : 0x%04X", poh.MajorImageVersion);
	LogA("    MinorImageVersion : 0x%04X", poh.MinorImageVersion);
	LogA("    MajorSubsystemVersion : 0x%04X", poh.MajorSubsystemVersion);
	LogA("    MinorSubsystemVersion : 0x%04X", poh.MinorSubsystemVersion);
	LogA("    Win32VersionValue : 0x%08X", poh.Win32VersionValue);
	LogA("    SizeOfImage : 0x%08X", poh.SizeOfImage);
	LogA("    SizeOfHeaders : 0x%08X", poh.SizeOfHeaders);
	LogA("    CheckSum : 0x%08X", poh.CheckSum);
	LogA("    Subsystem : 0x%04X", poh.Subsystem);
	LogA("    DllCharacteristics : 0x%04X", poh.DllCharacteristics);//--64
	LogA("    SizeOfStackReserve : 0x%08llX", poh.SizeOfStackReserve);//--64
	LogA("    SizeOfStackCommit : 0x%08llX", poh.SizeOfStackCommit);//--64
	LogA("    SizeOfHeapReserve : 0x%08llX", poh.SizeOfHeapReserve);//--64
	LogA("    SizeOfHeapCommit : 0x%08llX", poh.SizeOfHeapCommit);//--64
	LogA("    LoaderFlags : 0x%08X", poh.LoaderFlags);
	LogA("    NumberOfRvaAndSizes : 0x%08X", poh.NumberOfRvaAndSizes);
	LogA("    image data directory :");
	;
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++){
		LogA("        VirtualAddress : 0x%08X , Size : 0x%08X", poh.DataDirectory[i].VirtualAddress,
			poh.DataDirectory[i].Size);
	}
}
bool PeTool::InitFromNotMapedPeBuffer(void *pData, DWORD nSize){
	unsigned char* pReadPtr = (unsigned char*)pData;
	//bool bLog = true;
	LogA("Init From not Maped Pe Buffer Begin");
	//get dos header
	_pDosHeader = (PIMAGE_DOS_HEADER)LocalAlloc(LPTR, sizeof(IMAGE_DOS_HEADER));
	LogA("Read dos header from:0x%p to: 0x%p", pReadPtr,_pDosHeader);
	memcpy(_pDosHeader, pReadPtr, sizeof(IMAGE_DOS_HEADER));
	pReadPtr += sizeof(IMAGE_DOS_HEADER);
	Report_DosHeader(_pDosHeader);

	//get dos stub
	_dwDosStubSize = _pDosHeader->e_lfanew - sizeof(IMAGE_DOS_HEADER);
	_pDosStub = (BYTE *)LocalAlloc(LPTR, _dwDosStubSize);
	LogA("Read dos stub from:0x%p to: 0x%p", pReadPtr, _pDosStub);
	memcpy(_pDosStub, pReadPtr, _dwDosStubSize);
	pReadPtr += _dwDosStubSize;
	Reprt_DosStub(_pDosStub, _dwDosStubSize);

	//get nt header
	PIMAGE_NT_HEADERS32 pNTHeader32Tmp = (PIMAGE_NT_HEADERS32)((unsigned char*)pData + _pDosHeader->e_lfanew);
	_dwNtHeaderSize = sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+pNTHeader32Tmp->FileHeader.SizeOfOptionalHeader;
	if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == pNTHeader32Tmp->OptionalHeader.Magic){
		_pNTHeader32 = (PIMAGE_NT_HEADERS32)LocalAlloc(LPTR, _dwNtHeaderSize);
		LogA("Read Nt Header 32 from:0x%p to: 0x%p", pReadPtr, _pNTHeader32);
		memcpy(_pNTHeader32, pReadPtr, _dwNtHeaderSize);
		Report_NtHeader32(_pNTHeader32);
	}
	else if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == pNTHeader32Tmp->OptionalHeader.Magic){
		_pNTHeader64 = (PIMAGE_NT_HEADERS64)LocalAlloc(LPTR, _dwNtHeaderSize);
		LogA("Read Nt Header 64 from:0x%p to: 0x%p", pReadPtr, _pNTHeader64);
		memcpy(_pNTHeader64, pReadPtr, _dwNtHeaderSize);
		Report_NtHeader64(_pNTHeader64);
	}
	else{
		LogA("Error: Nt Header Magic not support 0x%x", pNTHeader32Tmp->OptionalHeader.Magic);
		return false;
	}
	pReadPtr += _dwNtHeaderSize;

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeader32Tmp);
	WORD nSection = 0;
	if (IsPe32())
		nSection = _pNTHeader32->FileHeader.NumberOfSections;
	else nSection = _pNTHeader64->FileHeader.NumberOfSections;
	LogA("First image section at : 0x%p number : %d", pSectionHeader, nSection);
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

