#include "PeTool.h"
#include "Tools.h"
#include <algorithm>

extern "C" __declspec(dllexport) PRunInfo g_pRunInfo = 0;

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
bool PeTool::ListSection_Init(PIMAGE_SECTION_HEADER pSectionHeader, WORD nSection){
	if (!pSectionHeader || !nSection)
		return false;
	_listPeSection.clear();
	_listPeSection.reserve(nSection);
	for (WORD i = 0; i < nSection; i++){
		PeFileSection peFileSection;
		memcpy_s(&peFileSection.sectionHeader, sizeof(IMAGE_SECTION_HEADER),
			pSectionHeader, sizeof(IMAGE_SECTION_HEADER));
		_listPeSection.push_back(peFileSection);
		pSectionHeader++;
	}
	return true;
}
bool PeTool::ListSection_GetTheFirstSectionOffset(bool bHasMaped, DWORD *dwOffset){
	if (!_listPeSection.size())
		return false;

	for (std::vector<PeFileSection>::iterator it = _listPeSection.begin(); it != _listPeSection.end(); it++){
		PIMAGE_SECTION_HEADER pSectionHeader = &(*it).sectionHeader;
// 		if ((*it).data)
// 			listPeSectionSort.push_back(*it);
	}

// 	for (WORD i = 0; i < nSection; i++){
// 		if (!bHasMaped){
// 			if (pSectionHeader[i].PointerToRawData){//maybe zero (e.g.  .textbss )
// 				if (!firstOffset)
// 					firstOffset = pSectionHeader[i].PointerToRawData;
// 				else if (pSectionHeader[i].PointerToRawData < firstOffset)
// 					firstOffset = pSectionHeader[i].PointerToRawData;
// 			}
// 		}
// 		else{
// 			if (pSectionHeader[i].VirtualAddress){
// 				if (!firstOffset)
// 					firstOffset = pSectionHeader[i].VirtualAddress;
// 				else if (pSectionHeader[i].VirtualAddress < firstOffset)
// 					firstOffset = pSectionHeader[i].VirtualAddress;
// 			}
// 		}
// 	}
	return false;
}
// to do: add alloc failed process 
bool PeTool::InitFromPeBuffer(bool bHasMaped, void *pData, DWORD nSize){
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
		ClearAll(false);
		return false;
	}
	pReadPtr += _dwNtHeaderSize;

	WORD nSection = 0;
	if (IsPe32())
		nSection = _pNTHeader32->FileHeader.NumberOfSections;
	else nSection = _pNTHeader64->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeader32Tmp);
	LogA("First image section at : 0x%p number : %d", pSectionHeader, nSection);

	//init _listPeSection the first time, just copy headers
	if (!ListSection_Init(pSectionHeader, nSection)){
		ClearAll(false);
		return false;
	}

	//get File Align Gap, the first item maybe not the first in the memory ,so use loop
	DWORD dwFirstSectionOffset = 0;// GetFileAlign();
	if (!ListSection_GetTheFirstSectionOffset(bHasMaped, &dwFirstSectionOffset)){
		ClearAll(false);
		return false;
	}
	_dwAlignGapLen = dwFirstSectionOffset - ((char*)&pSectionHeader[nSection] - pData);//use nSection but nSection-1
	if (_dwAlignGapLen){
		_pAlignGap = (BYTE*)LocalAlloc(LPTR, _dwAlignGapLen);;
		memcpy_s(_pAlignGap, _dwAlignGapLen,
			&pSectionHeader[nSection], _dwAlignGapLen);
	}
	pSectionHeader = 0;// avoid to use it at below

	//get section headers and sections data without the gap data
	_listPeSection.clear();
	_listPeSection.reserve(nSection);
	for (WORD i = 0; i < nSection; i++){
		PeFileSection peFileSection;
		memcpy_s(&peFileSection.sectionHeader, sizeof(IMAGE_SECTION_HEADER), pSectionHeader,sizeof(IMAGE_SECTION_HEADER));
		if (bHasMaped){
			// if pe has maped, the information of Misc.VirtualSize had lost,
			// dwSizeOfData will not include uninitialized data
			DWORD dwSizeOfData = pSectionHeader->SizeOfRawData;
			// when bHasMaped is true , dwSizeOfData maybe zero, if(...) condition has bug , fix me
			if (dwSizeOfData && pSectionHeader->VirtualAddress){//maybe VirtualAddress point MZ(is zero),fix me
				peFileSection.dataSize = dwSizeOfData;
				peFileSection.data = (BYTE*)LocalAlloc(LPTR, peFileSection.dataSize);
				memcpy_s(peFileSection.data, peFileSection.dataSize, (unsigned char*)pData + pSectionHeader->VirtualAddress, peFileSection.dataSize);
			}
			else{//what the fuck condition
				LogA("Error: section header data is invalid dwSizeOfData:0x%x,VirtualAddress:0x%x",
					dwSizeOfData , pSectionHeader->VirtualAddress);
				ClearAll(false);
				return false;
			}
		}
		else{// process not maped pe
			DWORD dwSizeOfData = pSectionHeader->Misc.VirtualSize;
			if (pSectionHeader->Misc.VirtualSize > pSectionHeader->SizeOfRawData)
				dwSizeOfData = pSectionHeader->SizeOfRawData;
			//maybe PointerToRawData point MZ(is zero),fix me , or no data in not maped pe data
			if (dwSizeOfData && pSectionHeader->PointerToRawData){
				peFileSection.dataSize = dwSizeOfData;
				peFileSection.data = (BYTE*)LocalAlloc(LPTR, peFileSection.dataSize);
				memcpy_s(peFileSection.data, peFileSection.dataSize, (unsigned char*)pData + pSectionHeader->PointerToRawData, peFileSection.dataSize);
			}
			else{//what the fuck condition
				if (pSectionHeader->PointerToRawData){
					LogA("Error: section header data is invalid dwSizeOfData:0x%x,PointerToRawData:0x%x",
						dwSizeOfData, pSectionHeader->PointerToRawData);
					ClearAll(false);
					return false;
				}
				else{
					;// maybe should process , fix me
				}
			}
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
	std::sort(listPeSectionSort.begin(), listPeSectionSort.end(), bHasMaped ? SortByVirtualAddress:SortByPointerToRawData);
	for (std::vector<PeFileSection>::iterator itSort = listPeSectionSort.begin(); itSort != listPeSectionSort.end(); itSort++){
		DWORD dwCurDataOffset = bHasMaped ? (*itSort).sectionHeader.VirtualAddress : (*itSort).sectionHeader.PointerToRawData;
		//warning: when bHasMaped is true, dwCurSectionEnd is not the real end,because uninitialized data len unknown
		// that can calc by VirtualSize which the information has lost
		DWORD dwCurDataEnd = 0;
		if (bHasMaped){
			dwCurDataEnd = dwCurDataOffset + (*itSort).sectionHeader.SizeOfRawData;
		}
		else{
			dwCurDataEnd = dwCurDataOffset + (*itSort).sectionHeader.Misc.VirtualSize;
			if ((*itSort).sectionHeader.Misc.VirtualSize > (*itSort).sectionHeader.SizeOfRawData)
				dwCurDataEnd = dwCurDataOffset + (*itSort).sectionHeader.SizeOfRawData;
		}
		DWORD dwNextSectionBegin = 0;
		if (itSort + 1 != listPeSectionSort.end()){
			dwNextSectionBegin = bHasMaped ? (*(itSort + 1)).sectionHeader.VirtualAddress : (*(itSort + 1)).sectionHeader.PointerToRawData;
		}
		else{
			//now itSort is the last, don't worry , 
			//it must be the last in no sort and has all item one (because the push condition)
			if (IsPe32())
				dwNextSectionBegin = bHasMaped ? _pNTHeader32->OptionalHeader.SizeOfImage:nSize;
			else dwNextSectionBegin = bHasMaped ? _pNTHeader64->OptionalHeader.SizeOfImage:nSize;

		}
		if (dwNextSectionBegin > dwCurDataEnd){
			(*itSort).dwAlignGapLen = dwNextSectionBegin - dwCurDataEnd;
			(*itSort).pAlignGap = (BYTE*)LocalAlloc(LPTR, (*itSort).dwAlignGapLen);
			//warning: when bHasMaped is true, dwAlignGapLen include the uninitialized data
			memcpy_s((*itSort).pAlignGap, (*itSort).dwAlignGapLen, (unsigned char*)pData
				+ dwCurDataEnd, (*itSort).dwAlignGapLen);
		}
		else if (dwNextSectionBegin == dwCurDataEnd){
			;// no gap here, do nothing
		}
		else{
			if (itSort + 1 != listPeSectionSort.end()){
				// sections overwrite
				LogA("Error: sections overwrite !");
				ClearAll(false);
				return false;
			}
			else{
				//section header data has err
				LogA("Error: section header data has err !");
				ClearAll(false);
				return false;
			}
		}
	}
	// assign to _listPeSection
	for (std::vector<PeFileSection>::iterator itSort = listPeSectionSort.begin(); itSort != listPeSectionSort.end(); itSort++){
		for (std::vector<PeFileSection>::iterator it = _listPeSection.begin(); it != _listPeSection.end(); it++){
			// don't worry when (*it).data is zero, because (*itSort).data always not zero
			if ((*itSort).data == (*it).data){
				(*it).pAlignGap = (*itSort).pAlignGap;
				(*it).dwAlignGapLen = (*itSort).dwAlignGapLen;
			}
		}
	}
	listPeSectionSort.clear();

	if (!bHasMaped){
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
				(char*)pData + lastRawOffset + lastRawSize, _dwOverlaySize);
		}
	}
	if (bHasMaped)
		_eStatus = eMaped;
	else _eStatus = eNotMaped;
	return true;
}
bool PeTool::InitFromPeFileW(wchar_t* szPathFileW){
	DWORD nSize;
	unsigned char* pData = (unsigned char*)File2BufferW(&nSize, szPathFileW);
	if (!pData)
		return false;
	return InitFromPeBuffer(false,pData, nSize);
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
	if (eNotMaped == _eStatus)
		nNeedSize += _dwOverlaySize;
	return nNeedSize;
}
char* PeTool::SaveToPeBuffer(DWORD *nSize){
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

	//write file or memory page align gap, actually align to the next stuff begin
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
	if (eNotMaped == _eStatus){
		//write overlay data
		if (_pOverlayData){
			memcpy_s(pWritePtr, nLeftSize, _pOverlayData, _dwOverlaySize);
			pWritePtr += _dwOverlaySize;
			nLeftSize -= _dwOverlaySize;
		}
	}
	return (char*)pOutPe;
}
bool PeTool::GetPointerInfo(DWORD64 pointer, PointerInfo* pPointerInfo){
	if (IsPe32()){
		;
	}
	return false;
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
		pe.InitFromPeBuffer(false,pData, nSize);
		char szModuleNameSave[0x1100] = { 0 };
		strcpy(szModuleNameSave, szModuleName);
		strcat(szModuleNameSave, ".save.exe");
		pe.SaveToPeFile(szModuleNameSave);
		Test_CompareFile(szModuleName, szModuleNameSave);
	}
}
char* PeTool::GetOverlayData(DWORD *pnSize){
	if (!_pOverlayData || !_dwOverlaySize){
		*pnSize = 0;
		return NULL;
	}
	char* pData = (char*)LocalAlloc(LPTR, _dwOverlaySize);
	if (pData){
		memcpy(_pOverlayData, pData, _dwOverlaySize);
		*pnSize = _dwOverlaySize;
		return pData;
	}
	*pnSize = 0;
	return NULL;
}
bool PeTool::SetOverlayData(char* pData, DWORD nSize){
	if (!pData || !nSize)
		return false;
	LPVOID pTmp = LocalAlloc(LPTR, nSize);
	if (pTmp){
		if (_pOverlayData)
			LocalFree(_pOverlayData);
		_pOverlayData = (BYTE*)pTmp;
		_dwOverlaySize = nSize;
		memcpy(_pOverlayData, pData,_dwOverlaySize);
		return true;
	}
	return false;
}
bool PeTool::AddToOverlayData(char* pData, DWORD nSize){
	if (!pData || !nSize)
		return false;
	BYTE* pTmp = NULL;
	pTmp = (BYTE*)LocalAlloc(LPTR, _dwOverlaySize + nSize);
	if (pTmp){
		if (_pOverlayData && _dwOverlaySize){
			memcpy(pTmp, _pOverlayData, _dwOverlaySize);
		}
		memcpy(pTmp + _dwOverlaySize, pData, nSize);
		if (_pOverlayData)
			LocalFree(_pOverlayData);
		_pOverlayData = pTmp;
		_dwOverlaySize = _dwOverlaySize + nSize;
		return true;
	}
	return false;
}
void PeTool::DeleteOverlayData(){
	if (_pOverlayData)
		LocalFree(_pOverlayData);
	_pOverlayData = NULL;
	_dwOverlaySize = 0;
}
void PeTool::Test2()
{
	PRunInfo& g_p = g_pRunInfo;
	if (g_p){
		char szModuleName[0x1100] = { 0 };
		if (GetModuleFileNameA(GetModuleHandleA(NULL), (LPCH)szModuleName, sizeof(szModuleName)-0x100))
		{
			DWORD nSize;
			char* pData = (char*)File2Buffer(&nSize, szModuleName);
			PeTool pe;
			pe.InitFromPeBuffer(false, pData, nSize);
			char myOverLayData[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
			if (pe.SetOverlayData(myOverLayData, 8)){
				char szModuleNameSave[0x1100] = { 0 };
				strcpy(szModuleNameSave, szModuleName);
				strcat(szModuleNameSave, ".save.exe");
				pe.SaveToPeFile(szModuleNameSave);
				Test_CompareFile(szModuleName, szModuleNameSave);
				return;

			}

		}
	}
}
void PeTool::Test3()
{
	PRunInfo& g_p = g_pRunInfo;
	if (g_p){
		if (g_p->pCopyMemImage){
			PeTool pe;
			if (pe.InitFromMapedPeBuffer(g_p->pCopyMemImage)){
				DWORD nSize = 0;
				void* pData = pe.SaveToPeBuffer(&nSize);
				if (pData){
					Test_CompareBuffer((char*)g_p->pCopyMemImage, nSize, (char*)pData, nSize);
					return ;
				}
			}
		}
	}
	ExitProcess(0);
}