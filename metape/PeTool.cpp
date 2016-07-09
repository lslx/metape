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

	std::vector<PeFileSection> listPeSectionSort;
	std::sort(listPeSectionSort.begin(), listPeSectionSort.end(), bHasMaped ? SortByVirtualAddress : SortByPointerToRawData);


	for (std::vector<PeFileSection>::iterator it = listPeSectionSort.begin(); it != listPeSectionSort.end(); it++){
		PIMAGE_SECTION_HEADER pSectionHeader = &(*it).sectionHeader;
		pSectionHeader->PointerToRawData;
		pSectionHeader->VirtualAddress;

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
bool PeTool::AddAddrInfo(PAddrInfo pAddrInfo){
	bool bAdd = false;
	NodeInfo nodeInfo;
	nodeInfo.Addr = pAddrInfo->Addr;
	nodeInfo.listAddrInfo.push_back(*pAddrInfo);
	for (std::list<NodeInfo>::iterator it = _listNodeInfo.begin(); it != _listNodeInfo.end(); it++){
		if (nodeInfo.Addr == (*it).Addr){
			(*it).Addr = nodeInfo.Addr;
			(*it).listAddrInfo.push_back(*pAddrInfo);
			bAdd = true;
			break;
		}
		else if ((*it).Addr > nodeInfo.Addr){
			_listNodeInfo.insert(it, nodeInfo);
			bAdd = true;
			break;
		}
	}
	if (!bAdd){
		_listNodeInfo.push_back(nodeInfo);
		bAdd = true;
	}
	return bAdd;
}
bool PeTool::FixMapedPeSectionsEndAddrInfo(){
	std::list<AddrInfo> listAddrInfoTmp;
	AddrInfo AddrEnd;
	for (std::list<NodeInfo>::iterator it = _listNodeInfo.begin(); it != _listNodeInfo.end(); it++){
		for(std::list<AddrInfo>::iterator it2 = (*it).listAddrInfo.begin(); it2 != (*it).listAddrInfo.end(); it2++){
			if (euSection == (*it2).eType  && eptBegin == (*it2).eptType){
				listAddrInfoTmp.push_back(*it2);
			}
			if (euAllBuffer == (*it2).eType && eptEnd == (*it2).eptType){
				AddrEnd = (*it2);
			}
		}
	}
	AddrInfo addrInfoTmp;
	for (std::list<AddrInfo>::iterator it = listAddrInfoTmp.begin(); it != listAddrInfoTmp.end(); it++){
		if ((*it).dwIndex > 0){
			addrInfoTmp = (*it);
			addrInfoTmp.dwIndex = (*it).dwIndex - 1;
			addrInfoTmp.eptType = eptEnd;// fix me: think about SizeOfRawData.
			AddAddrInfo(&addrInfoTmp);
		}
	}
	if (!listAddrInfoTmp.empty()){
		AddrEnd.dwIndex = listAddrInfoTmp.back().dwIndex;
		AddrEnd.eType = euSection;
		AddrEnd.eptType = eptEnd;
		AddAddrInfo(&AddrEnd);
	}
	else{}// no section, think about this condition
	return true;
}
bool PeTool::GetSectionCountByAddrInfo(DWORD *pdwNum){
	DWORD dwSecNum = 0;
	for (std::list<NodeInfo>::iterator it = _listNodeInfo.begin(); it != _listNodeInfo.end(); it++){
		for (std::list<AddrInfo>::iterator it2 = (*it).listAddrInfo.begin(); it2 != (*it).listAddrInfo.end(); it2++){
			if (euSection == (*it2).eType  && eptBegin == (*it2).eptType){
				dwSecNum++;
			}
		}
	}
	if (dwSecNum){
		*pdwNum = dwSecNum;
		return true;
	}
	return false;
}
bool PeTool::CheckAddrListValid(){
	if (_listNodeInfo.empty())
		return false;
	DWORD dwLastAddr = 0;
	for (std::list<NodeInfo>::iterator it = _listNodeInfo.begin(); it != _listNodeInfo.end(); it++){
		if (it == _listNodeInfo.begin()){
			if ((*it).Addr != 0)
				return false;
		}
		else{
			if ((*it).Addr <= dwLastAddr)
				return false;
			dwLastAddr = (*it).Addr;
		}
	}
	if (_listNodeInfo.back().listAddrInfo.empty())
		return false;
	bool bBufferEndAtLast = false;
	std::list<AddrInfo>::iterator it = _listNodeInfo.back().listAddrInfo.begin();
	for (; it != _listNodeInfo.back().listAddrInfo.end(); it++){
		if (euAllBuffer == (*it).eType && eptEnd == (*it).eptType){
			bBufferEndAtLast = true;
		}
	}
	if (false == bBufferEndAtLast)
		return false;
	return true;
}
bool PeTool::InitAddrInfoFromPeBuffer(bool bHasMaped, void *pData, DWORD nSize){
	IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)pData;
	IMAGE_NT_HEADERS32 *pNTHeader32Tmp = (IMAGE_NT_HEADERS32*)((unsigned char*)pData + dos->e_lfanew);
	IMAGE_NT_HEADERS32 *nt32 = 0;
	IMAGE_NT_HEADERS32 *nt64 = 0;
	DWORD dwMapedSize = 0;
	if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == pNTHeader32Tmp->OptionalHeader.Magic){
		nt32 = pNTHeader32Tmp;
		dwMapedSize = nt32->OptionalHeader.SizeOfImage;
	}
	else if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == pNTHeader32Tmp->OptionalHeader.Magic){
		nt64 = pNTHeader32Tmp;
		dwMapedSize = nt64->OptionalHeader.SizeOfImage;
	}
	else{
		return false;
	}
	AddrInfo addrInfo;
	addrInfo.Addr = 0;
	addrInfo.eType = euAllBuffer;
	addrInfo.eptType = eptBegin;
	AddAddrInfo(&addrInfo);
	addrInfo.Reset();
	if (bHasMaped)
		addrInfo.Addr = dwMapedSize;
	else
		addrInfo.Addr = nSize;
	addrInfo.eType = euAllBuffer;
	addrInfo.eptType = eptEnd;
	AddAddrInfo(&addrInfo);
	addrInfo.Reset();
	addrInfo.Addr = 0;
	addrInfo.eType = euDosHeader;
	addrInfo.eptType = eptBegin;
	AddAddrInfo(&addrInfo);
	addrInfo.Reset();
	addrInfo.Addr = (DWORD)sizeof(IMAGE_DOS_HEADER);
	addrInfo.eType = euDosHeader;
	addrInfo.eptType = eptEnd;
	AddAddrInfo(&addrInfo);
	addrInfo.Reset();
	addrInfo.Addr = (DWORD)sizeof(IMAGE_DOS_HEADER);
	addrInfo.eType = euDosStub;
	addrInfo.eptType = eptBegin;
	AddAddrInfo(&addrInfo);
	addrInfo.Reset();
	addrInfo.Addr = (DWORD)dos->e_lfanew;
	addrInfo.eType = euDosStub;
	addrInfo.eptType = eptEnd;
	AddAddrInfo(&addrInfo);
	addrInfo.Reset();
	addrInfo.Addr = (DWORD)dos->e_lfanew;
	addrInfo.eType = euNtHeader;
	addrInfo.eptType = eptBegin;
	AddAddrInfo(&addrInfo);
	addrInfo.Reset();

	DWORD ntSize = sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+pNTHeader32Tmp->FileHeader.SizeOfOptionalHeader;
	addrInfo.Addr = DWORD((char*)dos->e_lfanew + ntSize);
	addrInfo.eType = euNtHeader;
	addrInfo.eptType = eptEnd;
	AddAddrInfo(&addrInfo);

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeader32Tmp);
	WORD nSection = pNTHeader32Tmp->FileHeader.NumberOfSections;
	addrInfo.eType = euSection;
	for (WORD i = 0; i < nSection; i++){
		addrInfo.dwIndex = i;
		if (bHasMaped){
			addrInfo.Addr = DWORD(pSectionHeader[i].VirtualAddress);			
			addrInfo.eptType = eptBegin;
			AddAddrInfo(&addrInfo);
		}
		else{
			if (pSectionHeader[i].PointerToRawData){
				addrInfo.Addr = DWORD(pSectionHeader[i].PointerToRawData);
				addrInfo.eptType = eptBegin;
				AddAddrInfo(&addrInfo);
			}
		}
		if (bHasMaped){
			addrInfo.Addr = DWORD(pSectionHeader[i].VirtualAddress + 0/*i don't known, it's over write*/);
			addrInfo.eptType = eptEnd;
			//-- AddAddrInfo(Addr, &addrInfo);//we can calc it laster
		}
		else{
			if (pSectionHeader[i].PointerToRawData){
				addrInfo.Addr = DWORD(pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData);
				addrInfo.eptType = eptEnd;
				AddAddrInfo(&addrInfo);			
			}
		}
	}

	if (bHasMaped){
		FixMapedPeSectionsEndAddrInfo();
	}

	//overlay data
	if (!bHasMaped){
		DWORD dwBegin = 0; DWORD dwEnd = 0; DWORD dwSize = 0;
		if (!GetDataAddrInfo(euSection, &dwBegin, &dwEnd,nSection-1))
			return false;
		addrInfo.Reset();
		addrInfo.Addr = (DWORD)dwEnd;
		addrInfo.eType = euOverLay;
		addrInfo.eptType = eptBegin;
		AddAddrInfo(&addrInfo);
	
		addrInfo.Reset();
		addrInfo.Addr = nSize;
		addrInfo.eType = euOverLay;
		addrInfo.eptType = eptEnd;
		AddAddrInfo(&addrInfo);
	}

	bool bIsValid = CheckAddrListValid();
	return bIsValid;
}
bool PeTool::GetDataAddrInfo(E_EntityType eType, DWORD *pdwBengin, DWORD *pdwEnd, DWORD dwIndex){
	bool bFindBegin = false;
	bool bFindEnd = false;
	DWORD dwBegin = 0;
	DWORD dwEnd = 0;
	for (std::list<NodeInfo>::iterator it = _listNodeInfo.begin(); it != _listNodeInfo.end(); it++){
		for (std::list<AddrInfo>::iterator it2 = (*it).listAddrInfo.begin(); it2 != (*it).listAddrInfo.end(); it2++){
			if (eType == (*it2).eType && eptBegin == (*it2).eptType){
				if (euSection == eType){
					if ((*it2).dwIndex == dwIndex){
						dwBegin = (*it2).Addr;
						bFindBegin = true;
					}
				}
				else{
						dwBegin = (*it2).Addr;
						bFindBegin = true;
				}
			}
			if (eType == (*it2).eType && eptEnd == (*it2).eptType){
				if (euSection == eType){
					if ((*it2).dwIndex == dwIndex){
						dwEnd = (*it2).Addr;
						bFindEnd = true;
					}
				}
				else{
					dwEnd = (*it2).Addr;
					bFindEnd = true;
				}
			}
		}
	}
	if (!bFindBegin || !bFindEnd)
		return false;
	*pdwBengin = dwBegin;
	*pdwEnd = dwEnd;
	return true;
}
// to do: add alloc failed process 
bool PeTool::InitFromPeBuffer(bool bHasMaped, void *pData, DWORD nSize){
	if (!InitAddrInfoFromPeBuffer(bHasMaped, pData, nSize))
		return false;
	unsigned char* pReadPtr = (unsigned char*)pData;
	//bool bLog = true;
	LogA("Init From not Maped Pe Buffer Begin");
	//get dos header
	DWORD dwBegin = 0; DWORD dwEnd = 0; DWORD dwSize = 0;
	while (true){
		//dos header
		if (!GetDataAddrInfo(euDosHeader, &dwBegin, &dwEnd))
			break;
		dwSize = dwEnd - dwBegin;
		_pDosHeader = (PIMAGE_DOS_HEADER)LocalAlloc(LPTR, dwSize);
		if (!_pDosHeader)
			break;
		LogA("Read dos header from:0x%p to: 0x%p", pReadPtr, _pDosHeader);
		memcpy(_pDosHeader, pReadPtr, dwSize);
		pReadPtr += dwSize;
		Report_DosHeader(_pDosHeader);

		//get dos stub
		if (!GetDataAddrInfo(euDosStub, &dwBegin, &dwEnd))
			break;
		dwSize = dwEnd - dwBegin;
		_pDosStub = (BYTE *)LocalAlloc(LPTR, dwSize);
		if (!_pDosStub)
			break;
		LogA("Read dos stub from:0x%p to: 0x%p", pReadPtr, _pDosStub);
		memcpy(_pDosStub, pReadPtr, dwSize);
		pReadPtr += dwSize;
		Reprt_DosStub(_pDosStub, dwSize);
		_dwDosStubSize = dwSize;//------------ fix other size  

		//get nt header
		if (!GetDataAddrInfo(euNtHeader, &dwBegin, &dwEnd))
			break;
		dwSize = dwEnd - dwBegin;
		PIMAGE_NT_HEADERS32 pNTHeader32Tmp = (PIMAGE_NT_HEADERS32)((unsigned char*)pData + _pDosHeader->e_lfanew);
		if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == pNTHeader32Tmp->OptionalHeader.Magic){
			_pNTHeader32 = (PIMAGE_NT_HEADERS32)LocalAlloc(LPTR, dwSize);
			if (!_pNTHeader32)
				break;
			LogA("Read Nt Header 32 from:0x%p to: 0x%p", pReadPtr, _pNTHeader32);
			memcpy(_pNTHeader32, pReadPtr, dwSize);
			Report_NtHeader32(_pNTHeader32);
		}
		else if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == pNTHeader32Tmp->OptionalHeader.Magic){
			_pNTHeader64 = (PIMAGE_NT_HEADERS64)LocalAlloc(LPTR, dwSize);
			if (!_pNTHeader64)
				break;
			LogA("Read Nt Header 64 from:0x%p to: 0x%p", pReadPtr, _pNTHeader64);
			memcpy(_pNTHeader64, pReadPtr, dwSize);
			Report_NtHeader64(_pNTHeader64);
		}
		else{
			LogA("Error: Nt Header Magic not support 0x%x", pNTHeader32Tmp->OptionalHeader.Magic);
			break;
		}
		pReadPtr += dwSize;
		_dwNtHeaderSize = dwSize;

		// Section headers and Section data
		WORD nSection = pNTHeader32Tmp->FileHeader.NumberOfSections;
		PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeader32Tmp);
		LogA("First image section at : 0x%p number : %d", pSectionHeader, nSection);
		_listPeSection.clear();
		_listPeSection.reserve(nSection);
		bool bSectionDone = true;
		for (WORD i = 0; i < nSection; i++){
			PeFileSection peFileSection;
			memcpy_s(&peFileSection.sectionHeader, sizeof(IMAGE_SECTION_HEADER), pSectionHeader, sizeof(IMAGE_SECTION_HEADER));
			if (!GetDataAddrInfo(euSection, &dwBegin, &dwEnd, i))
				break;
			dwSize = dwEnd - dwBegin;
			peFileSection.data = (BYTE*)LocalAlloc(LPTR, dwSize);
			if (!peFileSection.data)
				break;
			memcpy_s(peFileSection.data, dwSize, (unsigned char*)pData + dwBegin, dwSize);
			peFileSection.dataSize = dwSize;
			_listPeSection.push_back(peFileSection);
			pSectionHeader++;
		}
		if (!bSectionDone)
			break;

		// overlay data
		if (!bHasMaped){
			if (!GetDataAddrInfo(euOverLay, &dwBegin, &dwEnd))
				break;
			dwSize = dwEnd - dwBegin;
			if (dwSize){
				_pOverlayData = (BYTE*)LocalAlloc(LPTR, dwSize);
				if (!_pOverlayData)
					break;
				memcpy_s(_pOverlayData, _dwOverlaySize,(char*)pData + dwBegin, dwSize);
				_dwOverlaySize = dwSize;
			}
		}
		if (bHasMaped)
			_eStatus = eMaped;
		else _eStatus = eNotMaped;
		return true;
	}
	ClearAll(false);
	return false;
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
	for (std::vector<PeFileSection>::iterator it = _listPeSection.begin(); it != _listPeSection.end(); it++){
		nNeedSize += (*it).dataSize;
	}
	if (eNotMaped == _eStatus)
		nNeedSize += _dwOverlaySize;
	return nNeedSize;
}
char* PeTool::SaveToPeBuffer(DWORD *nSize){

	DWORD dwBegin = 0; DWORD dwEnd = 0; DWORD dwSize = 0;
	if (!GetDataAddrInfo(euAllBuffer, &dwBegin, &dwEnd))
		return NULL;
	dwSize = dwEnd - dwBegin;
	BYTE* pOutPe = (BYTE*)LocalAlloc(LPTR, dwSize);
	if (!pOutPe)
		return NULL;
	while (true){
		//write dos header
		if (!GetDataAddrInfo(euDosHeader, &dwBegin, &dwEnd))
			break;
		dwSize = dwEnd - dwBegin;
		memcpy(pOutPe + dwBegin, _pDosHeader, dwSize);

		//write dos stub
		if (!GetDataAddrInfo(euDosStub, &dwBegin, &dwEnd))
			break;
		dwSize = dwEnd - dwBegin;
		memcpy(pOutPe + dwBegin, _pDosStub, dwSize);

		//write nt header 
		if (!GetDataAddrInfo(euNtHeader, &dwBegin, &dwEnd))
			break;
		dwSize = dwEnd - dwBegin;
		char* lpCopyBuffer = (char*)_pNTHeader32 ? (char*)_pNTHeader32 : (char*)_pNTHeader64;
		memcpy(pOutPe + dwBegin, lpCopyBuffer, dwSize);

		//write section headers
		IMAGE_SECTION_HEADER* pFirstSecHeader = (IMAGE_SECTION_HEADER*)(pOutPe + dwBegin + dwSize);
		for (std::vector<PeFileSection>::iterator it = _listPeSection.begin(); it != _listPeSection.end(); it++){
			memcpy(pFirstSecHeader, &(*it).sectionHeader, sizeof(IMAGE_SECTION_HEADER));
			pFirstSecHeader++;
		}

		//write sections, do not need sort 
		bool bHasWriteAll = true;
		for (std::vector<PeFileSection>::iterator it = _listPeSection.begin(); it != _listPeSection.end(); it++){
			if (!(*it).data)
				continue;
			DWORD dwIndex = it - _listPeSection.begin();
			if (!GetDataAddrInfo(euSection, &dwBegin, &dwEnd, dwIndex)){
				bHasWriteAll = false;
				break;
			}
			dwSize = dwEnd - dwBegin;
			memcpy(pOutPe + dwBegin, (*it).data, dwSize);
		}
		if (false == bHasWriteAll)
			break;

		//write overlay data
		if (eNotMaped == _eStatus){
			if (!GetDataAddrInfo(euDosHeader, &dwBegin, &dwEnd))
				break;
			dwSize = dwEnd - dwBegin;
			memcpy(pOutPe + dwBegin, _pOverlayData, dwSize);
		}
		*nSize = dwSize;
		return (char*)pOutPe;
	}
	LocalFree(pOutPe);
	pOutPe = NULL;
	return (char*)NULL;
}
// bool PeTool::GetPointerInfo(DWORD64 pointer, PointerInfo* pPointerInfo){
// 	if (IsPe32()){
// 		;
// 	}
// 	return false;
// }
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
void PeTool::Test4()
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