#include "ReflectiveLoader.h"

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
void PeTool::Test5()
{
	IMAGE_DOS_HEADER dos;
	dos.e_magic = IMAGE_DOS_SIGNATURE;
	dos.e_cblp = 0x0090;
	dos.e_cp = 0x0003;
	dos.e_crlc = 0x0000;
	dos.e_cparhdr = 0x0004;
	dos.e_minalloc = 0x0000;
	dos.e_maxalloc = 0xffff;
	dos.e_ss = 0x0000;
	dos.e_sp = 0x00b8;
	dos.e_csum = 0x0000;
	dos.e_ip = 0x0000;
	dos.e_cs = 0x0000;
	dos.e_lfarlc = 0x0040;
	dos.e_ovno = 0x0000;
	dos.e_res[4] = {0};
	dos.e_oemid = 0x0000;
	dos.e_oeminfo = 0x0000;
	dos.e_res2[10] = {0};
	dos.e_lfanew = 0x00000108;
	IMAGE_NT_HEADERS32 nt;
	nt.Signature = IMAGE_NT_SIGNATURE;
	nt.FileHeader.Machine = 0x014c;
	nt.FileHeader.NumberOfSections = 0x0007;
	nt.FileHeader.TimeDateStamp = 0x57818ce7;
	nt.FileHeader.PointerToSymbolTable = 0x00000000;
	nt.FileHeader.NumberOfSymbols = 0x00000000;
	nt.FileHeader.SizeOfOptionalHeader = 0x00e0;
	nt.FileHeader.Characteristics = 0x0102;
	// Standard fields.
	nt.OptionalHeader.Magic = 0x010b;
	nt.OptionalHeader.MajorLinkerVersion = 0x0c;
	nt.OptionalHeader.MinorLinkerVersion = 0x00;
	nt.OptionalHeader.SizeOfCode = 0x00257e00;
	nt.OptionalHeader.SizeOfInitializedData = 0x00086800;
	nt.OptionalHeader.SizeOfUninitializedData = 0x00000000;
	nt.OptionalHeader.AddressOfEntryPoint = 0x0011f195;
	nt.OptionalHeader.BaseOfCode = 0x00001000;
	nt.OptionalHeader.BaseOfData = 0x00001000;
	// NT additional fields.
	nt.OptionalHeader.ImageBase = 0x00850000;
	nt.OptionalHeader.SectionAlignment = 0x00001000;
	nt.OptionalHeader.FileAlignment = 0x00000200;
	nt.OptionalHeader.MajorOperatingSystemVersion = 0x0006;
	nt.OptionalHeader.MinorOperatingSystemVersion = 0x0000;
	nt.OptionalHeader.MajorImageVersion = 0x0000;
	nt.OptionalHeader.MinorImageVersion = 0x0000;
	nt.OptionalHeader.MajorSubsystemVersion = 0x0006;
	nt.OptionalHeader.MinorSubsystemVersion = 0x0000;
	nt.OptionalHeader.Win32VersionValue = 0x00000000;
	nt.OptionalHeader.SizeOfImage = 0x00400000;
	nt.OptionalHeader.SizeOfHeaders = 0x00000400;
	nt.OptionalHeader.CheckSum = 0x00000000;
	nt.OptionalHeader.Subsystem = 0x0002;
	nt.OptionalHeader.DllCharacteristics = 0x8140;
	nt.OptionalHeader.SizeOfStackReserve = 0x00100000;
	nt.OptionalHeader.SizeOfStackCommit = 0x00001000;
	nt.OptionalHeader.SizeOfHeapReserve = 0x00100000;
	nt.OptionalHeader.SizeOfHeapCommit = 0x00001000;
	nt.OptionalHeader.LoaderFlags = 0x00000000;
	nt.OptionalHeader.NumberOfRvaAndSizes = 0x00000010;
	//IMAGE_NUMBEROF_DIRECTORY_ENTRIES 
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES - 1].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES - 1].Size = 0;
//  [0x00000000]	{VirtualAddress = 0x003bb890 Size = 0x0000413b }	
//  [0x00000001]	{VirtualAddress = 0x003e85d4 Size = 0x000000a0 }
//  [0x00000002]	{VirtualAddress = 0x003eb000 Size = 0x0000043c }
//  [0x00000003]	{VirtualAddress = 0x00000000 Size = 0x00000000 }
//  [0x00000004]	{VirtualAddress = 0x00000000 Size = 0x00000000 }
//  [0x00000005]	{VirtualAddress = 0x003ec000 Size = 0x0001103c }
//  [0x00000006]	{VirtualAddress = 0x00378330 Size = 0x00000038 }
//  [0x00000007]	{VirtualAddress = 0x00000000 Size = 0x00000000 }
//  [0x00000008]	{VirtualAddress = 0x00000000 Size = 0x00000000 }
//  [0x00000009]	{VirtualAddress = 0x00000000 Size = 0x00000000 }
//  [0x0000000a]	{VirtualAddress = 0x003a2c70 Size = 0x00000040 }
//  [0x0000000b]	{VirtualAddress = 0x00000000 Size = 0x00000000 }
//  [0x0000000c]	{VirtualAddress = 0x003e8000 Size = 0x000005d4 }
//  [0x0000000d]	{VirtualAddress = 0x00000000 Size = 0x00000000 }
//  [0x0000000e]	{VirtualAddress = 0x00000000 Size = 0x00000000 }
//  [0x0000000f]	{VirtualAddress = 0x00000000 Size = 0x00000000 }

	IMAGE_SECTION_HEADER *pSectionHeader = 
		(IMAGE_SECTION_HEADER*)LocalAlloc(LPTR, sizeof(IMAGE_SECTION_HEADER)*nt.FileHeader.NumberOfSections);
}

#pragma runtime_checks( "", off )
void ShellCode(){
	// the functions we need
	LOADLIBRARYA pLoadLibraryA = NULL;
	GETPROCADDRESS pGetProcAddress = NULL;
	VIRTUALALLOC pVirtualAlloc = NULL;
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;
#ifdef ENABLE_STOPPAGING
	VIRTUALLOCK pVirtualLock = NULL;
#endif
#ifdef ENABLE_OUTPUTDEBUGSTRING
	OUTPUTDEBUG pOutputDebug = NULL;
#endif
	// the kernels base address and later this images newly loaded base address
	ULONG_PTR uiBaseAddress;

	// variables for processing the kernels export table
	ULONG_PTR uiAddressArray;
	ULONG_PTR uiNameArray;
	ULONG_PTR uiExportDir;
	ULONG_PTR uiNameOrdinals;
	DWORD dwHashValue;

	// variables for loading this image
	USHORT usCounter;
	ULONG_PTR uiValueA;
	ULONG_PTR uiValueB;
	ULONG_PTR uiValueC;
	// get the Process Enviroment Block
#ifdef _WIN64
	uiBaseAddress = __readgsqword(0x60);
#else
#ifdef WIN_ARM
	uiBaseAddress = *(DWORD *)((BYTE *)_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0x30);
#else _WIN32
	uiBaseAddress = __readfsdword(0x30);
#endif
#endif
	uiBaseAddress = (ULONG_PTR)((_PPEB)uiBaseAddress)->pLdr;

	// get the first entry of the InMemoryOrder module list
	uiValueA = (ULONG_PTR)((PPEB_LDR_DATA)uiBaseAddress)->InMemoryOrderModuleList.Flink;
	while (uiValueA)
	{
		// get pointer to current modules name (unicode string)
		uiValueB = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.pBuffer;
		// set bCounter to the length for the loop
		usCounter = ((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.Length;
		// clear uiValueC which will store the hash of the module name
		uiValueC = 0;

		// compute the hash of the module name...
		do
		{
			uiValueC = ror((DWORD)uiValueC);
			// normalize to uppercase if the module name is in lowercase
			if (*((BYTE *)uiValueB) >= 'a')
				uiValueC += *((BYTE *)uiValueB) - 0x20;
			else
				uiValueC += *((BYTE *)uiValueB);
			uiValueB++;
		} while (--usCounter);

		// compare the hash with that of kernel32.dll
		if ((DWORD)uiValueC == KERNEL32DLL_HASH)
		{
			// get this modules base address
			uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;

			// get the VA of the modules NT Header
			uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

			// uiNameArray = the address of the modules export directory entry
			uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			// get the VA of the export directory
			uiExportDir = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

			// get the VA for the array of name pointers
			uiNameArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames);

			// get the VA for the array of name ordinals
			uiNameOrdinals = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals);

			usCounter = 3;
#ifdef ENABLE_STOPPAGING
			usCounter++;
#endif
#ifdef ENABLE_OUTPUTDEBUGSTRING
			usCounter++;
#endif

			// loop while we still have imports to find
			while (usCounter > 0)
			{
				// compute the hash values for this function name
				dwHashValue = _hash((char *)(uiBaseAddress + DEREF_32(uiNameArray)));

				// if we have found a function we want we get its virtual address
				if (dwHashValue == LOADLIBRARYA_HASH
					|| dwHashValue == GETPROCADDRESS_HASH
					|| dwHashValue == VIRTUALALLOC_HASH
#ifdef ENABLE_STOPPAGING
					|| dwHashValue == VIRTUALLOCK_HASH
#endif
#ifdef ENABLE_OUTPUTDEBUGSTRING
					|| dwHashValue == OUTPUTDEBUG_HASH
#endif
					)
				{
					// get the VA for the array of addresses
					uiAddressArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

					// use this functions name ordinal as an index into the array of name pointers
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

					// store this functions VA
					if (dwHashValue == LOADLIBRARYA_HASH)
						pLoadLibraryA = (LOADLIBRARYA)(uiBaseAddress + DEREF_32(uiAddressArray));
					else if (dwHashValue == GETPROCADDRESS_HASH)
						pGetProcAddress = (GETPROCADDRESS)(uiBaseAddress + DEREF_32(uiAddressArray));
					else if (dwHashValue == VIRTUALALLOC_HASH)
						pVirtualAlloc = (VIRTUALALLOC)(uiBaseAddress + DEREF_32(uiAddressArray));
#ifdef ENABLE_STOPPAGING
					else if (dwHashValue == VIRTUALLOCK_HASH)
						pVirtualLock = (VIRTUALLOCK)(uiBaseAddress + DEREF_32(uiAddressArray));
#endif
#ifdef ENABLE_OUTPUTDEBUGSTRING
					else if (dwHashValue == OUTPUTDEBUG_HASH)
						pOutputDebug = (OUTPUTDEBUG)(uiBaseAddress + DEREF_32(uiAddressArray));
#endif

					// decrement our counter
					usCounter--;
				}

				// get the next exported function name
				uiNameArray += sizeof(DWORD);

				// get the next exported function name ordinal
				uiNameOrdinals += sizeof(WORD);
			}
		}
		else if ((DWORD)uiValueC == NTDLLDLL_HASH)
		{
			// get this modules base address
			uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;

			// get the VA of the modules NT Header
			uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

			// uiNameArray = the address of the modules export directory entry
			uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			// get the VA of the export directory
			uiExportDir = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

			// get the VA for the array of name pointers
			uiNameArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames);

			// get the VA for the array of name ordinals
			uiNameOrdinals = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals);

			usCounter = 1;

			// loop while we still have imports to find
			while (usCounter > 0)
			{
				// compute the hash values for this function name
				dwHashValue = _hash((char *)(uiBaseAddress + DEREF_32(uiNameArray)));

				// if we have found a function we want we get its virtual address
				if (dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
				{
					// get the VA for the array of addresses
					uiAddressArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

					// use this functions name ordinal as an index into the array of name pointers
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

					// store this functions VA
					if (dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
						pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)(uiBaseAddress + DEREF_32(uiAddressArray));

					// decrement our counter
					usCounter--;
				}

				// get the next exported function name
				uiNameArray += sizeof(DWORD);

				// get the next exported function name ordinal
				uiNameOrdinals += sizeof(WORD);
			}
		}

		// we stop searching when we have found everything we need.
		if (pLoadLibraryA
			&& pGetProcAddress
			&& pVirtualAlloc
#ifdef ENABLE_STOPPAGING
			&& pVirtualLock
#endif
			&& pNtFlushInstructionCache
#ifdef ENABLE_OUTPUTDEBUGSTRING
			&& pOutputDebug
#endif
			)
			break;

		// get the next entry
		uiValueA = DEREF(uiValueA);
	}
	char szUser32[16] = { 'u', 's', 'e', 'r', '3', '2', 0 };
	HMODULE hMod = pLoadLibraryA(szUser32);
	int(WINAPI *pMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
	char szMessageBox[32] = { 'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A', 0 };
	pMessageBoxA = (int(WINAPI *)(HWND, LPCSTR, LPCSTR, UINT))pGetProcAddress(hMod, szMessageBox);
	char szText[4] = { 'o', 'k', 0 };
	char szTitle[8] = { 't', 'e', 's', 't', 0 };
	pMessageBoxA(NULL, szText, szTitle, MB_OK);
}
_declspec(dllexport) int g_for_not_optimize_some_function = 0;
void ShellCode_end(){
	g_for_not_optimize_some_function++;
}
#pragma runtime_checks( "", restore ) 

void PeTool::Test6()
{
	IMAGE_DOS_HEADER dos;
	memset(&dos, 0, sizeof(IMAGE_DOS_HEADER));
	dos.e_magic = IMAGE_DOS_SIGNATURE;
	dos.e_lfanew = sizeof(IMAGE_DOS_HEADER);
	IMAGE_NT_HEADERS32 nt;
	memset(&nt, 0, sizeof(IMAGE_NT_HEADERS32));
	nt.Signature = IMAGE_NT_SIGNATURE;
	nt.FileHeader.Machine = 0x014c;
	nt.FileHeader.NumberOfSections = 0x0001;
	nt.FileHeader.TimeDateStamp = 0x57818ce7;
	nt.FileHeader.SizeOfOptionalHeader = 0x00e0;
	nt.FileHeader.Characteristics = 0x0102;
	// Standard fields.
	nt.OptionalHeader.Magic = 0x010b;
	nt.OptionalHeader.MajorLinkerVersion = 0x0c;
	nt.OptionalHeader.MinorLinkerVersion = 0x00;
	nt.OptionalHeader.SizeOfCode = 0x00257e00;
	nt.OptionalHeader.SizeOfInitializedData = 0x00086800;
	nt.OptionalHeader.SizeOfUninitializedData = 0x00000000;
	nt.OptionalHeader.AddressOfEntryPoint = 0x0011f195;
	nt.OptionalHeader.BaseOfCode = 0x00001000;
	nt.OptionalHeader.BaseOfData = 0x00001000;
	// NT additional fields.
	nt.OptionalHeader.ImageBase = 0x00850000;
	nt.OptionalHeader.SectionAlignment = 0x00001000;
	nt.OptionalHeader.FileAlignment = 0x00000200;
	nt.OptionalHeader.MajorOperatingSystemVersion = 0x0006;
	nt.OptionalHeader.MinorOperatingSystemVersion = 0x0000;
	nt.OptionalHeader.MajorImageVersion = 0x0000;
	nt.OptionalHeader.MinorImageVersion = 0x0000;
	nt.OptionalHeader.MajorSubsystemVersion = 0x0006;
	nt.OptionalHeader.MinorSubsystemVersion = 0x0000;
	nt.OptionalHeader.Win32VersionValue = 0x00000000;
	nt.OptionalHeader.SizeOfImage = 0x00400000;
	nt.OptionalHeader.SizeOfHeaders = 0x00000400;
	nt.OptionalHeader.CheckSum = 0x00000000;
	nt.OptionalHeader.Subsystem = 0x0002;
	nt.OptionalHeader.DllCharacteristics = 0x8140;
	nt.OptionalHeader.SizeOfStackReserve = 0x00100000;
	nt.OptionalHeader.SizeOfStackCommit = 0x00001000;
	nt.OptionalHeader.SizeOfHeapReserve = 0x00100000;
	nt.OptionalHeader.SizeOfHeapCommit = 0x00001000;
	nt.OptionalHeader.LoaderFlags = 0x00000000;
	nt.OptionalHeader.NumberOfRvaAndSizes = 0x00000010;
	//IMAGE_NUMBEROF_DIRECTORY_ENTRIES 
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES - 1].VirtualAddress = 0;
	nt.OptionalHeader.DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES - 1].Size = 0;

	IMAGE_SECTION_HEADER sectionHeader;
	memset(&sectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
	strcpy_s((char*)&sectionHeader.Name, IMAGE_SIZEOF_SHORT_NAME, ".text");
	sectionHeader.Misc.VirtualSize = 512;
	sectionHeader.VirtualAddress = 0x1000;
	sectionHeader.SizeOfRawData = 0x200;
	sectionHeader.PointerToRawData = 0x200;
	sectionHeader.Characteristics = 0x60000020;


	char* pshellEntry = 0;
	char* pshellEntry_end = 0;
	pshellEntry = (char*)SkipJumps((PBYTE)ShellCode);
	pshellEntry_end = (char*)SkipJumps((PBYTE)ShellCode_end);

	DWORD dwCodeSize = pshellEntry_end - pshellEntry;
	DWORD dwCodeAlignSize = 0x200*(dwCodeSize / 0x200 + (dwCodeSize % 0x200 ? 1 : 0));
	return ;
}