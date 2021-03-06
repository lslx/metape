#ifndef __PE_TOOL_H____h_
#define __PE_TOOL_H____h_
#include <windows.h>
#include <vector>
#include <list>

#define ALIGN_VALUE_UP(value, alignment)    (((value) + (alignment) - 1) & ~((alignment) - 1))
enum E_DataType{
	eNoType,
	eDosHeader,
	eDosStub,
	eNtHeader,
	eNtHeaderGap,
	eSectionHeader,
	eSectionHeaderGap,
	eSection,
	eSectionGap,
	eOverLay,
};
// enum E_DataUsageType{
// 	euNoType,
// 	euDosHeader,
// 	euDosStub,
// 	euNtHeader,
// 	euNtHeaderGap,
// 	euSectionHeader,
// 	euSectionHeaderGap,
// 	euExportTable,
// 	euImportTable,
// 	euResourcesTable,
// 	euExceptionTable,
// 	euSecurityTable,
// 	euBaseRelocationTable,
// 	euDebug,
// 	euCopyright,
// 	euGlobalPtr,
// 	euThreadLocalStorage,
// 	euLoadConfig,
// 	euBoundImport,
// 	euImportAddressTable,
// 	euDelayImport,
// 	euComDescriptor,
// };
enum E_EntityType{
	euAllBuffer,
	euDosHeader,
	euDosStub,
	euNtHeader,
	euSectionHeader,
	euSection,
	euOverLay,
	euNoType = -1,
};
enum E_PointTo{
	eptBegin,
	eptContent,
	eptEnd,
	eptNoType = -1,
};
typedef struct _AddrInfo
{
	DWORD Addr;
	DWORD dwIndex;
	E_EntityType eType;
	E_PointTo eptType;
	_AddrInfo(){
		Reset();
	}
	void Reset(){
		Addr = -1;
		dwIndex = -1;
		eType = euNoType;
		eptType = eptNoType;
	}
}AddrInfo, *PAddrInfo;
typedef struct _NodeInfo
{
	DWORD Addr;
	std::list<AddrInfo> listAddrInfo;
}NodeInfo, *PNodeInfo;
typedef std::list<NodeInfo> ListNodeInfo;


// typedef struct _PointerInfo{
// 	E_DataType eDataType;
// 	E_DataUsageType eDataUsageType;
// 	DWORD dwOffsetOfNotMaped;
// 	DWORD dwOffsetOfMaped;
// }PointerInfo, *PPointerInfo;
typedef struct _RunInfo{
	char JmpCodex86[64];
	char JmpCodex64[64];
	int iMoveCount;
	void* pCopyMemImage = 0;
	SIZE_T CopyMemImageSize = 0;

}RunInfo, *PRunInfo;
extern "C" __declspec(dllexport) PRunInfo g_pRunInfo;


class PeFileSection {
public:
	IMAGE_SECTION_HEADER sectionHeader;
	BYTE * data;
	DWORD dataSize;
	//DWORD normalSize;

	PeFileSection()
	{
		ZeroMemory(&sectionHeader, sizeof(IMAGE_SECTION_HEADER));
		data = 0;
		dataSize = 0;
		//normalSize = 0;
	}
};
enum E_PeStatus{
	eNoData,
	eNotMaped,
	eMaped,
};
class PeTool
{
public:
	PeTool(){
		ClearAll(true);
	};
	~PeTool(){};
	// sections op
	bool ListSection_Init(PIMAGE_SECTION_HEADER pSectionHeader, WORD nSection);
	bool ListSection_GetTheFirstSectionOffset(bool bHasMaped, DWORD *dwOffset);

	//chge pe 
	char* PeTool::GetOverlayData(DWORD *pnSize);
	bool SetOverlayData(char* pData, DWORD nSize);
	bool AddToOverlayData(char* pData, DWORD nSize);
	void DeleteOverlayData();

	void Test();
	void Test2();
	void Test3();
	void Test4();
	void Test5();
	void Test6();
	bool InitFromPeFileW(wchar_t* szPathFile);
	bool InitFromPeFile(char* szPathFile);
	bool InitFromMapedPeBuffer(void *pData){ return InitFromPeBuffer(true, pData, 0); };
	bool InitFromNotMapedPeBuffer(void *pData, DWORD nSize){ return InitFromPeBuffer(false, pData, nSize); };
	bool FixMapedPeSectionsEndAddrInfo();
	bool CheckAddrListValid();
	char* SaveToPeBuffer(DWORD *nSize);
	bool SaveToPeFileW(wchar_t* szPathFileW);
	bool SaveToPeFile(char* szPathFile);
	DWORD CalcSizeByPeContent();

	bool IsPe32(){ return _pNTHeader32 != 0; }
	bool IsPe64(){ return _pNTHeader64 != 0; }
	DWORD GetFileAlign(){
		if (IsPe32())
			return _pNTHeader32->OptionalHeader.FileAlignment;
		else return _pNTHeader64->OptionalHeader.FileAlignment;
	}
	DWORD GetMemoryAlign(){
		if (IsPe32())
			return _pNTHeader32->OptionalHeader.SectionAlignment;
		else return _pNTHeader32->OptionalHeader.SectionAlignment;
	}
	//bool GetPointerInfo(DWORD64 pointer, PointerInfo* pPointerInfo);
private:
	ListNodeInfo _listNodeInfo;
private:
	//if bHasMaped is true , nSize will be ignore
	bool InitFromPeBuffer(bool bHasMaped, void *pData, DWORD nSize);
	bool AddAddrInfo(PAddrInfo pAddrInfo);
	bool InitAddrInfoFromPeBuffer(bool bHasMaped, void *pData, DWORD nSize);
	bool GetDataAddrInfo(E_EntityType eType, DWORD *pdwBengin, DWORD *pdwEnd, DWORD dwIndex = 0);
	bool GetSectionCountByAddrInfo(DWORD *pdwNum);


private:
	E_PeStatus _eStatus;
private:
	PIMAGE_DOS_HEADER _pDosHeader;
	BYTE * _pDosStub; //between dos header and section header
	DWORD _dwDosStubSize;
	PIMAGE_NT_HEADERS32 _pNTHeader32;
	PIMAGE_NT_HEADERS64 _pNTHeader64;
	DWORD _dwNtHeaderSize;
	std::vector<PeFileSection> _listPeSection;// need multi times init
	BYTE * _pOverlayData;//between last section end and file end
	DWORD _dwOverlaySize;

private:
	void ClearAll(bool bInit){
		_eStatus = eNoData;
		if (!bInit && _pDosHeader)LocalFree(_pDosHeader);	/*if end*/ _pDosHeader = NULL;
		if (!bInit && _pDosStub)LocalFree(_pDosStub);		/*if end*/ _pDosStub = NULL;       _dwDosStubSize = 0;
		if (!bInit && _pNTHeader32)LocalFree(_pNTHeader32); /*if end*/ _pNTHeader32 = NULL;    
		if (!bInit && _pNTHeader64)LocalFree(_pNTHeader64); /*if end*/ _pNTHeader64 = NULL;    _dwNtHeaderSize = 0;
		if (!bInit){
			for (std::vector<PeFileSection>::iterator it = _listPeSection.begin(); it != _listPeSection.end();it++){
				if (it->data) LocalFree(it->data);          /*if end*/it->data = NULL; it->dataSize = 0;
			}
			_listPeSection.clear();
		}
		if (!bInit && _pOverlayData)LocalFree(_pOverlayData);/*if end*/ _pOverlayData = NULL;   _dwOverlaySize = 0;
	}

};





#endif //__PE_TOOL_H____h_