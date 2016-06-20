#ifndef __PE_TOOL_H____h_
#define __PE_TOOL_H____h_
#include <windows.h>
#include <vector>

#define ALIGN_VALUE_UP(value, alignment)    (((value) + (alignment) - 1) & ~((alignment) - 1))

class PeFileSection {
public:
	IMAGE_SECTION_HEADER sectionHeader;
	BYTE * data;
	DWORD dataSize;
	BYTE* pAlignGap;
	DWORD dwAlignGapLen;

	DWORD normalSize;

	PeFileSection()
	{
		ZeroMemory(&sectionHeader, sizeof(IMAGE_SECTION_HEADER));
		data = 0;
		dataSize = 0;
		pAlignGap = 0;
		dwAlignGapLen = 0;

		normalSize = 0;
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
		_pDosHeader = 0;
		_pDosStub = 0;
		_dwDosStubSize = 0;
		_pNTHeader32 = 0;
		_pNTHeader64 = 0;
		_dwNtHeaderSize = 0;
		_pAlignGap = 0;
		_dwAlignGapLen = 0;
		_pOverlayData = 0;
		_dwOverlaySize = 0;
		_eStatus = eNoData;

	};
	~PeTool(){};
	void Test();
	bool InitFromPeFileW(wchar_t* szPathFile);
	bool InitFromPeFile(char* szPathFile);
	bool InitFromNotMapedPeBuffer(void *pData, DWORD nSize);

	void* SaveToPeBuffer(DWORD *nSize);
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
private:
	E_PeStatus _eStatus;

private:
	PIMAGE_DOS_HEADER _pDosHeader;
	BYTE * _pDosStub; //between dos header and section header
	DWORD _dwDosStubSize;
	PIMAGE_NT_HEADERS32 _pNTHeader32;
	PIMAGE_NT_HEADERS64 _pNTHeader64;
	DWORD _dwNtHeaderSize;
	std::vector<PeFileSection> _listPeSection;
	BYTE* _pAlignGap;
	DWORD _dwAlignGapLen;
	BYTE * _pOverlayData;
	DWORD _dwOverlaySize;

};





#endif //__PE_TOOL_H____h_