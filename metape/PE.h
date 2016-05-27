/**
 *		PE image/memory analysis interface (class) by MGeeky (2010-2011).
 *
 *		Version:		1.2
 *		Last revision:	24.08.2011 (00:35)
 *		License:		LGPL
 *		Contact:		mgeeky on gmail dot com
 *
 *		Description:
 *		Currently this interface allows user to perform full
 *		analysis of selected process (by it's PID) or process's
 *		module (by process's PID and module name) or complete
 *		process dump file. Analysis includes headers reading and parsing,
 *		IAT and EAT parsing (even with custom start address - i.e.
 *		when user knows correct address of IAT/EAT can specify this
 *		during IAT/EAT parsing (i.e. ParseIAT( dwAddr) ). This allows
 *		to perform IAT/EAT analysis on-the-fly, for example when IAT
 *		address become explicit (packers characteristic behaviour).
 *		This interface allows as well easily creating image section.
 *		With this class user easily can append shellcode to the
 *		image/process, hooking IAT/EAT thunks with custom addresses. Entire
 *		interface seems (to me) in a little bit resistant to some PE
 *		headers corruptions (in case of any troubles - please contact me).
 *
 *
 *						**DISCLAIMER**
 *		THIS MATERIAL IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
 *		EITHER EXPRESS OR IMPLIED, INCLUDING, BUT Not LIMITED TO, THE
 *		IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 *		PURPOSE, OR NON-INFRINGEMENT. SOME JURISDICTIONS DO NOT ALLOW THE
 *		EXCLUSION OF IMPLIED WARRANTIES, SO THE ABOVE EXCLUSION MAY NOT
 *		APPLY TO YOU. IN NO EVENT WILL I BE LIABLE TO ANY PARTY FOR ANY
 *		DIRECT, INDIRECT, SPECIAL OR OTHER CONSEQUENTIAL DAMAGES FOR ANY
 *		USE OF THIS MATERIAL INCLUDING, WITHOUT LIMITATION, ANY LOST
 *		PROFITS, BUSINESS INTERRUPTION, LOSS OF PROGRAMS OR OTHER DATA ON
 *		YOUR INFORMATION HANDLING SYSTEM OR OTHERWISE, EVEN If WE ARE
 *		EXPRESSLY ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 *
 */

#ifndef __PE_CLASS_HEADER__
#define __PE_CLASS_HEADER__


///////////////////////////////////////////////////////////////////////////////////////
///////////////////		PREPROCESSOR		///////////////////////////////////////////

#ifdef _MSC_VER
	// Microsoft Visual Studio Compiler
#	pragma warning(disable:4996)
#	pragma warning(disable:4309)
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <vector>
#include <cstdio>
#include <cstdlib>

using namespace std;

///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////


// Sizes of structures

#define		IMAGE_SIZEOF_IMPORT_DESCRIPTOR	20
#define		IMAGE_SIZEOF_THUNK_DATA			4
#define		IMAGE_SIZEOF_IMPORT_BY_NAME		3
#define		IMAGE_SIZEOF_DOS_HEADER			64
#define		IMAGE_SIZEOF_DOS_STUB			64
#define		IMAGE_SIZEOF_OPTIONAL_HEADER	224
#define		IMAGE_SIZEOF_SECTION_HEADER		40
#define		IMAGE_SIZEOF_EXPORT_DIRECTORY	40

// Additional definitions / constants

#define		IMAGE_MAXIMAL_SECTIONS_COUNT	96			// according to Microsoft "pecoff_v8.doc"
														// and "The Art of computer virus research
														// and defense" by Peter Szor

// Errors

#define		ERROR_FILE_IS_COMPRESSED		0x80001		// File is probably compressed
#define		ERROR_IAT_UNACCESSIBLE			0x80002		// IAT is unaccessible
#define		ERROR_INVALID_MAGIC				0x80003		// DOS_HEADER.eMagic is not "MZ"
#define		ERROR_INVALID_PE				ERROR_INVALID_MAGIC
#define		ERROR_INVALID_SIGNATURE			0x80004		// NT_HEADERS.Signature is not "PE"
#define		ERROR_HEAP_CORRUPTED			0x80005		// Error while allocating memory at the Heap
#define		ERROR_READ_LESS_THAN_SHOULD		0x80006		// Read less bytes than should read
#define		ERROR_WRITE_LESS_THAN_SHOULD	0x80007		// Write less bytes than should write
#define		ERROR_EAT_UNACCESSIBLE			0x80008		// EAT is unaccessible
#define		ERROR_IAT_CORRUPTED				0x80009		// IAT is corrupted
#define		ERROR_EAT_CORRUPTED				0x8000A		// EAT is corrupted



///////////////////////////////////////////////////////////////////////////////////////
///////////////////		DECLARATIONS		///////////////////////////////////////////

// Class describing each imported thunk
class IMPORTED_FUNCTION
{
public:
	IMPORTED_FUNCTION(){ memset( (void*)szFunction, 0, sizeof( szFunction)); }

	unsigned	uImpDescriptorIndex;		// Index of import descriptor (index in vector)
	unsigned	uImportIndex;				// Index of import inside import descriptor

	union{
		char	szFunction[ 65];
		DWORD	dwOrdinal;
	};

	DWORD		dwPtrValue;					// Value of pointer to this thunk
	DWORD		dwHint;						// Hint
	DWORD		dwThunkRVA;					// RVA address of this Thunk in file (not of value)
};


// Class describing each exported thunk

class EXPORTED_FUNCTION
{
public:
	EXPORTED_FUNCTION(){ memset( (void*)szFunction, 0, sizeof( szFunction)); }

	bool 		bIsOrdinal;					// Specifies wheter function is exported by ordinal
											// instead of by name
	unsigned	uExportIndex;				// Export thunk index.
	union{
		char	szFunction[ 65];
		DWORD	dwOrdinal;
	};

	bool		bIsForwarded;				// Specifies wheter exported thunk is forwarded
	char		szForwarder[ 65];

	DWORD		dwPtrValue;					// Value of pointer to this thunk
	WORD		wOrdinal;					// Ordinal
	DWORD		dwThunkRVA;					// RVA address of this Thunk in file (not of value)
};


// Class describing each import descriptor

class __IMAGE_IMPORT_DESCRIPTOR
{
public:
	IMAGE_IMPORT_DESCRIPTOR		d;
	char						szName[ 32];
	vector< IMPORTED_FUNCTION>	vImports;
};


////////////////////////////////		MAIN CLASS		///////////////////////////////////////////////
class PE
{

	/************************************/
private:

	DWORD								_dwLastError;					// PE interface last error
																		//	may be as well return of the
																		//	GetLastError()
	DWORD								_dwErrorLine;					// Line in code where error occured
	char*								_szErrorFunction;				// Function name where error occured
	BOOL								_bIsIATFilled;					// Specifies wheter IAT has been
																		//	filled

	DWORD								_dwCurrentOffset;				// During process analysis
																		// we cannot use SetFilePointer
																		// routine to seek inside process
																		// memory, so that's how we obey it
	HANDLE								_hMapOfFile;
	BOOL								_bIsFileMapped;
	BOOL								_bAutoMapOfFile;				// Specifies wheter program used
																		// PE::MapFile() method


	/************************************/
public:

	BOOL								bIsValidPE;						// Specifies wheter target file is
																		// a valid Portable Executable Image.

	WCHAR/*char*/								szFileName[ MAX_PATH];
	BY_HANDLE_FILE_INFORMATION			bhFileInformation;

	DWORD								dwSizeOfFile;					// actual size of file
	DWORD								dwEP;							// AddressOfEntryPoint
	DWORD								dwNumberOfImports;				// Number of imported functions

	// PE Headers
	IMAGE_DOS_HEADER					imgDosHdr;
	IMAGE_FILE_HEADER					imgFileHdr;
	IMAGE_OPTIONAL_HEADER				imgOptionalHdr;
	IMAGE_SECTION_HEADER				*pSectionHdrs;

	IMAGE_EXPORT_DIRECTORY				imgExportDirectory;				// If this module provides
																		// EAT, then this structure
																		// will be filled correspondly

	DWORD								dwSignature;					// Should be "PE"
	unsigned							uNewSections;					// Number of added sections
																		// (by CreateSection method)

	// DOS header & stub
	LPVOID								lpDOSStub;						// DOS STUB
	DWORD								dwSizeOfDOSStub;

	// Vectors
	vector< char*>						vSectionsNames;
	vector< IMPORTED_FUNCTION>			vImports;
	vector< __IMAGE_IMPORT_DESCRIPTOR>	vImportDescriptors;
	vector< EXPORTED_FUNCTION>			vExports;

	// Address of mapped memory area
	LPBYTE								lpMapOfFile;
	BOOL								bUseRVAInsteadOfRAW;			// Useful when there is need to
																		// analyse file already loaded
																		// (positioned and aligned - i.e.
																		// process dump )
	HANDLE								hFileHandle;

	// Process analysis specific variables
	BOOL								bMemoryAnalysis;				// PE interface is performing living
																		// process/module analysis (memory).
																		// This not flags actual memory
																		// analysing, but in fact it's
																		// switch used in recognizing
																		// Process Memory operations.

	DWORD								dwPID;							// Living process analysis PID
	HANDLE								hProcess;						// Process handle


	//////////////////////////////		MEMBER METHODS		////////////////////////////////////////////


	// Implicit constructor. After you have to call PE::LoadFile member method to analyse an image
	PE( )
	{
		lpDOSStub = pSectionHdrs															= NULL;
		_bIsFileMapped = _bIsIATFilled = bUseRVAInsteadOfRAW = bMemoryAnalysis				= false;
		_dwLastError = dwSizeOfFile = dwSignature = uNewSections = dwEP = dwNumberOfImports =
			dwPID = _dwCurrentOffset														= 0;
		hFileHandle																			= (HANDLE)0;
		lpMapOfFile																			= NULL;

		memset( szFileName, 0,	sizeof( szFileName));
	}

	// Explicit constructor. After initialization instantly runs PE image analysis
	PE( const char *_szFileName, bool bRunAnalysis = false )
	{
		PE::PE();
		strncpy(  szFileName,  _szFileName,  sizeof(szFileName));
		if( bRunAnalysis == true){
			_bIsFileMapped = false;
			LoadFile();
		}
	}

	// Destructor, perform some cleaning now !
	~PE()
	{
		if( _bAutoMapOfFile && _bIsFileMapped )
		{
			UnmapViewOfFile( lpMapOfFile);
			_bIsFileMapped = false;
			if(_hMapOfFile != (HANDLE)INVALID_HANDLE_VALUE && _hMapOfFile != (HANDLE)0xCCCCCCCC )
			{
				CloseHandle( _hMapOfFile);
				_hMapOfFile = INVALID_HANDLE_VALUE;
				_bAutoMapOfFile = false;
			}
		}

		if( hFileHandle != INVALID_HANDLE_VALUE)
			CloseHandle( hFileHandle);

		hFileHandle = INVALID_HANDLE_VALUE;


		if( this->bIsValidPE)
		{
			if( lpDOSStub != NULL)		free( lpDOSStub);
			if( pSectionHdrs != NULL)	free( (void*)pSectionHdrs);
		}
	}


	//=========	 Address / offset conversions

	DWORD	RVA2RAW	(	DWORD dwRVA, bool bForce = false );
														// Returns conversion from RVA to RAW.
														// If we set bForce to true, it will omit
														// usage of this->bUseRVAInsteadOfRAW variable
	DWORD	RAW2RVA	(	DWORD dwRAW );
	DWORD	VA2RVA	(	DWORD dwVA  ){	return dwVA - GetIB();	}
	DWORD	RVA2VA	(	DWORD dwRVA ){	return dwRVA + GetIB();	}


	//=========	 Getting info

	DWORD					GetEP	(	)			{ return imgOptionalHdr.AddressOfEntryPoint;	}
	DWORD					GetIB	(	)			{ return imgOptionalHdr.ImageBase;				}
	DWORD					GetSectionsCount( )		{ return imgFileHdr.NumberOfSections;			}
	IMAGE_SECTION_HEADER*	GetSection( unsigned u ){ return &pSectionHdrs[ u];						}
	IMAGE_SECTION_HEADER*	GetLastSection( )		{ return &pSectionHdrs[ GetSectionsCount( )-1];	}


	//=========	 Checking errors

	DWORD	GetError( )								{ return _dwLastError;	}
	bool	operator!()								{ return ((this->GetError() != 0)? true : false); }
	void	SetError	( DWORD dwErrCode )			{ SetLastError( dwErrCode); _dwLastError = dwErrCode; }

	// More detailed SetError version
	void	_SetError	( DWORD dwErrCode, int iLine, const char *szFunc)
	{
		this->SetError( dwErrCode);
		this->_dwErrorLine = (DWORD)iLine;
		this->_szErrorFunction = (char*)szFunc;
	}


	//===========	Analysis methods	============

	// Simple file reading & writing (and of course parsing)
	BOOL	AnalyseFile( const char *_szFileName, bool _bIsValidPEImage = true )
	{
		strncpy(  this->szFileName,  _szFileName,  sizeof(this->szFileName));
		this->_bIsFileMapped = false;
		this->bIsValidPE = _bIsValidPEImage;

		return PE::LoadFile( );
	}

	// Another type of analysis. This performs analysis from dump file which is aligned and
	// divided to sections. This means, that analysis must be RVA-based
	// and make file reading & writing on every I/O.
	// e.g. dump file may be a dumped process memory.
	BOOL	AnalyseDump( const char *_szDump )
	{
		this->bUseRVAInsteadOfRAW = this->bIsValidPE = true;
		this->_bIsFileMapped = false;

		strncpy(  szFileName,  _szDump,  sizeof(szFileName));

		return PE::LoadFile( );
	}

	// Analyses current process memory treating input dwAddress as a base of
	// mapped image. This address should point to the mapped address of valid PE
	// file inside current process memory.
	BOOL	AnalyseMemory( DWORD dwAddress)
	{
		this->bUseRVAInsteadOfRAW = this->bIsValidPE =
			this->_bIsFileMapped = this->bMemoryAnalysis = true;
		this->lpMapOfFile = (LPBYTE)dwAddress;
		this->_bAutoMapOfFile = false;

		GetModuleFileNameA( GetModuleHandle(NULL), szFileName, sizeof szFileName);

		return PE::LoadFile( );
	}

	// Below methods performs module analysis from specified process memory.
	// This works by reading process memory and parsing/analysing it.
	BOOL	AnalyseProcessModule( DWORD dwPID, HMODULE hModule);

	// This method performs process module analysis. Actually, it opens process,
	// enumerates process modules and compares it with the szModule name. Afterwards,
	// it sets module handle and launches analysis. By specifying szModule to NULL user can
	// perform dwPID process analysis instead of one of it's modules.
	BOOL	AnalyseProcessModule( DWORD dwPID, const char *szModule);

	// Simple wrapper to _AnalyseProcessModule for quick process analysis
	BOOL	AnalyseProcess( DWORD dwPID ){ return this->AnalyseProcessModule( dwPID, (const char*)NULL); }


	//=========	 Maintenance methods	============

	void	SetFileMapped( LPBYTE _lpMapOfFile){	lpMapOfFile = _lpMapOfFile; _bIsFileMapped = true;
													_bAutoMapOfFile = false; }
														// Useful when user want to himself/herself
														// perform file mapping / use of already mapped
														// memory or simply load process dump

	char 	*trimQuote( char *szPath);					// Trims from file path quote chars '"'


	// Insert bytes to a file (by overwriting existing)
	inline BOOL Patch( LPVOID lpData, DWORD dwSize, LONG lOffset )
	{
		return this->WriteBytes( (LPVOID)lpData, dwSize, lOffset, FILE_BEGIN);
	}

	// Loads file and inserts a shellcode from this file (something like "infection" ).
	// Actually, this method makes new section, appends the shellcode inside this section,
	// and modifies AddressOfEntryPoint, nextly
	BOOL	InsertShellcode( const char *szFileWithShellcode, const char *szSectionName = ".extra");

	// This method hooks IAT/EAT routine by swapping original IAT/EAT thunk address with input hook address
	// Returns: 0 if szImportThunk/szExportThunk has not been found, -1 if there has
	// occured an error during WriteBytes, or non-zero if function succeed, and this value will
	// be previous thunk EntryPoint address.
	DWORD	HookIAT( const char* szImportThunk, DWORD dwHook);
	DWORD	HookEAT( const char* szExportThunk, DWORD dwHook);

	// This function actually opens the file, gathers headers from file, performs IAT parsing, and
	// if possible performs EAT parsing. Whole PE image analysis is beginning there.
	BOOL	LoadFile( );

	// Simple CreateFileMappingA and MapViewOfFile function
	LPBYTE	MapFile();

	// Function fills IAT in mapped memory (with GetProcAddr addresses
	// if dwAddresses hasn't been specified, or with addresses from dwAddresses table.
	BOOL	FillIAT( DWORD *dwAddresses = NULL, DWORD dwElements = 0 );


private:
	// ==========================================

	// This routine opens target image
	BOOL	_OpenFile()
	{
		if( hFileHandle != (HANDLE)0xCCCCCCCC &&
			hFileHandle != (HANDLE)-1 && hFileHandle != (HANDLE)0 )
			return TRUE;

		/* Open the file */
		hFileHandle = CreateFileA(	szFileName, GENERIC_READ|GENERIC_WRITE,
									FILE_SHARE_READ|FILE_SHARE_WRITE,
									NULL, OPEN_EXISTING, 0, NULL );
		if( hFileHandle == INVALID_HANDLE_VALUE || ::GetLastError() ){
			SetError( GetLastError() );
			return FALSE;
		}
		return TRUE;
	}

	// Returns char intepretation of input, or '.' if it is not printable
	inline char _HexChar(int c);

public:

	BOOL		ParseIAT( DWORD dwAddressOfIAT = 0 );	// Function parses IAT (from input address, or if
														//		not specified - from DataDirectory[1] )
	BOOL		ParseEAT( DWORD dwAddressOfEAT = 0 );	// Function parses EAT (from input address, or if
														//		not specified - from DataDirectory[0] )

	// I/O - read/writes opened file/process (PE::_hFileHandle) and returns
	BOOL		ReadBytes ( LPVOID, DWORD dwSize, DWORD dwOffset = 0, DWORD dwMethod = FILE_CURRENT);
	BOOL		WriteBytes ( LPVOID, DWORD dwSize, DWORD dwOffset = 0, DWORD dwMethod = FILE_CURRENT);

	// Creates image section and appends it to the PE::pSectionHdrs table
	IMAGE_SECTION_HEADER
				CreateSection	(	DWORD dwSizeOfSection, DWORD dwDesiredAccess,
									const char *szNameOfSection);

	// Writes down input section to the image/dump/memory
	BOOL		WriteSectionToImage
								(	IMAGE_SECTION_HEADER *pNewSectHdr );


	BOOL		AppendShellcode	( 	const char *szFileWithShellcode, DWORD dwSizeOfShellcode,
									IMAGE_SECTION_HEADER *imgNewSection );


};

///////////////////////////////////////////////////////////////////////////////////////

#endif // __PE_CLASS_HEADER__
