/**
 *		PE image/memory analysis interface (class) by MGeeky (2010-2011).
 *
 *		Version:		1.2
 *		Last revision:	24.08.2011 (00:35)
 *		License:		LGPL
 *		Contact:		mgeeky on gmail
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

// In MS Compiler (with precompiled headers usage) you have to uncomment below line.
//#include "stdafx.h"

#include "PE.h"
#include <tlhelp32.h>
#include <TCHAR.h>

#ifdef _MSC_VER
	// Microsoft Visual Studio Compiler
#	pragma warning(disable:4996)
#	pragma warning(disable:4309)
#endif


#define		SET_ERROR				this->SetError( GetLastError() )
#define		RETURN_ERROR2(x)		{this->_SetError( x, __LINE__, __FUNCTION__ ); return FALSE;}
#define		RETURN_ERROR			{SET_ERROR;return FALSE;}
#define		READ_FAIL				{ this->_SetError( ERROR_READ_LESS_THAN_SHOULD, __LINE__, __FUNCTION__ )\
									; return FALSE; }
#define		WRITE_FAIL				{ this->_SetError( ERROR_WRITE_LESS_THAN_SHOULD, __LINE__, __FUNCTION__ )\
									; return FALSE; }
#define		CHECK_MALLOC( ptr)		if( ptr == NULL){ SetError( ERROR_HEAP_CORRUPTED); return FALSE;}


///////////////////////////////////////////////////////////////////////////////////////
// Loads and analyses image/dump/memory .
// Gathers PE headers and launches IAT/EAT parsing

BOOL PE::LoadFile( )
{

	// Fix file path
	trimQuote(szFileName);

	// Open a file
	if( !_OpenFile())
		RETURN_ERROR

	// If this is process, then we have to open process module to acquire by_handle_information.
	if( this->bMemoryAnalysis)
	{
		// open process module/image file
		HANDLE hFile = CreateFileA( szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
							FILE_ATTRIBUTE_NORMAL, NULL);
		if( hFile == (HANDLE)INVALID_HANDLE_VALUE || ::GetLastError() )
			RETURN_ERROR

		// Gather informations
		GetFileInformationByHandle( hFile, &bhFileInformation);

		// Close ;-)
		CloseHandle( hFile);
	}
	else
		GetFileInformationByHandle( hFileHandle, &bhFileInformation);

	dwSizeOfFile = bhFileInformation.nFileSizeLow; /* + bhFileInformation.nFileSizeHigh; */

	if( !this->bIsValidPE)
	{
		if( !_bIsFileMapped )
			MapFile();

		return TRUE;
	}

	// Read DOS header
	if( !ReadBytes( (LPVOID)&imgDosHdr, sizeof(IMAGE_DOS_HEADER) ) )
	{
		this->_SetError( ERROR_READ_LESS_THAN_SHOULD, __LINE__, __FUNCTION__ );
		this->_dwCurrentOffset = 0;
		SetFilePointer( this->hFileHandle, 0, NULL, FILE_BEGIN);
		return FALSE;
	}

	// Check if e_magic is 'ZM' or 'MZ' - Mark's Zbikowski signature
	if( (0x5A4D != imgDosHdr.e_magic && 0x4D5A != imgDosHdr.e_magic) || GetLastError() )
		RETURN_ERROR2(ERROR_INVALID_MAGIC)

	// Retrieving DOS STUB
	DWORD dwActualPos;
	if( this->bMemoryAnalysis == false)
		dwActualPos = SetFilePointer( hFileHandle, 0, NULL, FILE_CURRENT );
	else
		dwActualPos = IMAGE_SIZEOF_DOS_HEADER;

	dwSizeOfDOSStub = imgDosHdr.e_lfanew - dwActualPos;

	lpDOSStub = malloc( dwSizeOfDOSStub );
	CHECK_MALLOC( lpDOSStub)

	// Read DOS stub
	if( !ReadBytes(lpDOSStub, dwSizeOfDOSStub ) )
		READ_FAIL

	// Read PE signature ("PE")
	if( !ReadBytes(	(LPVOID)&dwSignature, sizeof( dwSignature),
					imgDosHdr.e_lfanew, FILE_BEGIN) )
		READ_FAIL

	if( this->bMemoryAnalysis == false)
			SetFilePointer( hFileHandle, imgDosHdr.e_lfanew + sizeof( dwSignature), NULL, FILE_BEGIN);
	else	this->_dwCurrentOffset = imgDosHdr.e_lfanew + sizeof( dwSignature);

	if( !ReadBytes( (LPVOID)&imgFileHdr, IMAGE_SIZEOF_FILE_HEADER )) READ_FAIL
	if( !ReadBytes( (LPVOID)&imgOptionalHdr, sizeof(IMAGE_OPTIONAL_HEADER32))) READ_FAIL

	// Acquiring image sections count
	DWORD dwSectionCount = imgFileHdr.NumberOfSections;
	if( dwSectionCount > IMAGE_MAXIMAL_SECTIONS_COUNT)
	{
		dwSectionCount = imgFileHdr.NumberOfSections = IMAGE_MAXIMAL_SECTIONS_COUNT;
	}

	pSectionHdrs = (IMAGE_SECTION_HEADER*)malloc( IMAGE_SIZEOF_SECTION_HEADER * dwSectionCount + 1);
	CHECK_MALLOC( pSectionHdrs)

	memset( (void*)pSectionHdrs, 0, IMAGE_SIZEOF_SECTION_HEADER * dwSectionCount + 1);

	// Reading image sections
	for(unsigned i = 0; i < dwSectionCount; i++)
		if( !ReadBytes( (LPVOID)&pSectionHdrs[ i], IMAGE_SIZEOF_SECTION_HEADER ) )
			READ_FAIL

	// Gathering section names
	char szSectionName[ 9] = "";

	for(unsigned i = 0; i < imgFileHdr.NumberOfSections; i++)
	{
		strncpy(  (char*)szSectionName,  (const char*)pSectionHdrs[i].Name,  sizeof(szSectionName)-1);
		vSectionsNames.push_back( szSectionName);
	}

	if( !_bIsFileMapped )
		MapFile();

	dwEP = GetEP();

	// Launch IAT parsing
	ParseIAT();

	// Parse Export Address Table
	if( this->imgOptionalHdr.DataDirectory[0].VirtualAddress != 0 )
		ParseEAT();

	return TRUE;
}


///////////////////////////////////////////////////////////////////////////////////////
// RVA address to RAW conversion routine.
// Additional bForce argument determines wheter to omit bUseRVAInsteadOfRAW
// variable. This can be used during dump file analysis (or memory: process/image).
// Normally in entire code I have been using RVA2RAW where only it was possible,
// so in RVA analysis mode - it is simply bypassed by returning already RVA instead of
// RAW. But if user would like to acquire RAW he can forcibly let it compute.

// Return: converted RVA to RAW, or RVA if couldn't convert (i.e address outside sections)

DWORD PE::RVA2RAW ( DWORD dwRVA, bool bForce )
{
	if( !this->bIsValidPE)
		return dwRVA;

	DWORD dwSections = GetSectionsCount();
	DWORD dwRAW = dwRVA;

	if( !bForce && bUseRVAInsteadOfRAW)
		return dwRVA;

	if( dwRVA > this->GetIB() )
		dwRVA -=  this->GetIB();

	for( unsigned i = 0; i < dwSections; i++)
	{
		if( dwRVA >= pSectionHdrs[i].VirtualAddress &&
			dwRVA < (	pSectionHdrs[i].VirtualAddress
					+	pSectionHdrs[i].Misc.VirtualSize) ){
			dwRAW = dwRVA - pSectionHdrs[i].VirtualAddress
							+ pSectionHdrs[i].PointerToRawData;
			break;
		}
	}
	return dwRAW;
}


///////////////////////////////////////////////////////////////////////////////////////
// RAW address to RVA conversion routine
// Return: converted RAW to RVA, or RAW if couldn't convert (i.e address outside sections)

DWORD PE::RAW2RVA ( DWORD dwRAW )
{
	if( !this->bIsValidPE)
		return dwRAW;

	DWORD dwRVA = (DWORD)dwRAW;
	int i = 0;

	if( dwRAW > this->GetIB() )
		dwRAW -=  this->GetIB();

	while( i < imgFileHdr.NumberOfSections )
	{
		if(pSectionHdrs[ i].PointerToRawData <= dwRAW &&
			(pSectionHdrs[ i].PointerToRawData
			+ pSectionHdrs[ i].SizeOfRawData) > dwRAW )
		{
			dwRVA = dwRAW + pSectionHdrs[ i].VirtualAddress
					- pSectionHdrs[ i].PointerToRawData;
		}
		i++;
	}
	return dwRVA;
}


///////////////////////////////////////////////////////////////////////////////////////
// Function parses Import Address Table.
// Additional argument dwAddressOfIAT could be used as a different base of the IAT (useful when
// on start program hasn't got a valid IAT in DataDirectory[1] ).

BOOL PE::ParseIAT( DWORD dwAddressOfIAT )
{
	if( !this->bIsValidPE)
		RETURN_ERROR2(ERROR_INVALID_PE)

	// Computing virtual address of Import Address Table
	IMAGE_NT_HEADERS		*imgNTHdr = (IMAGE_NT_HEADERS*)malloc( sizeof(IMAGE_NT_HEADERS));
	IMAGE_DATA_DIRECTORY	*pIddIAT = (IMAGE_DATA_DIRECTORY*)
											&(imgOptionalHdr.DataDirectory[1]);
	CHECK_MALLOC( imgNTHdr)

	memset( (void*)imgNTHdr, 0, sizeof( IMAGE_NT_HEADERS));
	imgNTHdr->Signature		=	dwSignature;
	imgNTHdr->FileHeader	=	imgFileHdr;
	imgNTHdr->OptionalHeader=	imgOptionalHdr;

	// Validating import DataDirectory
	if( dwAddressOfIAT == 0)
	{
		if(		pIddIAT->VirtualAddress == 0
			||	pIddIAT->Size == 0)
		{
			SetError( ERROR_IAT_UNACCESSIBLE);
			free( (void*)imgNTHdr);
			return FALSE;
		}

		if(		pIddIAT->VirtualAddress > this->dwSizeOfFile
			||	pIddIAT->Size > this->dwSizeOfFile
			||	this->RVA2RAW( pIddIAT->VirtualAddress) > this->dwSizeOfFile
			||	this->RVA2RAW( pIddIAT->VirtualAddress + pIddIAT->Size) > this->dwSizeOfFile )
		{
			SetError( ERROR_IAT_CORRUPTED );
			free( (void*)imgNTHdr);
			return FALSE;
		}
	}

	// Specifying address of IAT
	DWORD	dwIAT;

	if( dwAddressOfIAT == 0 )
		dwIAT = RVA2RAW( pIddIAT->VirtualAddress);
	else dwIAT = RVA2RAW( dwAddressOfIAT);

	LPVOID lpBuffer;
	DWORD dwSizeOfIAT = 0;

	// Here we read from the process memory entire Import Address Table
	if( this->bMemoryAnalysis)
	{
		// Have to check in which section IAT is lying, afterwards set dwSizeOfIAT
		DWORD dwTmp = imgOptionalHdr.DataDirectory[1].VirtualAddress;
		for( unsigned u = 0; u < vSectionsNames.size(); u++)
			if( dwTmp > pSectionHdrs[u].VirtualAddress && dwTmp < pSectionHdrs[u].SizeOfRawData){
				dwSizeOfIAT = pSectionHdrs[u].SizeOfRawData - dwTmp;
				break;
			}

		// Allocate memory for entire IAT
		SetLastError(0);
		lpBuffer = VirtualAlloc(NULL, dwSizeOfIAT, MEM_COMMIT, PAGE_READWRITE);
		if( lpBuffer == NULL )
			RETURN_ERROR

		memset( lpBuffer, 0, dwSizeOfIAT);

		// Read IAT from process memory
		if( !ReadBytes( lpBuffer, dwSizeOfIAT,
						imgOptionalHdr.DataDirectory[1].VirtualAddress,
						FILE_BEGIN))
		{
			_SetError( ERROR_READ_LESS_THAN_SHOULD, __LINE__, __FUNCTION__ );
			if(this->bMemoryAnalysis)
				VirtualFree( (LPVOID)(DWORD(lpBuffer) + dwIAT), dwSizeOfIAT, MEM_DECOMMIT);
			free( (void*)imgNTHdr);
			return FALSE;
		}

		// Smart trick to obey AccessViolation caused by RVA+lpBuffer memory referencing
		lpBuffer = LPVOID(DWORD(lpBuffer) - dwIAT);
	}else
		lpBuffer = lpMapOfFile;

	IMAGE_IMPORT_DESCRIPTOR	*iidTmp = (IMAGE_IMPORT_DESCRIPTOR*)(DWORD(lpBuffer) + dwIAT);
	IMAGE_THUNK_DATA		*itdTmp, itdTmp2;
	IMAGE_IMPORT_BY_NAME	*iibnTmp;
	unsigned				u = 0, b = 0, c = 0;

	// This loop iterates on import descriptors
	while( true )
	{
		if( iidTmp->FirstThunk == 0 && iidTmp->OriginalFirstThunk == 0 && iidTmp->Name == 0 )
			break;

		__IMAGE_IMPORT_DESCRIPTOR *iid = (__IMAGE_IMPORT_DESCRIPTOR*)malloc(
										sizeof(__IMAGE_IMPORT_DESCRIPTOR)+1);
		if( iid == NULL)
		{
			SetError( ERROR_HEAP_CORRUPTED);
			if(this->bMemoryAnalysis)
				VirtualFree( (LPVOID)(DWORD(lpBuffer) + dwIAT), dwSizeOfIAT, MEM_DECOMMIT);
			free( (void*)imgNTHdr);
			return FALSE;
		}

		memset( (void*)iid, 0, sizeof( __IMAGE_IMPORT_DESCRIPTOR)+1);
		memcpy( (void*)iid, (const void*)iidTmp, sizeof( IMAGE_IMPORT_DESCRIPTOR));

		// Copy import descriptor name
		strncpy( iid->szName, (const char*)(DWORD(lpBuffer) + RVA2RAW(iidTmp->Name)),
				sizeof( iid->szName) );

		vImportDescriptors.push_back( *iid );
		free( (void*)iid);

		b = 0;

		// time to iterate on its (import descriptor) imports
		while( true )
		{
			IMPORTED_FUNCTION	impFunc;
			memset( &impFunc, 0, sizeof( impFunc));

			impFunc.uImpDescriptorIndex = u;

			itdTmp	= (IMAGE_THUNK_DATA*)(DWORD(lpBuffer) + RVA2RAW(iidTmp->OriginalFirstThunk)
						+ b*sizeof( IMAGE_THUNK_DATA) );

			if( this->bMemoryAnalysis == false)
				memcpy( (void*)&itdTmp2, (const void*)(DWORD(lpBuffer) + RVA2RAW(iidTmp->FirstThunk)
							+ b*sizeof( IMAGE_THUNK_DATA)), sizeof(itdTmp2));
			else
				// During process/module/memory analysis we have to perform
				// process memory reading to collect valid IMAGE_THUNK_DATA with import address
				if(!ReadBytes( (LPVOID)&itdTmp2, sizeof( itdTmp2),
							(iidTmp->FirstThunk + b*sizeof( IMAGE_THUNK_DATA)), FILE_BEGIN))
				{
					_SetError( ERROR_READ_LESS_THAN_SHOULD, __LINE__, __FUNCTION__ );
					if(this->bMemoryAnalysis)
						VirtualFree( (LPVOID)(DWORD(lpBuffer) + dwIAT), dwSizeOfIAT, MEM_DECOMMIT);
					free( (void*)imgNTHdr);
					return FALSE;
				}

			// Checking Image Import Thunk & Descriptor structs
			if( iidTmp->OriginalFirstThunk == 0) itdTmp = &itdTmp2;
			if( itdTmp->u1.Function == 0 && itdTmp->u1.Ordinal == 0) break;
			if( itdTmp->u1.Function > (DWORD(lpBuffer) + this->dwSizeOfFile)) break;

			// Image Import By Name struct
			iibnTmp = (IMAGE_IMPORT_BY_NAME*)(DWORD(lpBuffer) + RVA2RAW(itdTmp->u1.Function));


			// During process analysis common situation is wheter IAT is larger then specified
			// in DataDirectory[1].Size . In this manner IMAGE_IMPORT_BY_NAME.Name points to
			// unread / unavailable memory address . So, we have to reallocate virtual buffer which
			// was allocated for IAT and read more memory (from process). Short and Simple.

			if( this->bMemoryAnalysis
				&& (itdTmp->u1.Function > (dwIAT + dwSizeOfIAT) ) )
			{
				const DWORD cdwReadMore = 0x200;
				DWORD dwToRead = itdTmp->u1.Function - dwIAT + cdwReadMore;

				SetLastError(0);
				LPVOID _lpBuffer = VirtualAlloc(	NULL, dwToRead, MEM_COMMIT, PAGE_READWRITE );
				if( _lpBuffer == NULL)
				{
					SET_ERROR;
					if(this->bMemoryAnalysis)
						VirtualFree( (LPVOID)(DWORD(lpBuffer) + dwIAT), dwSizeOfIAT, MEM_DECOMMIT);
					free( (void*)imgNTHdr);
					return FALSE;
				}


				// Operating system allocated for us completly different memory region.
				// We have to renovate the buffer by simply copying memory from older to the newer one.

				if( _lpBuffer != (LPVOID)(DWORD(lpBuffer) + dwIAT ) )
				{
					if(this->bMemoryAnalysis)
						VirtualFree( (LPVOID)(DWORD(lpBuffer) + dwIAT), dwSizeOfIAT, MEM_DECOMMIT);
					lpBuffer = _lpBuffer;
				}

				memset( (void*)lpBuffer, 0, dwToRead);

				if( !ReadBytes( (LPVOID)lpBuffer, dwToRead, (DWORD)dwIAT, FILE_BEGIN) )
				{
					_SetError( ERROR_READ_LESS_THAN_SHOULD, __LINE__, __FUNCTION__ );
					if(this->bMemoryAnalysis)
						VirtualFree( (LPVOID)(DWORD(lpBuffer) + dwIAT ), dwSizeOfIAT, MEM_DECOMMIT);
					free( (void*)imgNTHdr);
					return FALSE;
				}

				dwSizeOfIAT = dwToRead;
				lpBuffer = (LPVOID)(DWORD(lpBuffer) - dwIAT);

				// Correct pointer to the image import descriptor
				iidTmp = (IMAGE_IMPORT_DESCRIPTOR*)(DWORD(lpBuffer)
				+ dwIAT + (u * sizeof(IMAGE_IMPORT_DESCRIPTOR)));

				// Correct previous pointers by jumping to the start of this while loop
				continue;
			}

			if( iibnTmp->Name == 0 && !(itdTmp->u1.Ordinal & IMAGE_ORDINAL_FLAG) ) break;
			if(!( *(const char*)iibnTmp->Name >= 0x30 && *(const char*)iibnTmp->Name <= 0x7A) )
				break;

			// Rewriting (but firstly getting) address of procedure
			if( (itdTmp->u1.Ordinal & IMAGE_ORDINAL_FLAG) )
				impFunc.dwOrdinal = DWORD(itdTmp->u1.Ordinal & IMAGE_ORDINAL_FLAG);
			else {
				strncpy(impFunc.szFunction, (const char*)iibnTmp->Name, sizeof(impFunc.szFunction)-1 );
			}

			// Filing import function structure fields
			impFunc.dwHint			= iibnTmp->Hint;
			impFunc.dwPtrValue		= itdTmp2.u1.Function;
			impFunc.dwThunkRVA		= (iidTmp->FirstThunk + b*sizeof( IMAGE_THUNK_DATA) );
			impFunc.uImportIndex	= b;

			vImports.push_back( impFunc);
			vImportDescriptors[ u].vImports.push_back( impFunc);

			b++;
			c++;
		}

		// Aiming next import descriptor structure
		u++;
		iidTmp = (IMAGE_IMPORT_DESCRIPTOR*)(DWORD(lpBuffer)
				+ dwIAT + (u * sizeof(IMAGE_IMPORT_DESCRIPTOR)));
	}

	free( (void*)imgNTHdr);
	dwNumberOfImports = c;

	if( this->bMemoryAnalysis)
	{
		VirtualFree( (LPVOID)(DWORD(lpBuffer) + dwIAT), dwSizeOfIAT, MEM_DECOMMIT);
	}

	if( u == 0 || c == 0)
		RETURN_ERROR2(ERROR_IAT_UNACCESSIBLE)

	return TRUE;
}



///////////////////////////////////////////////////////////////////////////////////////
// This function list all EAT (Export Address Table) entries.
// Additional argument dwAddressOfEAT could be used as a different base of the EAT (useful when
// on start program hasn't got a valid EAT in DataDirectory[0] ).

BOOL PE::ParseEAT( DWORD dwAddressOfEAT )
{
	if( !this->bIsValidPE)
		RETURN_ERROR2(ERROR_INVALID_PE)

	/* -------------------------- Variables -------------------------- */
	PIMAGE_EXPORT_DIRECTORY     image_export_directory;
	PIMAGE_OPTIONAL_HEADER      ioh;

	DWORD 						dwOffset 	= 0;
	LPVOID      				lpBuffer	= this->lpMapOfFile;

	EXPORTED_FUNCTION			expFunc;

	DWORD						dwAddr;

	/* -------------------------- Variables -------------------------- */

	// Validating Export Address Table (directory)
	if( dwAddressOfEAT == 0)
	{
		IMAGE_DATA_DIRECTORY*	pIddEAT = (IMAGE_DATA_DIRECTORY*)&imgOptionalHdr.DataDirectory[0];
		dwAddr = imgOptionalHdr.DataDirectory[0].VirtualAddress;

		if( pIddEAT->VirtualAddress == 0 )
			RETURN_ERROR2( ERROR_EAT_UNACCESSIBLE)

		if(		pIddEAT->VirtualAddress > this->dwSizeOfFile
			||	pIddEAT->Size > this->dwSizeOfFile
			||	this->RVA2RAW(pIddEAT->VirtualAddress) > this->dwSizeOfFile
			||	this->RVA2RAW( pIddEAT->VirtualAddress + pIddEAT->Size) > this->dwSizeOfFile )
			RETURN_ERROR2( ERROR_EAT_CORRUPTED)
	}
	else
		dwAddr = dwAddressOfEAT;

	if( this->_bIsFileMapped == false)
		MapFile();

	ZeroMemory((void*)&expFunc, sizeof(expFunc));

	ioh 		= (PIMAGE_OPTIONAL_HEADER)&imgOptionalHdr;
	DWORD dwSizeOfEAT = ioh->DataDirectory[0].Size;

	if( this->bMemoryAnalysis )
	{
		SetLastError(0);
		lpBuffer = VirtualAlloc( NULL, dwSizeOfEAT, MEM_COMMIT, PAGE_READWRITE);
		if( lpBuffer == NULL)
			RETURN_ERROR

		memset( (void*)lpBuffer, 0, dwSizeOfEAT);

		if( !ReadBytes( lpBuffer, dwSizeOfEAT, dwAddr, FILE_BEGIN))
		{
			_SetError( ERROR_READ_LESS_THAN_SHOULD, __LINE__, __FUNCTION__ );
			if(this->bMemoryAnalysis)
				VirtualFree( (LPVOID)(lpBuffer), dwSizeOfEAT, MEM_DECOMMIT);
			return FALSE;
		}

		lpBuffer = (LPVOID)(DWORD(lpBuffer) - dwAddr);
	}


	// Now we taking access to IMAGE_EXPORT_DIRECTORY
	dwOffset = DWORD(lpBuffer) + this->RVA2RAW(dwAddr);
	image_export_directory = (PIMAGE_EXPORT_DIRECTORY)( dwOffset);

	// Validating image_export_directory
	if (image_export_directory->AddressOfFunctions == 0 &&
		image_export_directory->AddressOfNameOrdinals == 0 &&
		image_export_directory->AddressOfNames == 0 &&
		image_export_directory->Name == 0 )
	{
		SetError( ERROR_EAT_UNACCESSIBLE);
		if(this->bMemoryAnalysis)
			VirtualFree( (LPVOID)(DWORD(lpBuffer)+dwAddr), dwSizeOfEAT, MEM_DECOMMIT);
		return FALSE;
	}

	// Computing offset of a module name
	dwOffset = this->RVA2RAW(image_export_directory->Name);
	dwOffset += (DWORD)lpBuffer;

	// Preparing name of exported module.
	if( this->RVA2RAW(ioh->DataDirectory[0].VirtualAddress) > this->dwSizeOfFile )
	{
		SetError( ERROR_EAT_CORRUPTED);
		if(this->bMemoryAnalysis)
			VirtualFree( (LPVOID)(DWORD(lpBuffer)+dwAddr), dwSizeOfEAT, MEM_DECOMMIT);
		return FALSE;
	}

	memcpy( (void*)&imgExportDirectory, (const void*)&image_export_directory, sizeof
				imgExportDirectory );

	int      	f         	= 0,
				iIndex 		= 0;
	WORD   		wOrdinal   	= 0;
	DWORD   	dwRVA      	= 0,
				dwNameRAW   = 0,
				dwTmp 		= 0;
	WORD*		aOrdinals;
	DWORD*		aAddresses,
				*aNamesRVA;

	DWORD		dwBufSize;
	DWORD		dwTmp3 = this->RVA2RAW(image_export_directory->AddressOfFunctions  );
	LPVOID		_lpBuffer;

	// Allocate memory for three export tables (Names, Functions, Ordinals)
	if( this->bMemoryAnalysis)
	{
		dwBufSize = (image_export_directory->AddressOfNameOrdinals
							- image_export_directory->AddressOfFunctions
							+ (image_export_directory->NumberOfFunctions*sizeof(WORD) ) );
		_lpBuffer = VirtualAlloc( NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
		if( _lpBuffer == NULL)
			RETURN_ERROR

		memset( _lpBuffer, 0, dwBufSize);

		if(! ReadBytes( _lpBuffer, dwBufSize, dwTmp3, FILE_BEGIN))
		{
			VirtualFree( (LPVOID)(DWORD(lpBuffer)+dwAddr), dwSizeOfEAT, MEM_DECOMMIT);
			VirtualFree( (LPVOID)(DWORD(_lpBuffer)+dwTmp3), dwBufSize, MEM_DECOMMIT);
			_SetError( ERROR_READ_LESS_THAN_SHOULD, __LINE__, __FUNCTION__ );
			return FALSE;
		}

		_lpBuffer = (LPVOID)(DWORD(_lpBuffer) - dwTmp3);
	}

	dwRVA      	= dwTmp3;
	aOrdinals   = (WORD *)(DWORD(lpBuffer) +
					this->RVA2RAW(image_export_directory->AddressOfNameOrdinals ));
	aAddresses	= (DWORD*)(DWORD(lpBuffer) + dwRVA);
	aNamesRVA	= (DWORD*)(DWORD(lpBuffer) + this->RVA2RAW(image_export_directory->AddressOfNames ));

	// Iterating all exported functions from this module
	for(f = 0; unsigned(f) < image_export_directory->NumberOfFunctions; f++)
	{
		ZeroMemory((void*)&expFunc, sizeof(expFunc));

		wOrdinal	= aOrdinals[ f];
		dwNameRAW	= this->RVA2RAW( aNamesRVA[ f]) + DWORD(lpBuffer);

		expFunc.uExportIndex
					= wOrdinal - image_export_directory->Base;
		dwRVA      	= aAddresses[ iIndex] + DWORD(lpBuffer);

		if( !this->bMemoryAnalysis )
			dwTmp      	= *((DWORD*)dwRVA);
		else
			if(!ReadBytes( (LPVOID)&dwTmp, 4, dwRVA, FILE_BEGIN))
			{
				VirtualFree( (LPVOID)(DWORD(lpBuffer)+dwAddr), dwSizeOfEAT, MEM_DECOMMIT);
				VirtualFree( (LPVOID)(DWORD(_lpBuffer)+dwTmp3), dwBufSize, MEM_DECOMMIT);
				_SetError( ERROR_READ_LESS_THAN_SHOULD, __LINE__, __FUNCTION__ );
				return FALSE;
			}

		expFunc.wOrdinal 	= wOrdinal;
		expFunc.dwPtrValue 	= dwTmp;
		expFunc.dwThunkRVA	= dwTmp;

		if( (dwNameRAW-dwOffset) > this->dwSizeOfFile )
			break;

		// Parsing name of an export thunk
		if( _HexChar( *((char*)dwNameRAW)) == '.' )
		{
			expFunc.bIsOrdinal = true;
		}
		else strncpy(	expFunc.szFunction, (const char*)(dwNameRAW), sizeof(expFunc.szFunction)-1 );

		// Retrieveing address...
		if( dwTmp > imgOptionalHdr.SizeOfImage && !this->bMemoryAnalysis )
		{
					dwTmp 		= this->RVA2RAW( aAddresses[ iIndex]) + DWORD( lpBuffer);
			char 	c 			= *((char*)dwTmp);
			char 	*szTest 	= (char*)dwTmp;
			unsigned uTmp 		= strlen( szTest);

			if(c >= '0' && c <= 'z')
			{
				bool bRes = true;
				for( unsigned u = uTmp-1; u > 0; u--)
					if( !( szTest[ u] >= 0x20 && szTest[ u] <= 0x7A) ){
						bRes = false;
						break;
					}

				if( bRes)
				{
					expFunc.bIsForwarded = true;
					if( strlen( szTest) > 3)      // Function is forwarded...
						strncpy( 	expFunc.szForwarder, (const char*)dwTmp, sizeof expFunc.szForwarder - 1);
				}
			}
		}

		if( expFunc.dwPtrValue != 0 )
			vExports.push_back( expFunc);

	} // for(f = 0; unsigned(f) < image_export_directory->NumberOfFunctions; f++)

	if( this->bMemoryAnalysis )
	{
		VirtualFree( (LPVOID)(DWORD(lpBuffer)+dwAddr), dwSizeOfEAT, MEM_DECOMMIT);
		VirtualFree( (LPVOID)(DWORD(_lpBuffer)+dwTmp3), dwBufSize, MEM_DECOMMIT);
	}


	return TRUE;
}


///////////////////////////////////////////////////////////////////////////////////////
// Function fills whole IAT in memory (by collecting thunk address through GetProcAddress)
// Additional parameters: dwAddresses and dwElements can be used as an independent
// addresses table. During IAT filling normally routine gains thunks addresses by calling
// GetProcAddress. Instead, user can put his own table with thunk addresses, but this
// table must have EXACTLY every address to every thunk. In other words speaking,
// dwAddresses must point to table which will contain address to all thunks.
// dwElements specifies elements in dwAddresses table. Of course, dwElements must be equal to
// actual imports quanity.

BOOL PE::FillIAT( DWORD *dwAddresses, DWORD dwElements )
{
	if( !this->bIsValidPE)
		RETURN_ERROR2(ERROR_INVALID_PE)

	HMODULE	hModule;
	DWORD	dwAddr = 0;
	int		i = 0;

	// If there is not enough addresses in dwAddresses table, then return false
	if( dwAddresses != NULL)
		if( vImportDescriptors.size() != dwElements)
			return FALSE;

	for( unsigned u = 0; u < vImportDescriptors.size(); u++)
	{
		char *pChar = vImportDescriptors[ u].szName;
		hModule 	= LoadLibraryA( pChar);

		// Couldn't load library, omit
		if( hModule == NULL )
			continue;

		for( unsigned n = 0; n < vImportDescriptors[ u].vImports.size(); n++)
		{
			if( dwAddresses != NULL)
				dwAddr = dwAddresses[ n];
			else
				dwAddr = (DWORD)GetProcAddress(hModule, vImportDescriptors[ u].vImports[ n].szFunction);

			// Couldn't gain address of thunk, omit
			if( dwAddr == 0)
				continue;

			vImportDescriptors[ u].vImports[ n].dwPtrValue = dwAddr;
			vImports[ i++].dwPtrValue = dwAddr;

			// Big Endian to Little Endian conversion of the address
			char szAddr[ 4] = {
				char(dwAddr & 0xFF),
				char((dwAddr & 0xFF00) / 0x100),
				char((dwAddr & 0xFF0000) / 0x10000),
				char((dwAddr & 0xFF000000) / 0x1000000)
			};

			// Write this address to the file (IAT)
			// WriteBytes( (LPVOID)szAddr, 4, vImportDescriptors[ u].d.FirstThunk + n * sizeof( DWORD), 0);

			DWORD *dwAddr2 = (DWORD*)(DWORD(lpMapOfFile)+RVA2RAW(vImportDescriptors[ u].d.FirstThunk
							+ n * sizeof( DWORD)) );

			// BigEndian<->LittleEndian conversion.
			*((BYTE*) dwAddr2 ) = (BYTE)szAddr[0];
			*((BYTE*) DWORD(dwAddr2)+1 ) = (BYTE)szAddr[1];
			*((BYTE*) DWORD(dwAddr2)+2 ) = (BYTE)szAddr[2];
			*((BYTE*) DWORD(dwAddr2)+3 ) = (BYTE)szAddr[3];
		}

		FreeLibrary( hModule);
	}

	// I don't know why exactly I've crafted this variable?
	_bIsIATFilled	= true;
	return TRUE;
}

///////////////////////////////////////////////////////////////////////////////////////
// Function appends new section to the file/memory.

IMAGE_SECTION_HEADER
PE::CreateSection(	DWORD dwSizeOfSection, DWORD dwDesiredAccess, const char *szNameOfSection)
{
	IMAGE_SECTION_HEADER	ish;
	DWORD					dwFileAlignment = 0,
							dwNewVirtualAddress = 0,
							dwSectionAlignment = 0;

	memset( (void*)&ish, 0, sizeof( ish));

	if( !this->bIsValidPE)
	{
		this->_SetError( ERROR_INVALID_PE, __LINE__, __FUNCTION__ );
		return ish;
	}

	dwFileAlignment			= 	imgOptionalHdr.FileAlignment;
	dwSectionAlignment		=	imgOptionalHdr.SectionAlignment;

	//dwNewVirtualAddress     =   (GetLastSection()->SizeOfRawData / dwSectionAlignment)
	//							* dwSectionAlignment + GetLastSection()->VirtualAddress;

	dwNewVirtualAddress 	= 	GetLastSection()->SizeOfRawData + GetLastSection()->VirtualAddress;

	// section name
	if( strlen(szNameOfSection) < IMAGE_SIZEOF_SHORT_NAME)
		strcpy( (char*)ish.Name, szNameOfSection);
	else
		memcpy( (char*)ish.Name, szNameOfSection, IMAGE_SIZEOF_SHORT_NAME);

	ish.SizeOfRawData		=	dwSizeOfSection;
	ish.VirtualAddress		=	dwNewVirtualAddress;
	ish.Misc.VirtualSize	=	( dwSizeOfSection / dwFileAlignment + 1) * dwFileAlignment;
	ish.Characteristics		=	dwDesiredAccess;

	//ish.PointerToRawData	=	GetLastSection()->PointerToRawData + GetLastSection()->SizeOfRawData;
	ish.PointerToRawData	= 	this->dwSizeOfFile;

	imgFileHdr.NumberOfSections ++;
	this->uNewSections ++;

	imgOptionalHdr.SizeOfImage += ( dwSizeOfSection / dwSectionAlignment + 1) * dwSectionAlignment;

	// Increasing pSectionHdrs dynamic table
	this->pSectionHdrs		= (IMAGE_SECTION_HEADER*)realloc( pSectionHdrs,
											imgFileHdr.NumberOfSections*IMAGE_SIZEOF_SECTION_HEADER );

	// Zero-ing increased memory space
	int i = (imgFileHdr.NumberOfSections-1)*IMAGE_SIZEOF_SECTION_HEADER;
	memset( (void*)(DWORD(pSectionHdrs)+i), 0, IMAGE_SIZEOF_SECTION_HEADER );

	pSectionHdrs[ imgFileHdr.NumberOfSections-1] = ish;

	return ish;
}


///////////////////////////////////////////////////////////////////////////////////////
// Function builds an image (writes data into exe file / into memory)

BOOL PE::WriteSectionToImage( IMAGE_SECTION_HEADER *pNewSectHdr )
{
	if( !this->bIsValidPE)
		RETURN_ERROR2(ERROR_INVALID_PE)

	LPVOID lpData	= VirtualAlloc( NULL, dwSizeOfFile+8, MEM_COMMIT, PAGE_READWRITE );
	if( lpData == NULL || ::GetLastError() )
		RETURN_ERROR

	memset( lpData, 0, dwSizeOfFile+8);

#define WRITE( x, y)	if( ! WriteBytes( x, y) ){ VirtualFree(lpData, dwSizeOfFile+8,\
						MEM_DECOMMIT); this->_SetError( ERROR_WRITE_LESS_THAN_SHOULD, \
						__LINE__, __FUNCTION__ ); return FALSE;}
#define OFFSET(x)		( DWORD(lpData)+DWORD(x) )

	if(this->bMemoryAnalysis == false)
			SetFilePointer( this->hFileHandle, 0, NULL, FILE_BEGIN);
	else	this->_dwCurrentOffset = 0;

	// Headers
	WRITE( (LPVOID)&imgDosHdr, IMAGE_SIZEOF_DOS_HEADER );
	WRITE( (LPVOID)lpDOSStub, dwSizeOfDOSStub );
	WRITE( (LPVOID)&dwSignature, sizeof( dwSignature) );
	WRITE( (LPVOID)&imgFileHdr, IMAGE_SIZEOF_FILE_HEADER );
	WRITE( (LPVOID)&imgOptionalHdr, IMAGE_SIZEOF_OPTIONAL_HEADER );

	// Sections
	for( unsigned i = 0; i < GetSectionsCount()-1; i++){
		WRITE( (LPVOID)&pSectionHdrs[ i], IMAGE_SIZEOF_SECTION_HEADER );
	}

	// New section
	WRITE( pNewSectHdr, IMAGE_SIZEOF_SECTION_HEADER );

	VirtualFree( lpData, dwSizeOfFile+8, MEM_DECOMMIT);
	return TRUE;

#undef WRITE
#undef OFFSET
}


///////////////////////////////////////////////////////////////////////////////////////
// Function prepares additional shellcode and loads specified shellcode from the file.
// In shellcode user is not obliged to write JMP back instructions, this function
// takes care about it. It simply appends szAdditionalShellcode to the user's shellcode
// which makes a far jmp to the Original image Entry Point.

BOOL PE::AppendShellcode( const char *szFileWithShellcode, DWORD dwSizeOfShellcode,
					  IMAGE_SECTION_HEADER *imgNewSection )
{
	if( !this->bIsValidPE)
		RETURN_ERROR2(ERROR_INVALID_PE)

	DWORD dwRelocatedEP = dwEP + GetIB();

	char JmpOEP[4] = {
        char(dwRelocatedEP & 0xFF),
        char((dwRelocatedEP & 0xFF00) / 0x100),
        char((dwRelocatedEP & 0xFF0000) / 0x10000),
        char((dwRelocatedEP & 0xFF000000) / 0x1000000)
	};

	char szAdditionalShellcode [ 32 ] = {
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		0x90, 0xB8, JmpOEP[0], JmpOEP[1], JmpOEP[2], JmpOEP[3], 0xFF, 0xE0
	}; /* Must be 32 bytes long */

	/* Upper shellcode does:
	 *		Simple jump-back to the OEP
	 *
	 *		90					25 x NOP
	 *      B8(dwRelocatedEP)	MOV eax, dwRelocatedEP
	 *      FFE0				JMP eax
	**/

	FILE 	*pFile 	= fopen( szFileWithShellcode, "rb");

	DWORD	dwTmp 	= dwSizeOfShellcode + sizeof( szAdditionalShellcode);
	char 	*pBuf	= (char*) malloc( dwTmp);

	CHECK_MALLOC( pBuf)
	memset( pBuf, 0, dwTmp);

	// Read shellcode-file
	fread( pBuf, 1, dwSizeOfShellcode, pFile);

	// Copy data from additional shellcode table to the buffer with actual shellcode
	memcpy( (void*)(pBuf+dwSizeOfShellcode), (const void*)szAdditionalShellcode,
			sizeof( szAdditionalShellcode));

	dwTmp = imgOptionalHdr.SizeOfImage;
	dwTmp += dwSizeOfShellcode + sizeof( szAdditionalShellcode) + 1;

	// Align actual size of image
	DWORD dwTmp2 = ( dwTmp / imgOptionalHdr.SectionAlignment + 1)
			* imgOptionalHdr.SectionAlignment;

	// Set new, aligned size of image
	imgOptionalHdr.SizeOfImage = dwTmp2;

	BOOL bRes = TRUE;

	if( this->bUseRVAInsteadOfRAW )
		bRes = WriteBytes( (LPVOID)pBuf, dwSizeOfShellcode + sizeof( szAdditionalShellcode),
				imgNewSection->VirtualAddress, FILE_BEGIN );
	else
		bRes = WriteBytes( (LPVOID)pBuf, dwSizeOfShellcode + sizeof( szAdditionalShellcode),
					imgNewSection->PointerToRawData, FILE_BEGIN );

	free( pBuf);
	fclose( pFile);

	if( !bRes)
	{
		this->_SetError( ERROR_WRITE_LESS_THAN_SHOULD, __LINE__, __FUNCTION__ );
		return FALSE;
	}

	return TRUE;
}


///////////////////////////////////////////////////////////////////////////////////////
// Inserts shellcode to the file/memory

BOOL PE::InsertShellcode( const char *szFileWithShellcode, const char *szSectionName )
{
	if( !this->bIsValidPE)
		RETURN_ERROR2(ERROR_INVALID_PE)

	// Check if file exists
	FILE 	*pFile 	= fopen( szFileWithShellcode, "rb");
	if( pFile == NULL)
		RETURN_ERROR2(2)

	// Check size of shellcode
	DWORD	dwSizeOfShellcode = fseek( pFile, 0, FILE_END);
	fclose( pFile);

	IMAGE_SECTION_HEADER ish =
		CreateSection( dwSizeOfShellcode + 32, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE |
						IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE, szSectionName );
	if( !WriteSectionToImage( &ish ))
		return FALSE;

	if( !AppendShellcode( szFileWithShellcode, dwSizeOfShellcode, &ish) )
		return FALSE;

	return TRUE;
}


///////////////////////////////////////////////////////////////////////////////////////
// This routine performs file/memory READING.

BOOL PE::ReadBytes ( LPVOID lpBuffer, DWORD dwSize, DWORD dwOffset, DWORD dwMethod )
{
	DWORD	dwRead			= 0;
	DWORD	dwLastOffs		= 0;
	DWORD	dwOldProtect	= 0;

	SetLastError(0);

	if( !this->bMemoryAnalysis )
	{
		// Save file pointer
		if( dwOffset != 0 ){
			dwLastOffs = SetFilePointer( hFileHandle, dwOffset, NULL, dwMethod) ;
			if( dwLastOffs == 0xFFFFFFFF || ::GetLastError() )
				RETURN_ERROR
		}
	}
	else{
		if(dwMethod == FILE_CURRENT)
			dwOffset = _dwCurrentOffset;

		// Check page protection
		if( this->bIsValidPE)
			if( !VirtualProtectEx( this->hFileHandle, (LPVOID)(DWORD(lpMapOfFile) + dwOffset),
									dwSize, PAGE_READWRITE, &dwOldProtect ) )
				RETURN_ERROR
	}

	// READ FILE/PROCESS
	BOOL bRes;
	if( this->bMemoryAnalysis && this->bIsValidPE)
			bRes = ReadProcessMemory(	this->hFileHandle, (LPCVOID)(DWORD(lpMapOfFile)+dwOffset),
										lpBuffer, dwSize, &dwRead);
	else	bRes = ReadFile( hFileHandle, lpBuffer, dwSize, &dwRead, NULL);

	// Check for ERRORs
	if( hFileHandle == INVALID_HANDLE_VALUE || ::GetLastError() || !bRes )
			RETURN_ERROR
	else if( dwSize != dwRead )
		RETURN_ERROR2(ERROR_READ_LESS_THAN_SHOULD)

	if( !this->bMemoryAnalysis )
	{
		// Restore last file pointer
		if( dwOffset != 0 )
			if(SetFilePointer( hFileHandle, dwLastOffs, NULL, FILE_BEGIN)
				== 0xFFFFFFFF || ::GetLastError())
				RETURN_ERROR
	}
	else
		// Check page protection
		if( this->bIsValidPE)
			if( !VirtualProtectEx(	this->hFileHandle, (LPVOID)(DWORD(lpMapOfFile) + dwOffset),
									dwSize, dwOldProtect, &dwRead ) )
				RETURN_ERROR

	if( this->bIsValidPE)
		_dwCurrentOffset += dwSize;

	return TRUE;
}



///////////////////////////////////////////////////////////////////////////////////////
// This routine performs file/memory WRITING.

BOOL PE::WriteBytes ( LPVOID lpBuffer, DWORD dwSize, DWORD dwOffset, DWORD dwMethod )
{
	DWORD	dwWritten		= 0;
	DWORD	dwLastOffs		= 0;
	DWORD	dwOldProtect	= 0;

	SetLastError(0);

	// Save current file pointer
	if( !this->bMemoryAnalysis )
	{
		if( dwOffset != 0 )
			dwLastOffs = SetFilePointer( hFileHandle, dwOffset, NULL, dwMethod) ;
			if( dwLastOffs == 0xFFFFFFFF || ::GetLastError() )
				RETURN_ERROR
	}
	else{
		if( dwMethod == FILE_CURRENT)
			dwOffset = _dwCurrentOffset;

		// Check page protection
		if( this->bIsValidPE)
			if( !VirtualProtectEx( this->hFileHandle, (LPVOID)(DWORD(lpMapOfFile) + dwOffset),
									dwSize, PAGE_READWRITE, &dwOldProtect ) )
				RETURN_ERROR
	}

	// WRITE FILE/PROCESS
	BOOL bRes;

	if( this->bMemoryAnalysis && this->bIsValidPE )
			bRes = WriteProcessMemory(	this->hFileHandle, (LPVOID)(DWORD(lpMapOfFile)+dwOffset),
										lpBuffer, dwSize, &dwWritten );
	else	bRes = WriteFile( this->hFileHandle, lpBuffer, dwSize, &dwWritten, NULL);

	// Check for ERRORs
	if( hFileHandle == INVALID_HANDLE_VALUE || ::GetLastError() || !bRes )
		RETURN_ERROR
	else if( dwSize != dwWritten )
		RETURN_ERROR2(ERROR_WRITE_LESS_THAN_SHOULD)

	if( !this->bMemoryAnalysis )
	{
		// Restore last file pointer
		if( dwOffset != 0 )
			if(SetFilePointer( hFileHandle, dwLastOffs, NULL, FILE_BEGIN)
				== 0xFFFFFFFF || ::GetLastError())
				RETURN_ERROR
	}
	else
		// Check page protection
		if( this->bIsValidPE)
			if( !VirtualProtectEx(	this->hFileHandle, (LPVOID)(DWORD(lpMapOfFile) + dwOffset),
									dwSize, dwOldProtect, &dwWritten ) )
				RETURN_ERROR

	if( this->bIsValidPE)
		_dwCurrentOffset += dwSize;

	return TRUE;
}



///////////////////////////////////////////////////////////////////////////////////////
// This method simply maps file in the memory.

LPBYTE	PE::MapFile()
{
	if( _bIsFileMapped || (lpMapOfFile != (HANDLE)0xCCCCCCCC &&
		lpMapOfFile != 0 && lpMapOfFile != (HANDLE)INVALID_HANDLE_VALUE) )
		return lpMapOfFile;

	if( hFileHandle == (HANDLE)-1 || hFileHandle == (HANDLE)0xCCCCCCCC )
		_OpenFile();

	_hMapOfFile = CreateFileMappingA(	hFileHandle, NULL, PAGE_READWRITE|SEC_COMMIT,
										bhFileInformation.nFileSizeHigh,
										bhFileInformation.nFileSizeLow, NULL );
	if( _hMapOfFile == NULL || ::GetLastError() )
		RETURN_ERROR

	_bAutoMapOfFile = true;

	lpMapOfFile = (LPBYTE)MapViewOfFile( _hMapOfFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if( lpMapOfFile == NULL || ::GetLastError() )
		RETURN_ERROR

	_bIsFileMapped = true;
	this->lpMapOfFile = lpMapOfFile;

	return (LPBYTE)lpMapOfFile;
}

///////////////////////////////////////////////////////////////////////////////////////
// This functions examine sended as parameter char code, and returns it or dot code

inline char PE::_HexChar(int c)
{
	if( c >= 0x20 /* space */ && c <= 0x7D /* '}' */ )return (char)c;
	//if( c > 0x1F && c != 0x7F && c != 0x81 && c < 0xFF) return (char)c;
	else return '.';
}

///////////////////////////////////////////////////////////////////////////////////////
// Launches process module analysis by specifying desired module HMODULE handle

BOOL PE::AnalyseProcessModule( DWORD dwPID, HMODULE hModule)
{
	this->bMemoryAnalysis		= true;
	this->_bIsFileMapped		= true;
	this->dwPID					= dwPID;
	this->bUseRVAInsteadOfRAW	= true;

	this->hFileHandle = OpenProcess(	PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
										FALSE, dwPID);

	if( this->hFileHandle == NULL || this->hFileHandle == (HANDLE)INVALID_HANDLE_VALUE ||
		::GetLastError() )
		RETURN_ERROR

	// Get map of file (process base/imagebase)
	this->lpMapOfFile = (LPBYTE)hModule;
	if( this->lpMapOfFile == NULL || ::GetLastError() )
		RETURN_ERROR

	this->hProcess = this->hFileHandle;
	this->bIsValidPE = true;

	return LoadFile();
}

///////////////////////////////////////////////////////////////////////////////////////
// Launches process module analysis by specifying desired module name/path

BOOL PE::AnalyseProcessModule( DWORD dwPID, const char *szModule )
{
	this->bMemoryAnalysis		= true;
	this->_bIsFileMapped		= true;
	this->dwPID					= dwPID;
	this->bUseRVAInsteadOfRAW	= true;

	this->hFileHandle = OpenProcess(	PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
										FALSE, dwPID);

	if( this->hFileHandle == NULL || this->hFileHandle == (HANDLE)INVALID_HANDLE_VALUE ||
		::GetLastError() )
		RETURN_ERROR

	// Get process module name - hereby we have to enumerate process's modules :-)
	HMODULE lpProcessModule;
	{

		HANDLE hSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, dwPID);
		if( hSnap == NULL || hSnap == (HANDLE)INVALID_HANDLE_VALUE ||
			::GetLastError() )
			RETURN_ERROR

		MODULEENTRY32 me32;
		memset( (void*)&me32, 0, sizeof me32);
		me32.dwSize = sizeof( MODULEENTRY32 );

		if(!Module32First( hSnap, &me32))
		{
			CloseHandle( hSnap);
			SET_ERROR;
			return FALSE;
		}

		if( szModule == NULL){
			lpProcessModule = me32.hModule;
			_tcscpy( szFileName, me32.szExePath);
		}
		else
		{
			while( NULL == strstr( me32.szModule, szModule) )
			{
				if(!Module32Next( hSnap, &me32))
					RETURN_ERROR
			}

			lpProcessModule = me32.hModule;
			_tcscpy(szFileName, me32.szExePath);
		}

		CloseHandle( hSnap);
	}

	// Get map of file (process base/imagebase)
	this->lpMapOfFile = (LPBYTE)lpProcessModule;
	if( this->lpMapOfFile == NULL || ::GetLastError() )
		RETURN_ERROR

	this->hProcess = this->hFileHandle;
	this->bIsValidPE = true;

	return LoadFile();
}

///////////////////////////////////////////////////////////////////////////////////////
// Trims from input string every quote '"' character. Useful during obfuscating
// file paths.

char *PE::trimQuote( char *szPath)
{
	char *szTmp = szPath;

	if( szPath[0] == '\"' )
	{
		szTmp = (char*)(int(szTmp)+1);

		unsigned i;
		for( i = 0; i < strlen( szPath)+1; i ++)
		{
			szPath[i] = szPath[i+1];
		}
	}

	if( strrchr(szPath, '\"') != NULL )
		*((char*)strrchr(szPath, '\"')) = '\0';

	return szTmp;
}

///////////////////////////////////////////////////////////////////////////////////////
// Hooks IAT thunk

DWORD PE::HookIAT( const char* szImportThunk, DWORD dwHook)
{
	if( !this->bIsValidPE)
		RETURN_ERROR2(ERROR_INVALID_PE)

	DWORD dwOEP = 0;

	for( unsigned u = 0 ; u < vImports.size(); u++)
	{
		if( 0 != stricmp( szImportThunk, vImports[u].szFunction) )
			continue;

		dwOEP = vImports[ u].dwPtrValue;
		vImports[ u].dwPtrValue = dwHook;
		DWORD dwAddr = vImports[u].dwThunkRVA;

		// Exact hooking
		if( !WriteBytes( (LPVOID)&dwHook, 4, dwAddr, FILE_BEGIN) )
		{
			_SetError( ERROR_WRITE_LESS_THAN_SHOULD, __LINE__, __FUNCTION__);
			return (DWORD)-1;
		}

		break;
	}

	return dwOEP;
}


///////////////////////////////////////////////////////////////////////////////////////
// Hooks EAT thunk.

DWORD PE::HookEAT( const char* szExportThunk, DWORD dwHook)
{
	if( !this->bIsValidPE)
		RETURN_ERROR2(ERROR_INVALID_PE)

	DWORD dwOEP = 0;

	for( unsigned u = 0 ; u < vExports.size(); u++)
	{
		if( 0 != stricmp( szExportThunk, vExports[u].szFunction) )
			continue;

		dwOEP = vExports[ u].dwPtrValue;
		vExports[ u].dwPtrValue = dwHook;
		DWORD dwAddr = vExports[u].dwThunkRVA;

		// Exact hooking
		if( !WriteBytes( (LPVOID)&dwHook, 4, dwAddr, FILE_BEGIN) )
		{
			_SetError( ERROR_WRITE_LESS_THAN_SHOULD, __LINE__, __FUNCTION__);
			return (DWORD)-1;
		}

		break;
	}

	return dwOEP;
}
