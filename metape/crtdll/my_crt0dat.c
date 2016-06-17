/***
*my_crt0dat.c - 32-bit C run-time initialization/termination routines
* copy and fix from : C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\crt\src\crt0dat.c
*      
*
*Purpose:
*       make compiler happy
*       
*       
*       
*       
*
*       [NOTE: maybe has some problem,  maybe cause by  the def:CRTDLL;_DLL; .]
*author : fhc 
*******************************************************************************/

// #include <cruntime.h>
// #include <msdos.h>
// #include <rtcapi.h>
// #include <dos.h>
// #include <oscalls.h>
// #include <mtdll.h>
// #include <awint.h>
#include <internal.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <process.h>
// #include <dbgint.h>
#include <sect_attribs.h>
// #include <mbctype.h>
// #include <mbdata.h>
// #include <awint.h>
/*
 * pointers to initialization sections
 */

extern _CRTALLOC(".CRT$XIA") _PIFV __xi_a[];
extern _CRTALLOC(".CRT$XIZ") _PIFV __xi_z[];    /* C initializers */
extern _CRTALLOC(".CRT$XCA") _PVFV __xc_a[];
extern _CRTALLOC(".CRT$XCZ") _PVFV __xc_z[];    /* C++ initializers */
extern _CRTALLOC(".CRT$XPA") _PVFV __xp_a[];
extern _CRTALLOC(".CRT$XPZ") _PVFV __xp_z[];    /* C pre-terminators */
extern _CRTALLOC(".CRT$XTA") _PVFV __xt_a[];
extern _CRTALLOC(".CRT$XTZ") _PVFV __xt_z[];    /* C terminators */

/*
 * pointers to the start and finish of the _onexit/atexit table
 * NOTE - the pointers are stored encoded.
 */
_PVFV *__onexitbegin;
_PVFV *__onexitend;


/*
 * static (internal) functions that walk a table of function pointers,
 * calling each entry between the two pointers, skipping NULL entries
 *
 * _initterm needs to be exported for CRT DLL so that C++ initializers in the
 * client EXE / DLLs can be initialized.
 *
 * _initterm_e calls function pointers that return a nonzero error code to
 * indicate an initialization failed fatally.
 */
#ifdef CRTDLL
void __cdecl _initterm(_PVFV *, _PVFV *);
#else  /* CRTDLL */
static void __cdecl _initterm(_PVFV *, _PVFV *);
#endif  /* CRTDLL */
int  __cdecl _initterm_e(_PIFV *, _PIFV *);





/***
* static void _initterm(_PVFV * pfbegin, _PVFV * pfend) - call entries in
*       function pointer table
*
*Purpose:
*       Walk a table of function pointers, calling each entry, as follows:
*
*           1. walk from beginning to end, pfunctbl is assumed to point
*              to the beginning of the table, which is currently a null entry,
*              as is the end entry.
*           2. skip NULL entries
*           3. stop walking when the end of the table is encountered
*
*Entry:
*       _PVFV *pfbegin  - pointer to the beginning of the table (first
*                         valid entry).
*       _PVFV *pfend    - pointer to the end of the table (after last
*                         valid entry).
*
*Exit:
*       No return value
*
*Notes:
*       This routine must be exported in the CRT DLL model so that the client
*       EXE and client DLL(s) can call it to initialize their C++ constructors.
*
*Exceptions:
*       If either pfbegin or pfend is NULL, or invalid, all bets are off!
*
*******************************************************************************/

#ifdef CRTDLL
void __cdecl _initterm (
#else  /* CRTDLL */
static void __cdecl _initterm (
#endif  /* CRTDLL */
        _PVFV * pfbegin,
        _PVFV * pfend
        )
{
        /*
         * walk the table of function pointers from the bottom up, until
         * the end is encountered.  Do not skip the first entry.  The initial
         * value of pfbegin points to the first valid entry.  Do not try to
         * execute what pfend points to.  Only entries before pfend are valid.
         */
        while ( pfbegin < pfend )
        {
            /*
             * if current table entry is non-NULL, call thru it.
             */
            if ( *pfbegin != NULL )
                (**pfbegin)();
            ++pfbegin;
        }
}


