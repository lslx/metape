
0. project is static linked to crt.

1. make dir :G:\dev_code\metape\metape\crtexe\

2. copy the file(num:9) list from dir :C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\crt\src\
awint.h
crt0.c
cruntime.h
dbgint.h
internal.h
isa_availability.h
mtdll.h
rterr.h
sect_attribs.h

3. add crt0.c to project 
4. set single file property
4.1  include dir : .\crtexe
4.2  pre define : _CRTBLD;


5. thats all , copiler the single file crt0.c,  it must be ok.