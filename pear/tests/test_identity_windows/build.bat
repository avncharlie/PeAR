@echo off
setlocal

rem 1) Build DLL with named exports + named EXE
cl /nologo /c testdll.c
link /nologo /DLL testdll.obj /DEF:testdll_named.def /OUT:testdll.named.dll
rem import lib produced: testdll.named.lib
cl /nologo main.c testdll.named.lib /Fe:main.named.exe

rem 2) Build DLL with ordinal-only (NONAME) exports + ordinal-import EXE
cl /nologo /c testdll.c
link /nologo /DLL testdll.obj /DEF:testdll_ordinal.def /OUT:testdll.ord.dll
rem import lib produced: testdll.ord.lib (imports by ordinal)
cl /nologo main.c testdll.ord.lib /Fe:main.ord.exe

rem 3) Delay-load (named exports)
cl /nologo main.c testdll.named.lib delayimp.lib /Fe:main.delay.exe ^
  /link /DELAYLOAD:testdll.dll

rem 4) Delay-load + ordinal-only exports
cl /nologo main.c testdll.ord.lib delayimp.lib /Fe:main.delayord.exe ^
  /link /DELAYLOAD:testdll.dll

echo.
echo Built:
echo   main.named.exe      + testdll.named.dll   (normal, by name)
echo   main.ord.exe        + testdll.ord.dll     (implicit import by ordinal only)
echo   main.delay.exe      + testdll.named.dll   (delay-load, by name)
echo   main.delayord.exe   + testdll.ord.dll     (delay-load, by ordinal)
echo.
endlocal

