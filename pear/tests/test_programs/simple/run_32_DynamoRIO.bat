@echo off
:: Replace paths below with paths to your WinAFL and DynamoRIO installations.
D:\bin\winafl\build32\bin\Release\afl-fuzz.exe -i .\corpus\ -o .\afl-out -w D:\bin\winafl\build32\bin\Release\winafl.dll -D D:\bin\DynamoRIO-Windows-10.92.19888\bin32\ -t 1000+ -- -coverage_module simple32.exe -fuzz_iterations 5000 -target_module simple32.exe -target_offset 0x75a0 -nargs 2 -- simple32.exe "@@"