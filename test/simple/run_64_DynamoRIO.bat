@echo off
:: Replace paths below with paths to your WinAFL and DynamoRIO installations.
D:\bin\winafl\build64\bin\Release\afl-fuzz.exe -i .\corpus\ -o .\afl-out -w D:\bin\winafl\build64\bin\Release\winafl.dll -D D:\bin\DynamoRIO-Windows-10.92.19888\bin64\ -t 1000+ -- -coverage_module simple64.exe -fuzz_iterations 5000 -target_module simple64.exe -target_offset 0x7500 -nargs 2 -- simple64.exe "@@"