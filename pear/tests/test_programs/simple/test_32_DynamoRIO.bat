@echo off
:: Replace paths below with paths to your WinAFL and DynamoRIO installations.
D:\bin\DynamoRIO-Windows-10.92.19888\bin32\drrun.exe -c D:\bin\winafl\build32\bin\Release\winafl.dll -debug -target_module simple32.exe -target_offset 0x75a0 -fuzz_iterations 10 -nargs 2 -- simple32.exe .\corpus\1 