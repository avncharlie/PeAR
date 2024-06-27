@echo off
:: Replace paths below with paths to your WinAFL and DynamoRIO installations.
D:\bin\DynamoRIO-Windows-10.92.19888\bin32\drrun.exe -c D:\bin\winafl\build32\bin\Release\winafl.dll -debug -target_module befunge32.exe -target_offset 0x3C42 -fuzz_iterations 10 -nargs 2 -- befunge32.exe .\corpus\hello_world.bef