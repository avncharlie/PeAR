@echo off
:: Replace paths below with paths to your WinAFL and DynamoRIO installations.
D:\bin\DynamoRIO-Windows-10.92.19888\bin64\drrun.exe -c D:\bin\winafl\build64\bin\Release\winafl.dll -debug -target_module befunge64.exe -target_offset 0x239C -fuzz_iterations 10 -nargs 2 -- befunge64.exe .\corpus\hello_world.bef



