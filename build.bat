@echo off
set PATH=C:\MinGW\bin;%PATH%
gcc -Wall -Wextra -O2 lc3.c -o lc3-vm.exe
if errorlevel 1 (
  echo Build failed.
  exit /b 1
)
echo Build OK: lc3-vm.exe
