@echo off
setlocal enabledelayedexpansion

echo ===================================================
echo   Building KPacketShield with MinGW-w64 (GCC)
echo ===================================================

:: Add MSYS2 UCRT64 to PATH if not already present
if exist C:\msys64\ucrt64\bin\gcc.exe (
    set "PATH=C:\msys64\ucrt64\bin;!PATH!"
) else if exist C:\msys64\mingw64\bin\gcc.exe (
    set "PATH=C:\msys64\mingw64\bin;!PATH!"
)

where gcc.exe >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] gcc.exe not found! Please ensure MSYS2 MinGW-w64 is installed.
    exit /b 1
)

echo Using GCC:
gcc --version | findstr /i "gcc"

if not exist bin mkdir bin

echo Compiling source files...
gcc -Wall -Wextra -O2 -Isrc -Ideps\windivert\include -DWIN32_LEAN_AND_MEAN -c src\main.c -o src\main.o
if %ERRORLEVEL% neq 0 goto :fail

gcc -Wall -Wextra -O2 -Isrc -Ideps\windivert\include -DWIN32_LEAN_AND_MEAN -c src\wfp_engine.c -o src\wfp_engine.o
if %ERRORLEVEL% neq 0 goto :fail

gcc -Wall -Wextra -O2 -Isrc -Ideps\windivert\include -DWIN32_LEAN_AND_MEAN -c src\proc_map.c -o src\proc_map.o
if %ERRORLEVEL% neq 0 goto :fail

gcc -Wall -Wextra -O2 -Isrc -Ideps\windivert\include -DWIN32_LEAN_AND_MEAN -c src\monitor.c -o src\monitor.o
if %ERRORLEVEL% neq 0 goto :fail

gcc -Wall -Wextra -O2 -Isrc -Ideps\windivert\include -DWIN32_LEAN_AND_MEAN -c src\rule_store.c -o src\rule_store.o
if %ERRORLEVEL% neq 0 goto :fail

gcc -Wall -Wextra -O2 -Isrc -Ideps\windivert\include -DWIN32_LEAN_AND_MEAN -c src\ipc_pipe.c -o src\ipc_pipe.o
if %ERRORLEVEL% neq 0 goto :fail

gcc -Wall -Wextra -O2 -Isrc -Ideps\windivert\include -DWIN32_LEAN_AND_MEAN -c src\service.c -o src\service.o
if %ERRORLEVEL% neq 0 goto :fail

echo Linking bin\kpacketshield.exe...
gcc src\main.o src\wfp_engine.o src\proc_map.o src\monitor.o src\rule_store.o src\ipc_pipe.o src\service.o -o bin\kpacketshield.exe -Ldeps\windivert\lib -lWinDivert -lfwpuclnt -liphlpapi -lws2_32 -lshlwapi -lshell32
if %ERRORLEVEL% neq 0 goto :fail

echo Compiling bin\kps.exe...
gcc -Wall -Wextra -O2 src\kps_cli.c -o bin\kps.exe
if %ERRORLEVEL% neq 0 goto :fail

echo Copying WinDivert binaries to bin\...
copy /Y deps\windivert\bin\WinDivert.dll bin\ >nul
copy /Y deps\windivert\bin\WinDivert64.sys bin\ >nul

echo [SUCCESS] Built bin\kpacketshield.exe successfully!
exit /b 0

:fail
echo [ERROR] Build failed!
exit /b 1
