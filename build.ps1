# PowerShell Build Script for KPacketShield
$ErrorActionPreference = "Stop"

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  Building KPacketShield with MinGW-w64 (GCC)" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan

if (Test-Path "C:\msys64\ucrt64\bin\gcc.exe") {
    $env:PATH = "C:\msys64\ucrt64\bin;" + $env:PATH
} elseif (Test-Path "C:\msys64\mingw64\bin\gcc.exe") {
    $env:PATH = "C:\msys64\mingw64\bin;" + $env:PATH
}

$gcc = Get-Command gcc -ErrorAction SilentlyContinue
if (-not $gcc) {
    Write-Error "gcc.exe not found! Please ensure MSYS2 MinGW-w64 is installed."
    exit 1
}

Write-Host "Compiler: $(& gcc --version | Select-Object -First 1)" -ForegroundColor Green

if (-not (Test-Path "bin")) {
    New-Item -ItemType Directory -Path "bin" | Out-Null
}

$cflags = @("-Wall", "-Wextra", "-O2", "-Isrc", "-Ideps/windivert/include", "-DWIN32_LEAN_AND_MEAN")
$sources = @(
    "src/main.c",
    "src/wfp_engine.c",
    "src/proc_map.c",
    "src/monitor.c",
    "src/rule_store.c",
    "src/ipc_pipe.c",
    "src/service.c"
)

$objs = @()
foreach ($src in $sources) {
    $obj = $src -replace '\.c$', '.o'
    Write-Host "Compiling $src..."
    & gcc @cflags -c $src -o $obj
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to compile $src"
        exit 1
    }
    $objs += $obj
}

Write-Host "Linking bin\kpacketshield.exe..." -ForegroundColor Yellow
$ldflags = @("-Ldeps/windivert/lib", "-lWinDivert", "-lfwpuclnt", "-liphlpapi", "-lws2_32", "-lshlwapi", "-lshell32")
& gcc @objs -o "bin/kpacketshield.exe" @ldflags
if ($LASTEXITCODE -ne 0) {
    Write-Error "Linking failed."
    exit 1
}

Write-Host "Compiling and linking client bin\kps.exe..." -ForegroundColor Yellow
& gcc -Wall -Wextra -O2 src/kps_cli.c -o "bin/kps.exe"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Client linking failed."
    exit 1
}

Copy-Item "deps/windivert/bin/WinDivert.dll" "bin/" -Force
Copy-Item "deps/windivert/bin/WinDivert64.sys" "bin/" -Force

Write-Host "[SUCCESS] Built bin\kpacketshield.exe successfully!" -ForegroundColor Green
