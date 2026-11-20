@echo off
cd /d "%~dp0"
if exist run.vbs (
    start "" wscript.exe "%~dp0run.vbs"
) else (
    start "" "%~dp0bin\kpacketshield-ui.exe"
)
exit /b 0
