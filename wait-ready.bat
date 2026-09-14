@echo off
setlocal enabledelayedexpansion

set READY_FILE=C:\ThreatBox\output\etw-ready
set DEBUG_LOG=C:\ThreatBox\output\wsb-debug.log
set MAX_WAIT_SECONDS=90
set ELAPSED=0

echo %date% %time% wait-ready: polling for %READY_FILE%>>%DEBUG_LOG%

:poll
if exist "%READY_FILE%" (
    echo %date% %time% wait-ready: collector signaled ready after %ELAPSED%s>>%DEBUG_LOG%
    exit /b 0
)

if %ELAPSED% GEQ %MAX_WAIT_SECONDS% (
    echo %date% %time% wait-ready: TIMEOUT after %ELAPSED%s - etw-ready never appeared>>%DEBUG_LOG%
    exit /b 1
)

timeout /t 1 /nobreak >nul
set /a ELAPSED+=1
goto poll
