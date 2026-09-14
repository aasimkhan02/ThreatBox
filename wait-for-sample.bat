@echo off
setlocal

:WAIT

if exist C:\ThreatBox\output\start-sample goto RUN

timeout /t 1 /nobreak >nul

goto WAIT

:RUN

del C:\ThreatBox\output\start-sample >nul 2>&1

echo STARTING SAMPLE > C:\ThreatBox\output\sample-started.log

start "" /wait cmd.exe /k C:\ThreatBox\sample\sample.exe

echo SAMPLE EXITED %ERRORLEVEL% > C:\ThreatBox\output\sample-exit.log

echo.
echo ========================================
echo SAMPLE FINISHED
echo Sandbox will remain open for inspection.
echo ========================================
echo.

timeout /t 600 /nobreak

REM TEMPORARILY DISABLED:
REM taskkill /IM etw-collector.exe /F /T
REM echo done > C:\ThreatBox\output\analysis.done
REM shutdown /s /t 0 /f