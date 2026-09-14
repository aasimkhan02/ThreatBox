@echo off

start "" C:\ThreatBox\tools\etw-collector.exe

timeout /t 120 /nobreak

start "" /wait C:\ThreatBox\sample\sample.exe

taskkill /IM etw-collector.exe /F /T

echo done>C:\ThreatBox\output\analysis.done

shutdown /s /t 0 /f