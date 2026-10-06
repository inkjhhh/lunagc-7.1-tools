@echo off
REM Double-click launcher for LunaGC 7.1.0
title LunaGC 7.1.0 Server
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\LunaGC\start-lunagc.ps1"
if errorlevel 1 pause