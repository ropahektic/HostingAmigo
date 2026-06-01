@echo off
REM Lists WA PIDs + window titles without changing global ExecutionPolicy.
REM Requires list_wa_instances.ps1 in the same folder (copy both to the WA game dir).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0list_wa_instances.ps1"
exit /b %ERRORLEVEL%
