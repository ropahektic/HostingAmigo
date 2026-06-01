@echo off
REM Always loads frida_wa_ground_truth.js from this folder (portable: cwd can be anywhere).
REM Example: run_frida_ground_truth.cmd -n "WA.exe"
REM          run_frida_ground_truth.cmd -f "C:\Games\WA\WA.exe"
REM Env: WA_MODULE  WA_PUT_MESSAGE_RVA  WA_FRIDA_CONFIG  (see frida_wa_ground_truth.js header)
set "SCRIPT_DIR=%~dp0"
frida %* -l "%SCRIPT_DIR%frida_wa_ground_truth.js"
