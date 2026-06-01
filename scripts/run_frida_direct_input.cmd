@echo off
set "SCRIPT_DIR=%~dp0"
frida %* -l "%SCRIPT_DIR%wa_direct_input_frida.js"
