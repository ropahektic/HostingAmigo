@echo off
REM Run from cmd.exe only. After Frida starts you see "[Local::PID::...]->" — that is Frida's
REM JavaScript prompt, NOT cmd. Type "exit" to quit Frida, then run another .cmd in a NEW window.
setlocal
set "DIR=%~dp0"
if "%~2"=="" (
  echo Usage: %~nx0 host^|joiner PID
  echo Example: %~nx0 host 15968
  echo          %~nx0 joiner 13496
  echo Copy this file next to frida_wa_tcp_host.js / frida_wa_tcp_joiner.js and WA.exe.
  exit /b 1
)
set "R=%~1"
set "P=%~2"
if /I "%R%"=="host" (
  frida -p %P% -l "%DIR%frida_wa_tcp_host.js"
  exit /b %ERRORLEVEL%
)
if /I "%R%"=="joiner" (
  frida -p %P% -l "%DIR%frida_wa_tcp_joiner.js"
  exit /b %ERRORLEVEL%
)
echo First argument must be host or joiner, not: %R%
exit /b 1
