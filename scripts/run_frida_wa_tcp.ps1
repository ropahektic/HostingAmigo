<#
.SYNOPSIS
Attach Frida TCP capture to one WA process by PID (required when multiple WA.exe run).

If ExecutionPolicy blocks this script, use run_frida_wa_tcp.cmd from the same folder, or:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\run_frida_wa_tcp.ps1" -Role host -Pid 15968

.DESCRIPTION
Frida's -n "WA.exe" is ambiguous with several instances. WA shows the OS PID in the
window title (e.g. "Worms Armageddon [15968]"); pass that number to -Pid.

One Frida session = one process. For host + 2 joiners, run this script three times
in three terminals with three different -Pid values (or use Start-Process per below).

.PARAMETER Role
  host   -> frida_wa_tcp_host.js
  joiner -> frida_wa_tcp_joiner.js (use for every non-host client you want to log)

.PARAMETER GameDir
  Folder containing WA.exe and the frida_wa_tcp_*.js files (copy scripts there first).

.EXAMPLE
  .\run_frida_wa_tcp.ps1 -Role host -Pid 15968

.EXAMPLE
  .\run_frida_wa_tcp.ps1 -Role joiner -Pid 13496
  .\run_frida_wa_tcp.ps1 -Role joiner -Pid 12576
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('host', 'joiner')]
    [string] $Role,

    [Parameter(Mandatory = $true)]
    [int] $Pid,

    [string] $GameDir = 'C:\Program Files (x86)\Steam\steamapps\common\Worms Armageddon',

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $FridaExtra
)

$ErrorActionPreference = 'Stop'
$wa = Join-Path $GameDir 'WA.exe'
$js = if ($Role -eq 'host') {
    Join-Path $GameDir 'frida_wa_tcp_host.js'
} else {
    Join-Path $GameDir 'frida_wa_tcp_joiner.js'
}

if (-not (Test-Path -LiteralPath $wa)) {
    Write-Error "WA.exe not found: $wa (fix -GameDir)"
}
if (-not (Test-Path -LiteralPath $js)) {
    Write-Error "Script not found: $js (copy frida_wa_tcp_$Role.js from repo scripts\ into GameDir)"
}

$p = Get-Process -Id $Pid -ErrorAction SilentlyContinue
if (-not $p) {
    Write-Error "No process with Id $Pid. Run .\list_wa_instances.ps1"
}

Write-Host "Attaching frida to PID $Pid ($($p.ProcessName)) role=$Role" -ForegroundColor Cyan
Write-Host "Script: $js" -ForegroundColor DarkGray

& frida -p $Pid -l $js @FridaExtra
