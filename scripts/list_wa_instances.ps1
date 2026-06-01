<#
.SYNOPSIS
List running WA (and related) processes with PID and window title for Frida -p.

.EXAMPLE
  .\list_wa_instances.ps1

If you get "running scripts is disabled", either:
  - Run list_wa_instances.cmd from the same folder (uses Bypass for this file only), or
  - powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\list_wa_instances.ps1"
#>
$ErrorActionPreference = 'SilentlyContinue'
$names = @('WA', 'WA Updated')
$rows = foreach ($n in $names) {
    Get-Process -Name $n -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
            Pid     = $_.Id
            Name    = $_.ProcessName
            Title   = $_.MainWindowTitle
        }
    }
}
if (-not $rows) {
    Write-Host "No process named WA or WA Updated found." -ForegroundColor Yellow
    exit 0
}
$rows | Sort-Object Pid | Format-Table -AutoSize
Write-Host "Use the PID from the title bar [...] with: run_frida_wa_tcp.cmd host|joiner <Pid>" -ForegroundColor DarkCyan
