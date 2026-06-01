# WA game TCP capture for vanilla P2P tests (run on Windows 11 before playing).
# Requires: Wireshark/Npcap installed (https://npcap.com/ or Wireshark installer).
#
# Usage (PowerShell as Administrator recommended):
#   .\wa_capture.ps1
#   .\wa_capture.ps1 -InterfaceName "Ethernet"
#   .\wa_capture.ps1 -OutFile "$env:USERPROFILE\Desktop\wa-red-blue-surrender.pcapng"
#
# Then upload the .pcapng to CT 104:
#   scp wa-red-blue-surrender.pcapng root@192.168.1.57:/opt/WormNETBot/captures/incoming/
#
# Tell the agent: "vanilla capture uploaded: wa-red-blue-surrender.pcapng"

param(
    [string]$InterfaceName = "",
    [int]$Port = 17011,
    [string]$OutFile = "",
    [int]$RingSeconds = 0
)

$ErrorActionPreference = "Stop"

function Find-Dumpcap {
    $candidates = @(
        "${env:ProgramFiles}\Wireshark\dumpcap.exe",
        "${env:ProgramFiles(x86)}\Wireshark\dumpcap.exe",
        "${env:ProgramFiles}\Wireshark\tshark.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    throw "Wireshark not found. Install from https://www.wireshark.org/download.html (include Npcap)."
}

function List-Interfaces {
    $dumpcap = Find-Dumpcap
    Write-Host "`nAvailable capture interfaces (use -InterfaceName):" -ForegroundColor Cyan
    & $dumpcap -D
}

if (-not $OutFile) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutFile = Join-Path $env:USERPROFILE "Desktop" "wa-game-$stamp.pcapng"
}

$dumpcap = Find-Dumpcap
$isTshark = $dumpcap -like "*tshark.exe*"

if (-not $InterfaceName) {
    Write-Host "No -InterfaceName set. Listing interfaces..." -ForegroundColor Yellow
    List-Interfaces
    Write-Host "`nRe-run with:  .\wa_capture.ps1 -InterfaceName `"Wi-Fi`"" -ForegroundColor Green
    Write-Host "Or Ethernet / the interface that carries your game traffic.`n"
    exit 1
}

$filter = "tcp port $Port"
Write-Host "Capturing WA game traffic" -ForegroundColor Cyan
Write-Host "  Interface : $InterfaceName"
Write-Host "  Filter    : $filter"
Write-Host "  Output    : $OutFile"
Write-Host "`nStart Worms, host/join, play until AFTER results screen." -ForegroundColor Yellow
Write-Host "Press Ctrl+C here when done to stop capture.`n"

$args = @("-i", $InterfaceName, "-f", $filter, "-w", $OutFile)
if ($RingSeconds -gt 0) {
    $args += @("-b", "duration:$RingSeconds")
}

try {
    if ($isTshark) {
        # fallback: tshark can capture too
        & $dumpcap -i $InterfaceName -f $filter -w $OutFile
    } else {
        & $dumpcap @args
    }
} catch {
    if ($_.Exception.Message -match "refused|access|permission") {
        Write-Host "`nTry: Run PowerShell as Administrator (Npcap needs elevation)." -ForegroundColor Red
    }
    throw
}

if (Test-Path $OutFile) {
    $size = (Get-Item $OutFile).Length
    Write-Host "`nSaved: $OutFile ($size bytes)" -ForegroundColor Green
    Write-Host @"

Upload to CT 104 (adjust IP/user if needed):
  scp "$OutFile" root@192.168.1.57:/opt/WormNETBot/captures/incoming/

Or WinSCP / FileZilla -> /opt/WormNETBot/captures/incoming/

Then in Cursor chat:
  vanilla capture uploaded: $(Split-Path $OutFile -Leaf)
  (note: red surrendered, blue won — or whatever happened)

"@ -ForegroundColor Green
}
