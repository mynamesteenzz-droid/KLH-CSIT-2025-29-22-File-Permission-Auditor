  GNU nano 7.2                                         run_auditor.sh
#!/usr/bin/env bash
set -euo pipefail

if [[ ! -e /proc/sys/fs/binfmt_misc/WSLInterop ]]; then
    echo "WSL Windows interop is disabled in this session; Windows executables cannot be launched from Ubuntu." >&2
    echo "Enable interop in /etc/wsl.conf ([interop] with enabled=true), then restart WSL and retry ./run_auditor.sh." >
    exit 1
fi

powershell_exe="$(command -v powershell.exe)"
ps_script=$(cat <<'PS'
$ErrorActionPreference = 'Stop'
$package = Get-AppxPackage -Name Microsoft.WindowsTerminal |
    Sort-Object Version -Descending |
    Select-Object -First 1
if (-not $package) { throw 'Windows Terminal package was not found.' }
$wt = Join-Path $package.InstallLocation 'wt.exe'
if (-not (Test-Path -LiteralPath $wt)) { throw "Windows Terminal CLI not found: $wt" }
Start-Process -FilePath $wt -ArgumentList '-w new wsl.exe -d Ubuntu -- bash -lc "cd /root/FilePermissionAuditor_Final &>
PS
)
encoded_command="$(printf '%s' "$ps_script" | iconv -f UTF-8 -t UTF-16LE | base64 -w 0)"
"$powershell_exe" -NoProfile -EncodedCommand "$encoded_command"
