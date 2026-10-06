# Stops the game process and injects the LunaGC patch DLL.
# ASCII-only on purpose: Windows PowerShell 5.1 parses .ps1 as GBK when
# there is no BOM, which mangles non-ASCII comments and breaks quoting.
# Run as Administrator, or let this script re-launch itself elevated.

$ErrorActionPreference = 'Continue'

$plugins  = 'G:\Genshin Impact Game\YuanShen_Data\Plugins'
$target   = Join-Path $plugins 'Astrolabe.dll'
$backup   = Join-Path $plugins 'Astrolabe.dll.bak'
$patchDll = 'C:\LunaGC\LunaGC_7.1.0\patch\Astrolabe.dll'

# --- Self-elevate if not already admin ---
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
   ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host 'Not admin. Requesting elevation (click Yes in the UAC prompt)...' -ForegroundColor Yellow
    Start-Process -FilePath 'powershell.exe' `
        -ArgumentList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-NoExit', '-File', $PSCommandPath
        ) `
        -Verb RunAs
    return
}

Write-Host '=== Running elevated ===' -ForegroundColor Green

# --- 1. Kill processes holding the DLL ---
$names = @('YuanShen', 'GenshinImpact')
$procs = Get-Process -Name $names -ErrorAction SilentlyContinue

if ($procs) {
    foreach ($proc in $procs) {
        Write-Host ("Killing {0} (PID {1})..." -f $proc.ProcessName, $proc.Id) -ForegroundColor Cyan
        try {
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
        } catch {
            Write-Host ("  Stop-Process failed, falling back to taskkill: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
            taskkill /PID $proc.Id /F /T 2>&1 | Out-String | Write-Host
        }
    }

    # Wait for the file handles to be released
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        if (-not (Get-Process -Name $names -ErrorAction SilentlyContinue)) { break }
    }

    $still = Get-Process -Name $names -ErrorAction SilentlyContinue
    if ($still) {
        Write-Host 'Process still alive. Possible anti-cheat driver holding it.' -ForegroundColor Red
        $still | ForEach-Object { Write-Host ("  PID {0}" -f $_.Id) -ForegroundColor Red }
        Read-Host 'Press Enter to exit'
        return
    }
    Write-Host 'Process exited, file handles released.' -ForegroundColor Green
} else {
    Write-Host 'Game was not running.' -ForegroundColor Green
}

# --- 2. Back up the original DLL (only if no backup yet) ---
if (-not (Test-Path $backup)) {
    Copy-Item $target $backup -Force
    Write-Host ("Backed up original DLL to {0}" -f $backup) -ForegroundColor Green
} else {
    Write-Host 'Backup already exists, skipping.' -ForegroundColor DarkGray
}

# --- 3. Inject the patch DLL ---
Copy-Item $patchDll $target -Force
$h1 = (Get-FileHash $target -Algorithm SHA256).Hash
$h2 = (Get-FileHash $patchDll -Algorithm SHA256).Hash
if ($h1 -eq $h2) {
    Write-Host 'Patch DLL injected (SHA256 verified).' -ForegroundColor Green
} else {
    Write-Host 'SHA256 mismatch, verify manually.' -ForegroundColor Red
}
Get-Item $target | Select-Object Name, Length, LastWriteTime | Format-List | Out-String | Write-Host

Write-Host ''
Write-Host '=== Done ===' -ForegroundColor Cyan
Write-Host 'To restore the original: rename Astrolabe.dll.bak back to Astrolabe.dll'
Write-Host ''
Write-Host 'Next: start MongoDB, then run LunaGC-7.1.0.jar, then launch the game.'
Read-Host 'Press Enter to close'