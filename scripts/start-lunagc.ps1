# One-click LunaGC 7.1.0 launcher.
# Starts MongoDB if needed, then runs the server in THIS console so the
# in-game command prompt works and output is visible.
# ASCII-only: PowerShell 5.1 parses BOM-less .ps1 as GBK otherwise.

$ErrorActionPreference = 'Continue'

$javaHome = 'C:\Program Files\Eclipse Adoptium\jdk-17.0.20.101-hotspot'
$appDir   = 'C:\LunaGC\LunaGC_7.1.0'
$jar      = Join-Path $appDir 'LunaGC-7.1.0.jar'
$tools    = 'C:\LunaGC\tools'
$mongoBin = Join-Path $tools 'mongodb\mongodb-win32-x86_64-windows-9.0.2\bin\mongod.exe'
$mongoDb  = Join-Path $tools 'mongodb-data'

function Say($msg, $color = 'White') { Write-Host $msg -ForegroundColor $color }

Say '=== LunaGC 7.1.0 launcher ===' Cyan
Say '' Cyan

# ---------------------------------------------------------------- prerequisites
if (-not (Test-Path "$javaHome\bin\java.exe")) {
    Say "ERROR: JDK not found at $javaHome" Red
    Read-Host 'Press Enter to exit' | Out-Null
    exit 1
}
if (-not (Test-Path $jar)) {
    Say "ERROR: JAR not found at $jar" Red
    Read-Host 'Press Enter to exit' | Out-Null
    exit 1
}
if (-not (Test-Path $mongoBin)) {
    Say "ERROR: mongod.exe not found at $mongoBin" Red
    Read-Host 'Press Enter to exit' | Out-Null
    exit 1
}

# ---------------------------------------------------------------------- MongoDB
$mongoListening = Get-NetTCPConnection -State Listen -LocalPort 27017 -ErrorAction SilentlyContinue
if ($mongoListening) {
    Say '[1/2] MongoDB already listening on 27017' Green
} else {
    Say '[1/2] Starting MongoDB...' Yellow
    if (-not (Test-Path $mongoDb)) { New-Item -ItemType Directory -Force -Path $mongoDb | Out-Null }
    $mongoArgs = @(
        '--dbpath', "`"$mongoDb`"",
        '--bind_ip', '127.0.0.1',
        '--port', '27017',
        '--logpath', "`"$mongoDb\mongod.log`""
    )
    Start-Process -FilePath $mongoBin -ArgumentList $mongoArgs -WindowStyle Hidden | Out-Null

    $up = $false
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 500
        if (Get-NetTCPConnection -State Listen -LocalPort 27017 -ErrorAction SilentlyContinue) { $up = $true; break }
    }
    if ($up) { Say '      MongoDB is up.' Green }
    else {
        Say '      ERROR: MongoDB did not come up. Check mongodb-data\mongod.log' Red
        Read-Host 'Press Enter to exit' | Out-Null
        exit 1
    }
}

# ------------------------------------------------------- already running check
$existing = Get-CimInstance Win32_Process -Filter "Name='java.exe'" |
            Where-Object { $_.CommandLine -match 'LunaGC' }
if ($existing) {
    Say ''
    Say 'A LunaGC server is already running:' Yellow
    $existing | ForEach-Object { Say ("  PID {0}" -f $_.ProcessId) Yellow }
    Say ''
    $ans = Read-Host 'Stop it and restart? (y/n)'
    if ($ans -eq 'y') {
        foreach ($p in $existing) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Seconds 3
        Say 'Stopped.' Green
    } else {
        Say 'Leaving it alone.' DarkGray
        Read-Host 'Press Enter to exit' | Out-Null
        exit 0
    }
}

# ----------------------------------------------------------------- the server
Say ''
Say '[2/2] Starting LunaGC server...' Yellow
Say '     This window IS the server console - type /account, /give, /stat here.' DarkGray
Say '     Press Ctrl+C twice to shut down.' DarkGray
Say '' Cyan

Set-Location $appDir
& "$javaHome\bin\java.exe" -jar $jar

Say ''
Say 'Server exited.' Yellow
Read-Host 'Press Enter to close' | Out-Null