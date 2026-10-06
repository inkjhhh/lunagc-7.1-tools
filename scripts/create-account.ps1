# Creates a LunaGC account by driving the server console over a kept-open stdin pipe.
# startConsole() only bails out on EndOfFileException, so holding the write end
# open keeps the console alive and lets us inject commands.
# ASCII-only: PowerShell 5.1 parses BOM-less .ps1 as GBK otherwise.

$ErrorActionPreference = 'Continue'

$javaHome = 'C:\Program Files\Eclipse Adoptium\jdk-17.0.20.101-hotspot'
$appDir   = 'C:\LunaGC\LunaGC_7.1.0'
$jar      = Join-Path $appDir 'LunaGC-7.1.0.jar'
$logOut   = Join-Path $appDir 'server-console.log'
$logErr   = Join-Path $appDir 'server-console-err.log'

$username = '11111111'
$password = '11111111'

# --- Make sure MongoDB is up ---
if (-not (Get-NetTCPConnection -State Listen -LocalPort 27017 -ErrorAction SilentlyContinue)) {
    $mongoBin = 'C:\LunaGC\tools\mongodb\mongodb-win32-x86_64-windows-9.0.2\bin\mongod.exe'
    $mongoDb  = 'C:\LunaGC\tools\mongodb-data'
    Write-Host 'Starting MongoDB...' -ForegroundColor Yellow
    $mongoArgs = @('--dbpath', "`"$mongoDb`"", '--bind_ip', '127.0.0.1', '--port', '27017',
                   '--logpath', "`"$mongoDb\mongod.log`"")
    Start-Process -FilePath $mongoBin -ArgumentList $mongoArgs -WindowStyle Hidden | Out-Null
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 500
        if (Get-NetTCPConnection -State Listen -LocalPort 27017 -ErrorAction SilentlyContinue) { break }
    }
}
if (-not (Get-NetTCPConnection -State Listen -LocalPort 27017 -ErrorAction SilentlyContinue)) {
    Write-Host 'ERROR: MongoDB is not up.' -ForegroundColor Red
    exit 1
}
Write-Host 'MongoDB is listening on 27017.' -ForegroundColor Green

# --- Launch the server with an open stdin pipe ---
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName               = (Join-Path $javaHome 'bin\java.exe')
$psi.Arguments              = '-jar "LunaGC-7.1.0.jar"'
$psi.WorkingDirectory       = $appDir
$psi.UseShellExecute        = $false
$psi.RedirectStandardInput  = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError  = $true
$psi.CreateNoWindow         = $true

$proc = New-Object System.Diagnostics.Process
$proc.StartInfo = $psi
$outSb = New-Object System.Text.StringBuilder
$errSb = New-Object System.Text.StringBuilder
$null = Register-ObjectEvent -InputObject $proc -EventName OutputDataReceived -Action {
    if ($EventArgs.Data) { $null = $Event.MessageData.AppendLine($EventArgs.Data) }
} -MessageData $outSb
$null = Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived -Action {
    if ($EventArgs.Data) { $null = $Event.MessageData.AppendLine($EventArgs.Data) }
} -MessageData $errSb

[void]$proc.Start()
$proc.BeginOutputReadLine()
$proc.BeginErrorReadLine()
Write-Host ("Server started (PID {0})." -f $proc.Id) -ForegroundColor Green

# --- Wait until the console prompt is ready ---
$ready = $false
for ($i = 0; $i -lt 120; $i++) {
    Start-Sleep -Seconds 1
    if ($outSb.ToString() -match '22101') { $ready = $true; break }
    if ($proc.HasExited) { break }
}
if (-not $ready -or $proc.HasExited) {
    Write-Host 'Server did not start cleanly.' -ForegroundColor Red
    $outSb.ToString() | Set-Content -Path $logOut -Encoding UTF8
    exit 1
}
Start-Sleep -Seconds 5

# --- Create the account ---
Write-Host ("Creating account '{0}'..." -f $username) -ForegroundColor Cyan
$proc.StandardInput.WriteLine("account create $username $password")
$proc.StandardInput.Flush()
Start-Sleep -Seconds 6

$outSb.ToString() | Set-Content -Path $logOut -Encoding UTF8
$errSb.ToString() | Set-Content -Path $logErr -Encoding UTF8

Write-Host ''
Write-Host '=== Output tail ===' -ForegroundColor Yellow
($outSb.ToString() -split "`r?`n") | Where-Object { $_ -match '\S' } | Select-Object -Last 8

Write-Host ''
Write-Host ("Server PID {0} running. Username: {1}  Password: {2}" -f $proc.Id, $username, $password) -ForegroundColor Green
Write-Host 'Now launch the game.' -ForegroundColor Green
Read-Host 'Press Enter to detach (server keeps running)' | Out-Null