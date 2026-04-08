param(
    [switch]$SetupOnly,
    [switch]$StartServices
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Resolve-Path (Join-Path $scriptDir '..')
$rootPath = $root.Path

if (-not $SetupOnly -and -not $StartServices) {
    $SetupOnly = $true
    $StartServices = $true
}

function Get-Python313 {
    $candidates = @(
        'C:\Python313\python.exe',
        'c:\python313\python.exe'
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    throw 'Python 3.13 was not found. Install Python 3.13, then rerun this command.'
}

$venvPath = Join-Path $rootPath '.venv313'
$venvPython = Join-Path $venvPath 'Scripts\python.exe'

if (-not (Test-Path $venvPython)) {
    Write-Host 'Creating Python 3.13 virtual environment in .venv313 ...'
    $python313 = Get-Python313
    & $python313 -m venv $venvPath
}

Write-Host 'Installing backend dependencies ...'
& $venvPython -m pip install --upgrade pip

$backendPath = Join-Path $rootPath 'backend'
& $venvPython -m pip install fastapi uvicorn python-socketio joblib pandas numpy scikit-learn tensorflow requests

Write-Host 'Installing frontend dependencies ...'
Push-Location (Join-Path $rootPath 'frontend')
& npm.cmd install --legacy-peer-deps
& npm.cmd install --legacy-peer-deps prop-types
Pop-Location

if ($SetupOnly -and -not $StartServices) {
    Write-Host 'Setup complete.'
    exit 0
}

Write-Host 'Starting backend and frontend in separate PowerShell windows ...'

$backendCommand = "Set-Location '$backendPath'; & '$venvPython' -m uvicorn app:app --host 0.0.0.0 --port 8000"
$frontendPath = Join-Path $rootPath 'frontend'
$frontendCommand = "Set-Location '$frontendPath'; npm.cmd run dev -- --host 0.0.0.0 --port 5173"

Start-Process powershell -ArgumentList '-NoExit', '-ExecutionPolicy', 'Bypass', '-Command', $backendCommand | Out-Null
Start-Process powershell -ArgumentList '-NoExit', '-ExecutionPolicy', 'Bypass', '-Command', $frontendCommand | Out-Null

Write-Host 'Services launched.'
Write-Host 'Backend:  http://localhost:8000'
Write-Host 'Frontend: http://localhost:5173'
