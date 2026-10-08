# Build the Windows executable and (optionally) the installer.
# Usage (from the repository root, in PowerShell):
#   powershell -ExecutionPolicy Bypass -File phone_media_vault\installer\build.ps1 [-DownloadAdb] [-SkipInstaller]
param(
    [switch]$DownloadAdb,
    [switch]$SkipInstaller
)
$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$pkg = Join-Path $repo "phone_media_vault"
Set-Location $repo

Write-Host "==> Installing build dependencies"
python -m pip install --upgrade pip
python -m pip install -r (Join-Path $pkg "requirements-dev.txt")

Write-Host "==> Running tests"
python -m unittest discover -s phone_media_vault/tests
if ($LASTEXITCODE -ne 0) { throw "Tests failed; aborting build." }

if ($DownloadAdb) {
    Write-Host "==> Downloading Android Platform-Tools"
    $zip = Join-Path $env:TEMP "platform-tools-latest-windows.zip"
    Invoke-WebRequest "https://dl.google.com/android/repository/platform-tools-latest-windows.zip" -OutFile $zip
    $extract = Join-Path $env:TEMP "pmv-platform-tools"
    if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }
    Expand-Archive $zip -DestinationPath $extract
    Copy-Item (Join-Path $extract "platform-tools\*") (Join-Path $pkg "platform-tools") -Recurse -Force
}

$version = (python -c "import phone_media_vault; print(phone_media_vault.__version__)").Trim()
$env:PMV_VERSION = $version
Write-Host "==> Building PhoneMediaVault $version with PyInstaller"
python -m PyInstaller --noconfirm --clean `
    --distpath (Join-Path $pkg "dist") --workpath (Join-Path $pkg "build") `
    (Join-Path $pkg "installer\phone_media_vault.spec")

if (-not $SkipInstaller) {
    $iscc = Get-Command iscc.exe -ErrorAction SilentlyContinue
    if (-not $iscc) {
        $default = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
        if (Test-Path $default) { $iscc = $default } else { $iscc = $null }
    }
    if ($iscc) {
        Write-Host "==> Building installer with Inno Setup"
        & $iscc (Join-Path $pkg "installer\PhoneMediaVault.iss")
    } else {
        Write-Warning "Inno Setup 6 (ISCC.exe) not found; skipped the installer. The app folder is in phone_media_vault\dist\PhoneMediaVault."
    }
}
Write-Host "==> Done"
