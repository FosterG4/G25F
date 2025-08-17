# PowerShell Manual Build Script for G25F Injector
Write-Host "Building G25F Injector Standalone (Manual Build)..." -ForegroundColor Green
Write-Host ""

# Create output directory
$outputDir = "..\build\electron"
$unpackedDir = "$outputDir\win-unpacked"
$resourcesDir = "$unpackedDir\resources\backend"

if (!(Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force }
if (!(Test-Path $unpackedDir)) { New-Item -ItemType Directory -Path $unpackedDir -Force }
if (!(Test-Path $resourcesDir)) { New-Item -ItemType Directory -Path $resourcesDir -Force }

# Copy application files
Write-Host "Copying application files..." -ForegroundColor Yellow
Copy-Item "*.js" -Destination $unpackedDir -Force
Copy-Item "*.html" -Destination $unpackedDir -Force
Copy-Item "*.css" -Destination $unpackedDir -Force
Copy-Item "assets" -Destination $unpackedDir -Recurse -Force

# Copy backend executable
Write-Host "Copying backend executable..." -ForegroundColor Yellow
Copy-Item "..\build\Release\G25F_Injector_Backend.exe" -Destination $resourcesDir -Force

# Copy Electron runtime
Write-Host "Copying Electron runtime..." -ForegroundColor Yellow
Copy-Item "node_modules\electron\dist\electron.exe" -Destination "$unpackedDir\G25F Injector.exe" -Force

# Create launcher script
Write-Host "Creating launcher script..." -ForegroundColor Yellow
$launcherContent = @"
@echo off
cd /d "%~dp0win-unpacked"
start "" "G25F Injector.exe"
"@

$launcherContent | Out-File -FilePath "$outputDir\G25F-Injector-Standalone.bat" -Encoding ASCII

# Create PowerShell launcher
$psLauncherContent = @"
# PowerShell Launcher for G25F Injector
Set-Location "`$PSScriptRoot\win-unpacked"
Start-Process "G25F Injector.exe"
"@

$psLauncherContent | Out-File -FilePath "$outputDir\G25F-Injector-Standalone.ps1" -Encoding UTF8

Write-Host ""
Write-Host "Manual build completed!" -ForegroundColor Green
Write-Host "Standalone executable: $outputDir\G25F-Injector-Standalone.bat" -ForegroundColor Cyan
Write-Host "PowerShell launcher: $outputDir\G25F-Injector-Standalone.ps1" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
