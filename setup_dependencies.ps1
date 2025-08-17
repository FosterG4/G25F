# G25F Injector - Dependencies Setup Script
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "G25F Injector - Dependencies Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Create external directory if it doesn't exist
if (-not (Test-Path "external")) {
    Write-Host "[INFO] Creating external directory..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path "external" | Out-Null
}

# Check if websocketpp exists
if (-not (Test-Path "external\websocketpp")) {
    Write-Host "[INFO] Cloning websocketpp..." -ForegroundColor Yellow
    git clone https://github.com/zaphoyd/websocketpp.git external/websocketpp
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to clone websocketpp" -ForegroundColor Red
        Read-Host "Press Enter to continue"
        exit 1
    }
} else {
    Write-Host "[INFO] websocketpp already exists" -ForegroundColor Green
}

# Check if json exists
if (-not (Test-Path "external\json")) {
    Write-Host "[INFO] Cloning nlohmann/json..." -ForegroundColor Yellow
    git clone https://github.com/nlohmann/json.git external/json
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to clone nlohmann/json" -ForegroundColor Red
        Read-Host "Press Enter to continue"
        exit 1
    }
} else {
    Write-Host "[INFO] nlohmann/json already exists" -ForegroundColor Green
}

# Check if asio exists
if (-not (Test-Path "external\asio")) {
    Write-Host "[INFO] Cloning asio..." -ForegroundColor Yellow
    git clone https://github.com/chriskohlhoff/asio.git external/asio
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to clone asio" -ForegroundColor Red
        Read-Host "Press Enter to continue"
        exit 1
    }
} else {
    Write-Host "[INFO] asio already exists" -ForegroundColor Green
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "DEPENDENCIES SETUP COMPLETED!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "All required external libraries are now available." -ForegroundColor White
Write-Host "You can now run: .\build_release.ps1" -ForegroundColor Cyan
Write-Host ""
Read-Host "Press Enter to continue"
