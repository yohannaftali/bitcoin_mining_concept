# This script sets up a Python virtual environment using uv and installs dependencies
# for the Grid Martingale Lite Telegram bot.

Write-Host "Setting up Python virtual environment with uv..." -ForegroundColor Green

# Check if uv is installed
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
  Write-Host "uv is not installed. Installing uv..." -ForegroundColor Yellow
  # Install uv using the official installer
  Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression
  if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to install uv. Please install it manually and try again." -ForegroundColor Red
    exit 1
  }
}

# Check if Python is installed
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
  Write-Host "Python is not installed. Please install Python and try again." -ForegroundColor Red
  exit 1
}

# Remove existing venv if it exists (uv manages its own venv)
if (Test-Path ".\.venv") {
  Write-Host "Removing existing virtual environment..." -ForegroundColor Yellow
  Remove-Item -Recurse -Force .\.venv
}

# Sync dependencies using uv
Write-Host "Installing dependencies with uv..." -ForegroundColor Yellow
uv sync
if ($LASTEXITCODE -ne 0) {
  Write-Host "Failed to install dependencies with uv." -ForegroundColor Red
  exit 1
}

Write-Host "Virtual environment setup complete. To activate it manually, run:" -ForegroundColor Green
Write-Host "uv run <command>" -ForegroundColor Yellow
Write-Host "Or activate the virtual environment with:" -ForegroundColor Yellow
Write-Host ".\.venv\Scripts\Activate.ps1" -ForegroundColor Yellow

# Debugging steps
Write-Host "Debugging steps:" -ForegroundColor Green
Write-Host "1. Check the Python executable being used:" -ForegroundColor Yellow
Write-Host "   where python" -ForegroundColor Yellow
Write-Host "   Ensure it points to the Python installation used to create the virtual environment." -ForegroundColor Yellow
Write-Host "2. Run the script manually after activating the virtual environment:" -ForegroundColor Yellow
Write-Host "   .\.venv\Scripts\Activate.ps1" -ForegroundColor Yellow
Write-Host "   python src/main.py" -ForegroundColor Yellow
