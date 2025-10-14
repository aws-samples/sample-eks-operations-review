@echo off
echo Installing EKS Operations Review Prerequisites for Windows...
echo.

REM Check if chocolatey is installed
where choco >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Installing Chocolatey package manager...
    powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
    if %ERRORLEVEL% NEQ 0 (
        echo Failed to install Chocolatey. Please install manually from https://chocolatey.org/install
        pause
        exit /b 1
    )
    echo Chocolatey installed successfully!
    echo Please restart this script in a new command prompt.
    pause
    exit /b 0
)

echo Chocolatey is available, installing required tools...
echo.

REM Install kubectl
echo Installing kubectl...
choco install kubernetes-cli -y
if %ERRORLEVEL% NEQ 0 (
    echo Failed to install kubectl
    pause
    exit /b 1
)

REM Check AWS CLI
echo Checking AWS CLI...
where aws >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Installing AWS CLI...
    choco install awscli -y
    if %ERRORLEVEL% NEQ 0 (
        echo Failed to install AWS CLI
        pause
        exit /b 1
    )
)

echo.
echo ✓ All prerequisites installed successfully!
echo.
echo Next steps:
echo 1. Configure AWS credentials: aws configure
echo 2. Run the application: .\start_app.bat
echo.
pause
