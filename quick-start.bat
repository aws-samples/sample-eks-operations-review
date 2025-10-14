@echo off
echo ========================================
echo EKS Operations Review - Quick Start
echo ========================================
echo.
echo This script will set up everything you need:
echo 1. Install prerequisites (kubectl, AWS CLI)
echo 2. Help configure AWS credentials
echo 3. Start the Operations Review Application
echo.
echo Note: You need an existing EKS cluster to analyze
echo.
echo Estimated time: 5-10 minutes
echo.
pause

echo.
echo Step 1: Installing Prerequisites...
echo ===================================
call setup-prerequisites.bat
if %ERRORLEVEL% NEQ 0 (
    echo Failed to install prerequisites
    pause
    exit /b 1
)

echo.
echo Step 2: AWS Configuration
echo ========================
echo Checking AWS credentials...
aws sts get-caller-identity >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo AWS credentials not configured. Please run:
    echo aws configure
    echo.
    echo Enter your:
    echo - AWS Access Key ID
    echo - AWS Secret Access Key  
    echo - Default region ^(recommend: us-west-2^)
    echo - Default output format ^(json^)
    echo.
    pause
    aws configure
    
    echo Testing credentials...
    aws sts get-caller-identity
    if %ERRORLEVEL% NEQ 0 (
        echo AWS configuration failed. Please check your credentials.
        pause
        exit /b 1
    )
) else (
    echo ✓ AWS credentials are configured
    aws sts get-caller-identity
)

echo.
echo Step 3: Starting Application
echo ===========================
echo Starting the EKS Operations Review Application...
echo.
echo The application will open at: http://localhost:8501
echo.
echo Make sure you have:
echo - An existing EKS cluster to analyze
echo - Proper IAM permissions for EKS access
echo.
echo Press any key to start the application...
pause

call start_app.bat

echo.
echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo Your EKS Operations Review Application is running.
echo Open your browser to: http://localhost:8501
echo.
echo Enter your existing EKS cluster details in the application.
echo.
pause
