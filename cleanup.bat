@echo off
echo ========================================
echo EKS Operations Review - Cleanup Script
echo ========================================
echo.
echo This script will clean up the following local resources:
echo - Generated reports and logs
echo - Temporary files
echo - Python cache files
echo - Virtual environment (optional)
echo.
echo Note: This does NOT delete any AWS resources.
echo You must manually delete any EKS clusters you created.
echo.
set /p confirm="Proceed with local cleanup? (y/n): "
if /i not "%confirm%"=="y" (
    echo Cleanup cancelled.
    pause
    exit /b 0
)

echo.
echo Cleaning up local files...
echo ========================

REM Clean up reports
if exist "reports\" (
    echo Removing generated reports...
    rmdir /s /q "reports\"
    mkdir "reports"
    echo ✓ Reports cleaned
)

REM Clean up logs
if exist "*.log" (
    echo Removing log files...
    del /q "*.log"
    echo ✓ Log files cleaned
)

REM Clean up Python cache
if exist "__pycache__\" (
    echo Removing Python cache...
    rmdir /s /q "__pycache__\"
    echo ✓ Python cache cleaned
)

if exist "src\__pycache__\" (
    rmdir /s /q "src\__pycache__\"
)

REM Clean up temporary files
if exist "*.tmp" (
    echo Removing temporary files...
    del /q "*.tmp"
    echo ✓ Temporary files cleaned
)

if exist "*.temp" (
    del /q "*.temp"
)

echo.
set /p clean_venv="Remove virtual environment? (y/n): "
if /i "%clean_venv%"=="y" (
    if exist "venv\" (
        echo Removing virtual environment...
        rmdir /s /q "venv\"
        echo ✓ Virtual environment removed
    )
)

echo.
echo ========================================
echo Local Cleanup Complete!
echo ========================================
echo.
echo Local files have been cleaned up.
echo.
echo IMPORTANT: Remember to manually delete any AWS resources:
echo - EKS clusters
echo - EC2 instances
echo - Load balancers
echo - VPCs (if created for EKS)
echo.
echo Use AWS Console or CLI to delete these resources.
echo.
pause
