@echo off
REM AgentK8s - Windows Startup Script

echo 🚀 Starting AgentK8s EKS Operations Review Tool...

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python is not installed or not in PATH. Please install Python 3.8 or higher.
    pause
    exit /b 1
)

REM Check if pip is installed
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ pip is not installed. Please install pip.
    pause
    exit /b 1
)

REM Install dependencies if requirements.txt exists
if exist "requirements.txt" (
    echo 📦 Installing/updating dependencies...
    pip install -r requirements.txt
) else (
    echo ⚠️ requirements.txt not found. Please ensure all dependencies are installed.
)

REM Check if Streamlit is installed
streamlit --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Streamlit is not installed. Installing...
    pip install streamlit
)

REM Start the application
echo.
echo 🌟 Launching AgentK8s...
echo 🌐 Application will be available at: http://localhost:8501
echo ⏹️  Press Ctrl+C to stop the application
echo.

streamlit run main.py
