@echo off
REM Clean startup script for AgentK8s on Windows

echo 🚀 Starting AgentK8s Multi-Agent System...

REM Kill any existing streamlit processes (Windows approach)
taskkill /f /im "python.exe" /fi "WINDOWTITLE eq *streamlit*" >nul 2>&1

REM Wait a moment
timeout /t 2 /nobreak >nul

REM Test imports
echo 🔍 Testing imports...
python -c "import sys; sys.path.append('.'); from core.config import Config; from ui.streamlit_app import StreamlitApp; print('✅ Core imports successful')"

if %errorlevel% equ 0 (
    echo 🌟 Starting application on port 8501...
    echo 🌐 Open: http://localhost:8501
    streamlit run main.py --server.port=8501 --server.address=localhost
) else (
    echo ❌ Import test failed
    pause
    exit /b 1
)
