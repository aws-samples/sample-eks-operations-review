@echo off
echo Starting EKS Operational Review Agent...
echo.

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Start the Streamlit application
echo Application will be available at: http://localhost:8501
echo Press Ctrl+C to stop the application
echo.
streamlit run app.py

pause