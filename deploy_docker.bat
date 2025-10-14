@echo off
echo Building and deploying EKS Operational Review Agent with Docker...
echo.

REM Build the Docker image
echo Building Docker image...
docker build -t eks-review-agent .

REM Check if build was successful
if %ERRORLEVEL% NEQ 0 (
    echo Docker build failed!
    pause
    exit /b 1
)

echo.
echo Docker image built successfully!
echo.

REM Create environment file template if it doesn't exist
if not exist .env (
    echo Creating .env template file...
    echo # AWS Configuration > .env
    echo AWS_ACCESS_KEY_ID=your_access_key_here >> .env
    echo AWS_SECRET_ACCESS_KEY=your_secret_key_here >> .env
    echo AWS_DEFAULT_REGION=us-west-2 >> .env
    echo. >> .env
    echo # Optional Bedrock Configuration >> .env
    echo BEDROCK_KNOWLEDGE_BASE_ID=your_kb_id_here >> .env
    echo. >> .env
    echo # Application Configuration >> .env
    echo LOG_LEVEL=INFO >> .env
    echo MAX_REQUESTS_PER_MINUTE=10 >> .env
    echo.
    echo Please edit the .env file with your AWS credentials before running the container.
    echo.
)

REM Run the container
echo Starting Docker container...
echo Application will be available at: http://localhost:8501
echo Press Ctrl+C to stop the container
echo.

docker run -p 8501:8501 --env-file .env -v "%cd%\reports:/app/reports" eks-review-agent

pause