#!/bin/bash

# AgentK8s - Clean Implementation Startup Script

echo "🚀 Starting AgentK8s Clean Implementation..."

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

# Check if pip is installed
if ! command -v pip &> /dev/null; then
    echo "❌ pip is not installed. Please install pip."
    exit 1
fi

# Install dependencies if requirements.txt exists
if [ -f "requirements.txt" ]; then
    echo "📦 Installing dependencies..."
    pip install -r requirements.txt
else
    echo "⚠️ requirements.txt not found. Please ensure all dependencies are installed."
fi

# Check if Streamlit is installed
if ! command -v streamlit &> /dev/null; then
    echo "❌ Streamlit is not installed. Installing..."
    pip install streamlit
fi

# Start the application
echo "🌟 Launching AgentK8s..."
echo "🌐 Application will be available at: http://localhost:8501"
echo "⏹️  Press Ctrl+C to stop the application"
echo ""

streamlit run main.py
