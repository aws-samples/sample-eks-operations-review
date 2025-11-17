#!/bin/bash

# Clean startup script for AgentK8s

echo "🚀 Starting AgentK8s Multi-Agent System..."

# Kill any existing streamlit processes
pkill -f streamlit 2>/dev/null || true
sleep 2

# Navigate to directory
cd "/Users/pmenghan/Downloads/sample-eks-operations-review-main 5/AgentK8snew"

# Activate virtual environment
source venv/bin/activate

# Test imports
echo "🔍 Testing imports..."
python3 -c "
import sys
sys.path.append('.')
from core.config import Config
from ui.streamlit_app import StreamlitApp
print('✅ Core imports successful')
"

if [ $? -eq 0 ]; then
    echo "🌟 Starting application on port 8503..."
    echo "🌐 Open: http://localhost:8503"
    streamlit run main.py --server.port=8503 --server.address=0.0.0.0
else
    echo "❌ Import test failed"
    exit 1
fi
