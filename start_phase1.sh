#!/bin/bash

# Phase 1 Quick Start Script
echo "🚀 Starting Phase 1 Implementation..."

# Check if required files exist
if [ ! -f "phase1_implementation.py" ]; then
    echo "❌ phase1_implementation.py not found"
    exit 1
fi

# Set up environment
echo "📦 Setting up environment..."
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"

# Check AWS credentials
if [ -z "$AWS_ACCESS_KEY_ID" ]; then
    echo "⚠️  AWS_ACCESS_KEY_ID not set"
    echo "Please set your AWS credentials:"
    echo "export AWS_ACCESS_KEY_ID=your-key"
    echo "export AWS_SECRET_ACCESS_KEY=your-secret"
    echo "export AWS_DEFAULT_REGION=us-west-2"
    echo "export EKS_CLUSTER_NAME=arcus-test"
fi

# Run validation tests
echo "🧪 Running Phase 1 validation tests..."
python test_phase1.py

if [ $? -eq 0 ]; then
    echo "✅ Validation passed! Starting Phase 1 app..."
    
    # Start the Phase 1 Streamlit app
    echo "🌐 Starting Phase 1 Streamlit app on http://localhost:8501"
    streamlit run phase1_implementation.py
else
    echo "❌ Validation failed. Please check the issues above."
    exit 1
fi
