#!/bin/bash

echo "=========================================="
echo "EKS Analyzer - Enhanced V2.0"
echo "=========================================="
echo ""

# Check if streamlit is installed
if ! command -v streamlit &> /dev/null; then
    echo "⚠️  Streamlit not found. Installing dependencies..."
    pip3 install --user streamlit boto3 openpyxl reportlab
    echo ""
fi

echo "🚀 Starting Streamlit app..."
echo ""
echo "The app will open in your browser at: http://localhost:8501"
echo ""
echo "To stop the app, press Ctrl+C"
echo ""
echo "=========================================="
echo ""

# Run streamlit
streamlit run main.py
