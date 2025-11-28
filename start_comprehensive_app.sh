#!/bin/bash

echo "=========================================="
echo "EKS Analyzer - Comprehensive V2.0"
echo "=========================================="
echo ""
echo "Starting Streamlit app with:"
echo "  ✓ All 152 DORA checks"
echo "  ✓ 7 compliance frameworks"
echo "  ✓ 300+ comprehensive checks"
echo "  ✓ Enterprise PDF reports"
echo "  ✓ Comprehensive Excel reports"
echo ""
echo "The app will open at: http://localhost:8501"
echo ""
echo "To stop: Press Ctrl+C"
echo "=========================================="
echo ""

# Set environment variable for comprehensive mode
export COMPREHENSIVE_MODE=true

# Run streamlit
streamlit run main.py
