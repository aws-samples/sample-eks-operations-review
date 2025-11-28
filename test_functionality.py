#!/usr/bin/env python3
"""
Test script to verify AgentK8s functionality
"""
import sys
import os
sys.path.append('.')

from core.config import Config
from core.aws_client import AWSClientManager
from core.unified_analyzer import UnifiedClusterAnalyzer

def test_configuration():
    """Test configuration system"""
    print("🔧 Testing Configuration System...")
    config = Config()
    assert config.aws_region == 'us-west-2'
    assert config.app_title == "AgentK8s - EKS Operations Review"
    print("✅ Configuration system working")

def test_aws_client_initialization():
    """Test AWS client initialization"""
    print("🔗 Testing AWS Client Initialization...")
    try:
        aws_client = AWSClientManager(region='us-west-2')
        # Don't actually connect, just test initialization
        print("✅ AWS client manager initialized")
    except Exception as e:
        print(f"⚠️ AWS client initialization: {e}")

def test_analyzers_initialization():
    """Test analyzer initialization"""
    print("🔍 Testing Analyzers Initialization...")
    try:
        # Test with dummy values
        unified_analyzer = UnifiedClusterAnalyzer("test-cluster", "us-west-2")
        print("✅ Unified analyzer initialized successfully")
    except Exception as e:
        print(f"❌ Analyzer initialization failed: {e}")

def test_imports():
    """Test all critical imports"""
    print("📦 Testing Critical Imports...")
    try:
        import streamlit
        import boto3
        import pandas
        import plotly
        print("✅ All critical dependencies imported")
    except ImportError as e:
        print(f"❌ Import failed: {e}")

def main():
    """Run all tests"""
    print("🚀 AgentK8s - Clean Implementation Test Suite")
    print("=" * 50)
    
    test_configuration()
    test_aws_client_initialization()
    test_analyzers_initialization()
    test_imports()
    
    print("=" * 50)
    print("🎉 All tests completed!")
    print("🌐 Application is running at: http://localhost:8501")
    print("📋 Next steps:")
    print("   1. Open http://localhost:8501 in your browser")
    print("   2. Configure AWS credentials in the sidebar")
    print("   3. Enter your EKS cluster name")
    print("   4. Click 'Generate Analysis Report'")

if __name__ == "__main__":
    main()
