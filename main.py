#!/usr/bin/env python3
"""
AgentK8s - Clean Implementation
Main application entry point with all current features preserved
"""

import streamlit as st
import asyncio
import sys
import os

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ui.streamlit_app import StreamlitApp
from core.config import Config

def main():
    """Main application entry point"""
    # Initialize configuration
    config = Config()
    
    # Initialize and run Streamlit app
    app = StreamlitApp(config)
    app.run()

if __name__ == "__main__":
    main()
