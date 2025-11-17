"""
UI Components - Reusable Streamlit components
"""
import streamlit as st
from typing import Dict, Any, List

class UIComponents:
    """Reusable UI components for Streamlit"""
    
    @staticmethod
    def render_metric_card(title: str, value: str, delta: str = None, status: str = "normal"):
        """Render a metric card with status styling"""
        status_class = {
            "good": "status-good",
            "warning": "status-warning", 
            "danger": "status-danger",
            "normal": ""
        }.get(status, "")
        
        st.markdown(f"""
        <div class="metric-card {status_class}">
            <h4>{title}</h4>
            <h2>{value}</h2>
            {f'<p>{delta}</p>' if delta else ''}
        </div>
        """, unsafe_allow_html=True)
    
    @staticmethod
    def render_status_badge(status: str, text: str = None):
        """Render a status badge"""
        colors = {
            "ACTIVE": "🟢",
            "INACTIVE": "🔴", 
            "DEGRADED": "🟡",
            "PASS": "✅",
            "FAIL": "❌",
            "WARNING": "⚠️"
        }
        
        icon = colors.get(status, "⚪")
        display_text = text or status
        
        return f"{icon} {display_text}"
    
    @staticmethod
    def render_progress_bar(value: int, max_value: int = 100, label: str = ""):
        """Render a progress bar"""
        percentage = (value / max_value) * 100
        st.progress(percentage / 100)
        if label:
            st.caption(f"{label}: {value}/{max_value} ({percentage:.1f}%)")
    
    @staticmethod
    def render_code_block(code: str, language: str = "bash", title: str = None):
        """Render a code block with optional title"""
        if title:
            st.subheader(title)
        st.code(code, language=language)
    
    @staticmethod
    def render_info_box(title: str, content: Dict[str, Any]):
        """Render an information box"""
        with st.expander(title):
            for key, value in content.items():
                st.write(f"**{key}:** {value}")
    
    @staticmethod
    def render_alert(message: str, alert_type: str = "info"):
        """Render an alert message"""
        if alert_type == "success":
            st.success(message)
        elif alert_type == "warning":
            st.warning(message)
        elif alert_type == "error":
            st.error(message)
        else:
            st.info(message)
