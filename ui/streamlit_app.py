"""
Streamlit UI - Clean implementation with working PDF downloads and no scores
"""
import streamlit as st
import json
from datetime import datetime
from typing import Dict, Any, Optional

from core.analyzers import HealthAnalyzer, SecurityAnalyzer
from core.config import Config
from ui.components import UIComponents
from utils.pdf_generator import PDFGenerator

class StreamlitApp:
    """Main Streamlit application"""
    
    def __init__(self, config: Config):
        self.config = config
        self.ui = UIComponents()
    
    def _safe_metric(self, label: str, value, delta=None):
        """Safely display metric, handling various data types"""
        try:
            # Handle different data types
            if isinstance(value, (list, tuple)):
                display_value = len(value)
            elif isinstance(value, dict):
                display_value = len(value)
            elif isinstance(value, str):
                display_value = value
            elif isinstance(value, (int, float)):
                display_value = value
            else:
                display_value = str(value)
            
            st.metric(label, display_value, delta)
        except Exception as e:
            st.metric(label, "N/A", delta)
        
    def run(self):
        """Run the Streamlit application"""
        self._setup_page()
        self._render_sidebar()
        self._render_main_content()
    
    def _setup_page(self):
        """Setup page configuration"""
        st.set_page_config(
            page_title=self.config.app_title,
            page_icon=self.config.app_icon,
            layout="wide",
            initial_sidebar_state="expanded"
        )
        
        # Custom CSS
        st.markdown("""
        <style>
        .main-header {
            background: linear-gradient(90deg, #FF6B6B, #4ECDC4);
            padding: 1rem;
            border-radius: 10px;
            margin-bottom: 2rem;
            text-align: center;
            color: white;
        }
        .metric-card {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 8px;
            border-left: 4px solid #007bff;
            margin: 0.5rem 0;
        }
        .status-good { border-left-color: #28a745 !important; }
        .status-warning { border-left-color: #ffc107 !important; }
        .status-danger { border-left-color: #dc3545 !important; }
        </style>
        """, unsafe_allow_html=True)
    
    def _render_sidebar(self):
        """Render sidebar configuration"""
        with st.sidebar:
            st.header("🔧 Configuration")
            
            # AWS Configuration
            st.subheader("AWS Settings")
            
            # IAM Role or Access Keys
            auth_method = st.radio(
                "Authentication Method",
                ["IAM Role (Recommended)", "Access Keys"],
                help="IAM Role is more secure for production use"
            )
            
            if auth_method == "IAM Role (Recommended)":
                role_arn = st.text_input(
                    "IAM Role ARN",
                    placeholder="arn:aws:iam::123456789012:role/AgentK8sRole",
                    help="Leave empty to use default AWS credentials"
                )
                st.session_state['role_arn'] = role_arn if role_arn else None
                st.session_state['aws_access_key'] = None
                st.session_state['aws_secret_key'] = None
            else:
                aws_access_key = st.text_input("AWS Access Key ID", type="password")
                aws_secret_key = st.text_input("AWS Secret Access Key", type="password")
                st.session_state['aws_access_key'] = aws_access_key
                st.session_state['aws_secret_key'] = aws_secret_key
                st.session_state['role_arn'] = None
            
            # Region and Cluster
            aws_region = st.selectbox(
                "AWS Region",
                ["us-west-2", "us-east-1", "eu-west-1", "ap-southeast-1"],
                index=0
            )
            
            cluster_name = st.text_input(
                "EKS Cluster Name",
                placeholder="my-eks-cluster",
                help="Enter the name of your EKS cluster"
            )
            
            st.session_state['aws_region'] = aws_region
            st.session_state['cluster_name'] = cluster_name
            
            # Analysis Options
            st.subheader("Analysis Options")
            analysis_depth = st.selectbox(
                "Analysis Depth",
                ["Quick (2 min)", "Comprehensive (5 min)", "Security Focus (3 min)", "🤖 Multi-Agent Analysis (7 min)"],
                index=1
            )
            st.session_state['analysis_depth'] = analysis_depth
            
            # Multi-Agent Options
            if "Multi-Agent" in analysis_depth:
                st.subheader("🤖 Multi-Agent Options")
                enable_security_agent = st.checkbox("🛡️ Security Intelligence Agent", value=True, help="Advanced security analysis with threat intelligence")
                enable_performance_agent = st.checkbox("📊 Performance Optimization Agent", value=True, help="Resource utilization and cost optimization")
                enable_compliance_agent = st.checkbox("📋 Compliance Orchestration Agent", value=True, help="Multi-framework compliance validation")
                
                st.session_state['multi_agent_config'] = {
                    'security': enable_security_agent,
                    'performance': enable_performance_agent,
                    'compliance': enable_compliance_agent
                }
                
                if enable_security_agent or enable_performance_agent or enable_compliance_agent:
                    st.info("🚀 Multi-agent analysis provides deeper insights through specialized AI agents working together")
            
            # Test Connection
            if st.button("🔍 Test AWS Connection", key="test_aws_connection"):
                self._test_aws_connection()
    
    def _render_main_content(self):
        """Render main content area"""
        # Header
        st.markdown("""
        <div class="main-header">
            <h1>🚀 AgentK8s - EKS Operations Review</h1>
            <p>Comprehensive EKS cluster analysis with AI-powered insights</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Check if configuration is complete
        if not self._is_configured():
            st.warning("⚠️ Please configure AWS credentials and cluster name in the sidebar")
            return
        
        # Main action button
        if st.button("🚀 Generate Analysis Report", type="primary", use_container_width=True, key="main_analysis_btn"):
            self._run_analysis()
        
        # Tabs for different views
        self._render_tabs()
    
    def _render_tabs(self):
        """Render analysis tabs - enhanced for multi-agent"""
        # Debug: Show session state
        if 'analysis_results' in st.session_state:
            st.info(f"📋 Analysis results available: {st.session_state['analysis_results'].keys()}")
        
        analysis_type = st.session_state.get('analysis_results', {}).get('analysis_type', 'traditional')
        
        if analysis_type == 'multi_agent':
            # Multi-agent tabs
            tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
                "📊 Executive Summary",
                "🤖 Multi-Agent Insights",
                "🛡️ Security Intelligence", 
                "📊 Performance Optimization",
                "📋 Compliance Orchestration",
                "🔧 Unified Recommendations",
                "📄 Reports",
                "🔍 Traditional View"
            ])
            
            with tab1:
                self._render_executive_summary()
            
            with tab2:
                self._render_multi_agent_insights()
            
            with tab3:
                self._render_security_intelligence()
            
            with tab4:
                self._render_performance_optimization()
            
            with tab5:
                self._render_compliance_orchestration()
            
            with tab6:
                self._render_unified_recommendations()
            
            with tab7:
                self._render_multi_agent_reports()
            
            with tab8:
                self._render_traditional_tabs()
        else:
            # Traditional tabs - always show these when not multi-agent
            self._render_traditional_tabs()
    
    def _render_multi_agent_reports(self):
        """Render multi-agent reports tab"""
        st.subheader("📄 Multi-Agent Reports")
        
        if 'analysis_results' not in st.session_state or 'multi_agent_results' not in st.session_state['analysis_results']:
            st.info("Run multi-agent analysis first to generate reports")
            return
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📄 Generate Multi-Agent PDF Report", use_container_width=True, key="multi_agent_pdf_btn"):
                self._generate_multi_agent_pdf_report()
        
        with col2:
            if st.button("📊 Download Multi-Agent JSON", use_container_width=True, key="multi_agent_json_btn"):
                self._generate_multi_agent_json_report()
    
    def _generate_multi_agent_pdf_report(self):
        """Generate comprehensive multi-agent PDF report"""
        try:
            with st.spinner("📄 Generating comprehensive multi-agent PDF report..."):
                from utils.pdf_generator import PDFGenerator
                
                pdf_generator = PDFGenerator()
                
                # Use multi-agent results for PDF generation
                multi_agent_results = st.session_state['analysis_results']['multi_agent_results']
                
                # Convert multi-agent results to format expected by PDF generator
                pdf_data = {
                    'health_analysis': {
                        'cluster_info': {
                            'name': multi_agent_results.get('cluster_name'),
                            'status': 'ACTIVE',  # Placeholder
                            'version': 'Unknown'  # Would get from agent results
                        }
                    },
                    'security_analysis': multi_agent_results.get('agent_results', {}).get('security', {}),
                    'multi_agent_insights': multi_agent_results.get('cross_agent_insights', {}),
                    'executive_summary': multi_agent_results.get('executive_summary', {}),
                    'unified_recommendations': multi_agent_results.get('unified_recommendations', [])
                }
                
                pdf_bytes = pdf_generator.generate_report(
                    pdf_data,
                    st.session_state['cluster_name']
                )
                
                # Create download button
                st.download_button(
                    label="📄 Download Multi-Agent PDF Report",
                    data=pdf_bytes,
                    file_name=f"multi_agent_eks_analysis_{st.session_state['cluster_name']}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                    key="download_multi_agent_pdf"
                )
                
                st.success("✅ Multi-agent PDF report generated successfully!")
                
        except Exception as e:
            st.error(f"❌ Multi-agent PDF generation failed: {str(e)}")
    
    def _generate_multi_agent_json_report(self):
        """Generate multi-agent JSON report"""
        try:
            multi_agent_results = st.session_state['analysis_results']['multi_agent_results']
            json_data = json.dumps(multi_agent_results, indent=2, default=str)
            
            st.download_button(
                label="📊 Download Multi-Agent JSON Data",
                data=json_data,
                file_name=f"multi_agent_eks_analysis_{st.session_state['cluster_name']}_{datetime.now().strftime('%Y%m%d_%H%M')}.json",
                mime="application/json",
                use_container_width=True,
                key="download_multi_agent_json"
            )
            
            st.success("✅ Multi-agent JSON report generated successfully!")
            
        except Exception as e:
            st.error(f"❌ Multi-agent JSON generation failed: {str(e)}")
        else:
            # Traditional tabs
            self._render_traditional_tabs()
    
    def _render_traditional_tabs(self):
        """Render traditional analysis tabs"""
        tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
            "📊 Dashboard",
            "🔍 Cluster Analysis", 
            "🛡️ Security Analysis",
            "📋 Compliance",
            "🔧 Recommendations",
            "📄 Reports"
        ])
        
        with tab1:
            self._render_dashboard()
        
        with tab2:
            self._render_cluster_analysis()
        
        with tab3:
            self._render_security_analysis()
        
        with tab4:
            self._render_compliance()
        
        with tab5:
            self._render_recommendations()
        
        with tab6:
            self._render_reports()
    
    def _render_executive_summary(self):
        """Render executive summary for multi-agent analysis"""
        st.subheader("📊 Executive Summary")
        
        if 'analysis_results' not in st.session_state or 'multi_agent_results' not in st.session_state['analysis_results']:
            st.info("Run multi-agent analysis to see executive summary")
            return
        
        multi_agent_results = st.session_state['analysis_results']['multi_agent_results']
        executive_summary = multi_agent_results.get('executive_summary', {})
        
        # Key metrics
        st.subheader("🎯 Key Metrics")
        key_metrics = executive_summary.get('key_metrics', {})
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            security_posture = key_metrics.get('security_posture', 'UNKNOWN')
            st.metric("Security Posture", security_posture)
        
        with col2:
            performance_efficiency = key_metrics.get('performance_efficiency', 'UNKNOWN')
            st.metric("Performance Efficiency", performance_efficiency)
        
        with col3:
            compliance_status = key_metrics.get('compliance_status', 'UNKNOWN')
            st.metric("Compliance Status", compliance_status)
        
        with col4:
            overall_risk = key_metrics.get('overall_risk', 'UNKNOWN')
            st.metric("Overall Risk", overall_risk)
        
        # Overall health
        overall_health = executive_summary.get('overall_health', 'UNKNOWN')
        if overall_health == 'EXCELLENT':
            st.success(f"🎉 Overall Cluster Health: {overall_health}")
        elif overall_health == 'GOOD':
            st.info(f"✅ Overall Cluster Health: {overall_health}")
        elif overall_health == 'FAIR':
            st.warning(f"⚠️ Overall Cluster Health: {overall_health}")
        else:
            st.error(f"❌ Overall Cluster Health: {overall_health}")
        
        # Critical issues
        critical_issues = executive_summary.get('critical_issues', [])
        if critical_issues:
            st.subheader("🚨 Critical Issues")
            for issue in critical_issues[:5]:
                st.error(f"• {issue}")
        
        # Analysis coverage
        coverage = executive_summary.get('analysis_coverage', {})
        st.subheader("📈 Analysis Coverage")
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Agents Executed", coverage.get('agents_executed', 0))
        with col2:
            st.metric("Security Checks", coverage.get('security_checks', 0))
        with col3:
            st.metric("Performance Metrics", coverage.get('performance_metrics', 0))
        with col4:
            st.metric("Compliance Frameworks", coverage.get('compliance_frameworks', 0))
    
    def _render_multi_agent_insights(self):
        """Render multi-agent cross-correlation insights"""
        st.subheader("🤖 Multi-Agent Intelligence Insights")
        
        if 'analysis_results' not in st.session_state or 'multi_agent_results' not in st.session_state['analysis_results']:
            st.info("Run multi-agent analysis to see cross-agent insights")
            return
        
        multi_agent_results = st.session_state['analysis_results']['multi_agent_results']
        insights = multi_agent_results.get('cross_agent_insights', {})
        
        # Security-Performance Correlation
        st.subheader("🔗 Security-Performance Correlation")
        sec_perf_corr = insights.get('security_performance_correlation', {})
        
        if sec_perf_corr:
            correlation_type = sec_perf_corr.get('correlation_type', 'UNKNOWN')
            insight = sec_perf_corr.get('insight', 'No insight available')
            
            if correlation_type == 'OPTIMAL':
                st.success(f"✅ {insight}")
            elif correlation_type in ['SECURITY_FOCUSED', 'PERFORMANCE_FOCUSED']:
                st.warning(f"⚠️ {insight}")
            else:
                st.error(f"❌ {insight}")
            
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Security Score", f"{sec_perf_corr.get('security_score', 0):.1f}%")
            with col2:
                st.metric("Efficiency Score", f"{sec_perf_corr.get('efficiency_score', 0):.1f}%")
        
        # Compliance-Security Gap Analysis
        st.subheader("📋 Compliance-Security Gap Analysis")
        comp_sec_gaps = insights.get('compliance_security_gaps', {})
        
        if comp_sec_gaps:
            gap_analysis = comp_sec_gaps.get('gap_analysis', {})
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Compliance Rate", f"{gap_analysis.get('compliance_rate', 0):.1f}%")
            with col2:
                st.metric("Security Gaps", gap_analysis.get('security_gaps', 0))
            with col3:
                st.metric("Critical Gaps", gap_analysis.get('critical_gaps', 0))
            
            primary_gaps = gap_analysis.get('primary_gaps', [])
            if primary_gaps:
                st.write("**Primary Security Gaps:**")
                for gap in primary_gaps:
                    st.write(f"• {gap}")
        
        # Risk Assessment
        st.subheader("⚠️ Overall Risk Assessment")
        risk_assessment = insights.get('risk_assessment', {})
        
        if risk_assessment:
            risk_level = risk_assessment.get('risk_level', 'UNKNOWN')
            risk_score = risk_assessment.get('overall_risk_score', 0)
            
            if risk_level == 'CRITICAL':
                st.error(f"🚨 Risk Level: {risk_level} (Score: {risk_score}/100)")
            elif risk_level == 'HIGH':
                st.warning(f"⚠️ Risk Level: {risk_level} (Score: {risk_score}/100)")
            elif risk_level == 'MEDIUM':
                st.info(f"ℹ️ Risk Level: {risk_level} (Score: {risk_score}/100)")
            else:
                st.success(f"✅ Risk Level: {risk_level} (Score: {risk_score}/100)")
            
            risk_factors = risk_assessment.get('primary_risk_factors', [])
            if risk_factors:
                st.write("**Primary Risk Factors:**")
                for factor in risk_factors:
                    st.write(f"• {factor}")
    
    def _render_security_intelligence(self):
        """Render security intelligence agent results"""
        st.subheader("🛡️ Security Intelligence Agent")
        
        if 'analysis_results' not in st.session_state:
            st.info("Run analysis to see security intelligence")
            return
        
        # Get security results from multi-agent or traditional analysis
        if 'multi_agent_results' in st.session_state['analysis_results']:
            agent_results = st.session_state['analysis_results']['multi_agent_results'].get('agent_results', {})
            security_results = agent_results.get('security', {})
        else:
            security_results = st.session_state['analysis_results'].get('security_analysis', {})
        
        if not security_results:
            st.warning("No security analysis available")
            return
        
        # Security posture
        security_posture = security_results.get('security_posture', {})
        if security_posture:
            st.subheader("🎯 Security Posture Assessment")
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Posture Level", security_posture.get('posture_level', 'UNKNOWN'))
            with col2:
                st.metric("Weighted Score", f"{security_posture.get('weighted_score', 0):.1f}%")
            with col3:
                st.metric("Critical Issues", security_posture.get('critical_issues', 0))
        
        # Threat intelligence
        threat_intel = security_results.get('threat_intelligence', {})
        if threat_intel:
            st.subheader("🔍 Threat Intelligence")
            
            threat_level = threat_intel.get('threat_level', 'UNKNOWN')
            if threat_level == 'CRITICAL':
                st.error(f"🚨 Threat Level: {threat_level}")
            elif threat_level == 'HIGH':
                st.warning(f"⚠️ Threat Level: {threat_level}")
            else:
                st.success(f"✅ Threat Level: {threat_level}")
            
            col1, col2 = st.columns(2)
            with col1:
                security_hub_findings = threat_intel.get('security_hub_findings', 0)
                self._safe_metric("Security Hub Findings", security_hub_findings)
            with col2:
                guardduty_findings = threat_intel.get('guardduty_findings', 0)
                self._safe_metric("GuardDuty Findings", guardduty_findings)
        
        # Compliance mapping
        compliance_mapping = security_results.get('compliance_mapping', {})
        if compliance_mapping:
            st.subheader("📋 Compliance Framework Mapping")
            
            for framework, data in compliance_mapping.items():
                with st.expander(f"{framework} - {data.get('compliance_level', 'UNKNOWN')}"):
                    col1, col2 = st.columns(2)
                    with col1:
                        compliance_score = data.get('compliance_score', 0)
                        if isinstance(compliance_score, (int, float)):
                            self._safe_metric("Compliance Score", f"{compliance_score:.1f}%")
                        else:
                            self._safe_metric("Compliance Score", "N/A")
                    with col2:
                        applicable_checks = data.get('applicable_checks', [])
                        self._safe_metric("Applicable Checks", applicable_checks)
    
    def _render_performance_optimization(self):
        """Render performance optimization agent results"""
        st.subheader("📊 Performance Optimization Agent")
        
        if 'analysis_results' not in st.session_state:
            st.info("Run multi-agent analysis to see performance optimization")
            return
        
        # Get performance results
        if 'multi_agent_results' in st.session_state['analysis_results']:
            agent_results = st.session_state['analysis_results']['multi_agent_results'].get('agent_results', {})
            performance_results = agent_results.get('performance', {})
        else:
            st.info("Performance optimization requires multi-agent analysis")
            return
        
        if not performance_results:
            st.warning("No performance analysis available")
            return
        
        # Resource utilization
        resource_util = performance_results.get('resource_utilization', {})
        if resource_util:
            st.subheader("📈 Resource Utilization Analysis")
            
            efficiency = resource_util.get('resource_efficiency', {})
            if efficiency:
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Efficiency Level", efficiency.get('efficiency_level', 'UNKNOWN'))
                with col2:
                    st.metric("Efficiency Score", f"{efficiency.get('efficiency_score', 0):.1f}%")
                with col3:
                    st.metric("CPU Utilization", f"{efficiency.get('average_cpu_utilization', 0):.1f}%")
        
        # Cost optimization
        cost_optimization = performance_results.get('cost_optimization', {})
        if cost_optimization:
            st.subheader("💰 Cost Optimization Opportunities")
            
            spot_opportunities = cost_optimization.get('spot_instance_opportunities', [])
            if spot_opportunities:
                st.write(f"**Spot Instance Opportunities:** {len(spot_opportunities)} node groups")
                for opp in spot_opportunities[:3]:
                    st.write(f"• {opp.get('node_group', 'Unknown')}: {opp.get('potential_savings', 'Unknown')} savings")
        
        # Performance recommendations
        perf_recs = performance_results.get('performance_recommendations', [])
        if perf_recs:
            st.subheader("🔧 Performance Recommendations")
            
            for rec in perf_recs[:5]:
                priority = rec.get('priority', 'MEDIUM')
                if priority == 'HIGH':
                    st.error(f"🔴 **{rec.get('title', 'Unknown')}** - {rec.get('description', '')}")
                elif priority == 'MEDIUM':
                    st.warning(f"🟡 **{rec.get('title', 'Unknown')}** - {rec.get('description', '')}")
                else:
                    st.info(f"🔵 **{rec.get('title', 'Unknown')}** - {rec.get('description', '')}")
    
    def _render_compliance_orchestration(self):
        """Render compliance orchestration agent results"""
        st.subheader("📋 Compliance Orchestration Agent")
        
        if 'analysis_results' not in st.session_state:
            st.info("Run multi-agent analysis to see compliance orchestration")
            return
        
        # Get compliance results
        if 'multi_agent_results' in st.session_state['analysis_results']:
            agent_results = st.session_state['analysis_results']['multi_agent_results'].get('agent_results', {})
            compliance_results = agent_results.get('compliance', {})
        else:
            st.info("Compliance orchestration requires multi-agent analysis")
            return
        
        if not compliance_results:
            st.warning("No compliance analysis available")
            return
        
        # Overall assessment
        overall_assessment = compliance_results.get('overall_assessment', {})
        if overall_assessment:
            st.subheader("🎯 Overall Compliance Assessment")
            
            col1, col2, col3 = st.columns(3)
            with col1:
                status = overall_assessment.get('status', 'UNKNOWN')
                if status == 'COMPLIANT':
                    st.success(f"✅ Status: {status}")
                elif status == 'PARTIALLY_COMPLIANT':
                    st.warning(f"⚠️ Status: {status}")
                else:
                    st.error(f"❌ Status: {status}")
            
            with col2:
                st.metric("Average Score", f"{overall_assessment.get('average_score', 0):.1f}%")
            
            with col3:
                st.metric("Compliant Frameworks", f"{overall_assessment.get('compliant_frameworks', 0)}/{overall_assessment.get('total_frameworks', 0)}")
        
        # Framework details
        compliance_summary = compliance_results.get('compliance_summary', {})
        if compliance_summary:
            st.subheader("📊 Framework Compliance Details")
            
            for framework, summary in compliance_summary.items():
                with st.expander(f"{framework} - {summary.get('status', 'UNKNOWN')}"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Compliance Score", f"{summary.get('compliance_score', 0):.1f}%")
                    with col2:
                        st.metric("Critical Gaps", summary.get('critical_gaps', 0))
        
        # Remediation priorities
        remediation_priorities = compliance_results.get('remediation_priorities', [])
        if remediation_priorities:
            st.subheader("🔧 Remediation Priorities")
            
            for priority in remediation_priorities[:5]:
                priority_level = priority.get('priority', 'MEDIUM')
                if priority_level == 'CRITICAL':
                    st.error(f"🚨 **{priority.get('control_name', 'Unknown')}** - Affects {len(priority.get('affected_frameworks', []))} frameworks")
                elif priority_level == 'HIGH':
                    st.warning(f"⚠️ **{priority.get('control_name', 'Unknown')}** - Affects {len(priority.get('affected_frameworks', []))} frameworks")
                else:
                    st.info(f"ℹ️ **{priority.get('control_name', 'Unknown')}** - Affects {len(priority.get('affected_frameworks', []))} frameworks")
    
    def _render_unified_recommendations(self):
        """Render unified recommendations from all agents"""
        st.subheader("🔧 Unified Recommendations")
        
        if 'analysis_results' not in st.session_state:
            st.info("Run analysis to see recommendations")
            return
        
        # Get unified recommendations
        if 'multi_agent_results' in st.session_state['analysis_results']:
            unified_recs = st.session_state['analysis_results']['multi_agent_results'].get('unified_recommendations', [])
        else:
            # Fall back to traditional recommendations
            security_analysis = st.session_state['analysis_results'].get('security_analysis', {})
            unified_recs = security_analysis.get('recommendations', [])
        
        if not unified_recs:
            st.success("🎉 No critical recommendations - your cluster configuration looks good!")
            return
        
        # Group recommendations by priority
        critical_recs = [r for r in unified_recs if r.get('priority') == 'CRITICAL']
        high_recs = [r for r in unified_recs if r.get('priority') == 'HIGH']
        medium_recs = [r for r in unified_recs if r.get('priority') == 'MEDIUM']
        
        if critical_recs:
            st.subheader("🚨 Critical Priority")
            for rec in critical_recs:
                with st.expander(f"🔴 {rec.get('title', 'Unknown')} ({rec.get('source', 'Unknown Agent')})"):
                    st.write(f"**Category:** {rec.get('category', 'Unknown')}")
                    st.write(f"**Description:** {rec.get('description', 'No description available')}")
                    if 'implementation_time' in rec:
                        st.write(f"**Implementation Time:** {rec['implementation_time']}")
                    if 'business_impact' in rec:
                        st.write(f"**Business Impact:** {rec['business_impact']}")
        
        if high_recs:
            st.subheader("⚠️ High Priority")
            for rec in high_recs:
                with st.expander(f"🟡 {rec.get('title', 'Unknown')} ({rec.get('source', 'Unknown Agent')})"):
                    st.write(f"**Category:** {rec.get('category', 'Unknown')}")
                    st.write(f"**Description:** {rec.get('description', 'No description available')}")
                    if 'expected_benefit' in rec:
                        st.write(f"**Expected Benefit:** {rec['expected_benefit']}")
        
        if medium_recs:
            st.subheader("ℹ️ Medium Priority")
            for rec in medium_recs[:5]:  # Show top 5 medium priority
                with st.expander(f"🔵 {rec.get('title', 'Unknown')} ({rec.get('source', 'Unknown Agent')})"):
                    st.write(f"**Category:** {rec.get('category', 'Unknown')}")
                    st.write(f"**Description:** {rec.get('description', 'No description available')}")
    
    def _render_dashboard(self):
        """Render dashboard tab - NO SECURITY SCORE"""
        st.subheader("📊 Cluster Dashboard")
        
        if 'analysis_results' not in st.session_state:
            st.info("Run analysis to see dashboard metrics")
            return
        
        results = st.session_state['analysis_results']
        cluster_info = results.get('health_analysis', {}).get('cluster_info', {})
        
        # Metrics row - NO SECURITY SCORE
        col1, col2, col3 = st.columns(3)
        
        with col1:
            status = cluster_info.get('status', 'Unknown')
            st.metric("Cluster Status", status, delta="Healthy" if status == "ACTIVE" else "Issue")
        
        with col2:
            version = cluster_info.get('version', 'Unknown')
            st.metric("Kubernetes Version", version)
        
        with col3:
            node_count = results.get('health_analysis', {}).get('node_analysis', {}).get('total_nodes', 0)
            st.metric("Total Nodes", node_count)
        
        # Network and addon status
        if 'health_analysis' in results:
            health = results['health_analysis']
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("🌐 Network Status")
                network = health.get('network_analysis', {})
                if 'issues' in network and network['issues']:
                    for issue in network['issues']:
                        st.warning(f"⚠️ {issue}")
                else:
                    st.success("✅ No network issues detected")
            
            with col2:
                st.subheader("🔧 Addon Status")
                addons = health.get('addon_analysis', {})
                if 'issues' in addons and addons['issues']:
                    for issue in addons['issues']:
                        st.error(f"❌ {issue}")
                else:
                    st.success("✅ All addons healthy")
    
    def _render_cluster_analysis(self):
        """Render cluster analysis tab"""
        st.subheader("🔍 Detailed Cluster Analysis")
        
        if 'analysis_results' not in st.session_state:
            st.info("Run analysis to see detailed cluster information")
            return
        
        results = st.session_state['analysis_results']
        health_analysis = results.get('health_analysis', {})
        
        # Cluster Information
        cluster_info = health_analysis.get('cluster_info', {})
        if cluster_info:
            st.subheader("ℹ️ Cluster Information")
            
            info_col1, info_col2 = st.columns(2)
            with info_col1:
                st.write(f"**Name:** {cluster_info.get('name', 'N/A')}")
                st.write(f"**Status:** {cluster_info.get('status', 'N/A')}")
                st.write(f"**Version:** {cluster_info.get('version', 'N/A')}")
            
            with info_col2:
                st.write(f"**Platform Version:** {cluster_info.get('platform_version', 'N/A')}")
                st.write(f"**Endpoint:** {cluster_info.get('endpoint', 'N/A')}")
                if cluster_info.get('created_at'):
                    st.write(f"**Created:** {cluster_info['created_at']}")
        
        # Node Groups
        node_analysis = health_analysis.get('node_analysis', {})
        if node_analysis and 'node_groups' in node_analysis:
            st.subheader("🖥️ Node Groups")
            
            for ng in node_analysis['node_groups']:
                with st.expander(f"Node Group: {ng['name']}"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**Status:** {ng['status']}")
                        st.write(f"**Instance Types:** {', '.join(ng['instance_types'])}")
                    with col2:
                        st.write(f"**Desired Size:** {ng['desired_size']}")
                        st.write(f"**Min/Max Size:** {ng['min_size']}/{ng['max_size']}")
    
    def _render_security_analysis(self):
        """Render security analysis tab - NO SECURITY SCORE"""
        st.subheader("🛡️ Security Analysis")
        
        if 'analysis_results' not in st.session_state:
            st.info("Run analysis to see security assessment")
            return
        
        results = st.session_state['analysis_results']
        security_analysis = results.get('security_analysis', {})
        
        if not security_analysis:
            st.warning("No security analysis available")
            return
        
        # Security Check Summary - NO SCORE
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Passed Checks", security_analysis.get('passed_checks', 0))
        with col2:
            st.metric("Failed Checks", security_analysis.get('failed_checks', 0))
        
        # Security Checks
        checks = security_analysis.get('checks', [])
        if checks:
            st.subheader("🔍 Security Checks")
            
            for check in checks:
                status_icon = "✅" if check['status'] == 'PASS' else "❌" if check['status'] == 'FAIL' else "⚠️"
                
                with st.expander(f"{status_icon} {check['title']}"):
                    st.write(f"**Status:** {check['status']}")
                    st.write(f"**Description:** {check['description']}")
                    if 'severity' in check:
                        st.write(f"**Severity:** {check['severity']}")
    
    def _render_compliance(self):
        """Render compliance tab"""
        st.subheader("📋 Compliance Assessment")
        st.info("Compliance assessment will be available in the multi-agent version")
    
    def _render_recommendations(self):
        """Render recommendations tab"""
        st.subheader("🔧 Recommendations")
        
        if 'analysis_results' not in st.session_state:
            st.info("Run analysis to see recommendations")
            return
        
        results = st.session_state['analysis_results']
        security_analysis = results.get('security_analysis', {})
        recommendations = security_analysis.get('recommendations', [])
        
        if not recommendations:
            st.success("🎉 No recommendations - your cluster looks good!")
            return
        
        for i, rec in enumerate(recommendations):
            with st.expander(f"🔧 {rec['title']} (Priority: {rec['priority']})"):
                st.write(f"**Description:** {rec['description']}")
                if 'aws_cli' in rec:
                    st.code(rec['aws_cli'], language='bash')
    
    def _render_reports(self):
        """Render reports tab with WORKING PDF downloads"""
        st.subheader("📄 Generate Reports")
        
        if 'analysis_results' not in st.session_state:
            st.info("Run analysis first to generate reports")
            return
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📄 Generate PDF Report", use_container_width=True, key="traditional_pdf_report_btn"):
                self._generate_pdf_report()
        
        with col2:
            if st.button("📊 Download JSON Data", use_container_width=True, key="traditional_json_report_btn"):
                self._generate_json_report()
    
    def _is_configured(self) -> bool:
        """Check if app is properly configured"""
        return (
            st.session_state.get('cluster_name') and
            st.session_state.get('aws_region') and
            (st.session_state.get('role_arn') or 
             (st.session_state.get('aws_access_key') and st.session_state.get('aws_secret_key')))
        )
    
    def _test_aws_connection(self):
        """Test AWS connection"""
        try:
            from core.aws_client import AWSClientManager
            
            aws_client = AWSClientManager(
                region=st.session_state.get('aws_region'),
                role_arn=st.session_state.get('role_arn')
            )
            
            clients = aws_client.get_clients()
            account_id = aws_client.get_account_id()
            
            st.success(f"✅ AWS connection successful! Account: {account_id}")
            
        except Exception as e:
            st.error(f"❌ AWS connection failed: {str(e)}")
    
    def _run_analysis(self):
        """Run comprehensive analysis - now with multi-agent support"""
        analysis_depth = st.session_state.get('analysis_depth', 'Comprehensive (5 min)')
        
        if "Multi-Agent" in analysis_depth:
            self._run_multi_agent_analysis()
        else:
            self._run_traditional_analysis()
    
    def _run_multi_agent_analysis(self):
        """Run multi-agent analysis"""
        with st.spinner("🤖 Running multi-agent analysis..."):
            try:
                # Import multi-agent manager
                import sys
                import os
                sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
                
                from agents.multi_agent_manager import MultiAgentManager
                
                # Initialize multi-agent manager
                config = {
                    'region': st.session_state['aws_region']
                }
                
                manager = MultiAgentManager(config)
                
                # Run comprehensive analysis
                import asyncio
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                comprehensive_results = loop.run_until_complete(
                    manager.run_comprehensive_analysis(
                        cluster_name=st.session_state['cluster_name'],
                        region=st.session_state['aws_region'],
                        role_arn=st.session_state.get('role_arn')
                    )
                )
                
                # Store results
                st.session_state['analysis_results'] = {
                    'multi_agent_results': comprehensive_results,
                    'analysis_type': 'multi_agent',
                    'timestamp': datetime.now().isoformat()
                }
                
                # Also store individual agent results for compatibility
                agent_results = comprehensive_results.get('agent_results', {})
                if 'security' in agent_results:
                    st.session_state['analysis_results']['security_analysis'] = agent_results['security']
                if 'performance' in agent_results:
                    st.session_state['analysis_results']['performance_analysis'] = agent_results['performance']
                if 'compliance' in agent_results:
                    st.session_state['analysis_results']['compliance_analysis'] = agent_results['compliance']
                
                st.success("✅ Multi-agent analysis completed successfully!")
                st.info(f"🤖 Analysis completed in {comprehensive_results.get('analysis_duration_seconds', 0):.1f} seconds using {len(comprehensive_results.get('agents_used', []))} specialized agents")
                st.rerun()
                
            except Exception as e:
                st.error(f"❌ Multi-agent analysis failed: {str(e)}")
                st.info("Falling back to traditional analysis...")
                self._run_traditional_analysis()
    
    def _run_traditional_analysis(self):
        """Run traditional single-agent analysis"""
        with st.spinner("🔄 Running comprehensive analysis..."):
            try:
                # Debug info
                st.info(f"🔍 Starting analysis for cluster: {st.session_state['cluster_name']} in region: {st.session_state['aws_region']}")
                
                # Initialize analyzers
                health_analyzer = HealthAnalyzer(
                    cluster_name=st.session_state['cluster_name'],
                    region=st.session_state['aws_region'],
                    role_arn=st.session_state.get('role_arn')
                )
                
                st.info("📊 Running health analysis...")
                health_results = health_analyzer.analyze_comprehensive_health()
                st.info(f"✅ Health analysis complete. Found {len(health_results)} components.")
                
                security_analyzer = SecurityAnalyzer(
                    cluster_name=st.session_state['cluster_name'],
                    region=st.session_state['aws_region'],
                    role_arn=st.session_state.get('role_arn')
                )
                
                st.info("🛡️ Running security analysis...")
                security_results = security_analyzer.run_security_checks()
                st.info(f"✅ Security analysis complete. Found {security_results.get('total_checks', 0)} checks.")
                
                # Store results with debug info
                analysis_results = {
                    'health_analysis': health_results,
                    'security_analysis': security_results,
                    'analysis_type': 'traditional',
                    'timestamp': datetime.now().isoformat(),
                    'cluster_name': st.session_state['cluster_name'],
                    'region': st.session_state['aws_region']
                }
                
                st.session_state['analysis_results'] = analysis_results
                
                # Debug: Show what was stored
                st.success("✅ Analysis completed successfully!")
                st.info(f"📋 Results stored: {len(analysis_results)} sections")
                
                # Force UI refresh
                st.rerun()
                
            except Exception as e:
                st.error(f"❌ Analysis failed: {str(e)}")
                st.error(f"Error details: {type(e).__name__}")
                import traceback
                st.code(traceback.format_exc())
    
    def _generate_pdf_report(self):
        """Generate and download PDF report - WORKING VERSION"""
        try:
            with st.spinner("📄 Generating PDF report..."):
                pdf_generator = PDFGenerator()
                pdf_bytes = pdf_generator.generate_report(
                    st.session_state['analysis_results'],
                    st.session_state['cluster_name']
                )
                
                # Create download button
                st.download_button(
                    label="📄 Download PDF Report",
                    data=pdf_bytes,
                    file_name=f"eks_analysis_{st.session_state['cluster_name']}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
                
                st.success("✅ PDF report generated successfully!")
                
        except Exception as e:
            st.error(f"❌ PDF generation failed: {str(e)}")
            st.write("Error details:", str(e))
    
    def _generate_json_report(self):
        """Generate and download JSON report - WORKING VERSION"""
        try:
            json_data = json.dumps(st.session_state['analysis_results'], indent=2, default=str)
            
            st.download_button(
                label="📊 Download JSON Data",
                data=json_data,
                file_name=f"eks_analysis_{st.session_state['cluster_name']}_{datetime.now().strftime('%Y%m%d_%H%M')}.json",
                mime="application/json",
                use_container_width=True
            )
            
            st.success("✅ JSON report generated successfully!")
            
        except Exception as e:
            st.error(f"❌ JSON generation failed: {str(e)}")
