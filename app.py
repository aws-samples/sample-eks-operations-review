import time
import uuid
import os
import re
from datetime import datetime
import json
import logging

# Specific imports to avoid broad library imports
import streamlit as st
import boto3
import pandas as pd
from src.analyzers.best_practices_analyzer import EKSBestPracticesAnalyzer
from src.analyzers.hardeneks_analyzer import HardenEKSAnalyzer
from src.analyzers.cluster_analyzer import ClusterAnalyzer
from src.utils.kubernetes_client import KubernetesClient
from src.monitoring.cluster_monitor import ClusterMonitor
from src.remediation.remediation_manager import RemediationManager
from src.compliance.compliance_manager import ComplianceManager
from src.comparison.cluster_comparison import ClusterComparison
from src.security_hub.security_hub_integration import SecurityHubIntegration
from src.history.history_manager import HistoryManager
from src.utils.aws_utils import AWSUtils
from src.utils.report_generator import ReportGenerator
from src.utils.csv_generator import CSVGenerator
from src.config.default_values import DEFAULT_VALUES, DEFAULT_CLUSTER_NAME
from src.config.constants import PILLARS

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Page config
st.set_page_config(page_title="EKS Operational Review Agent", layout="wide")

class EKSOperationalReviewAgent:
    def _sanitize_log_input(self, text: str) -> str:
        """Sanitize input for logging to prevent log injection."""
        if not isinstance(text, str):
            return str(text)
        # Remove newlines and control characters
        sanitized = re.sub(r'[\r\n\t\x00-\x1f\x7f-\x9f]', '', text)
        return sanitized[:200]  # Limit length
    
    def __init__(self):
        self.aws_utils = None
        self.best_practices_analyzer = EKSBestPracticesAnalyzer()
        self.hardeneks_analyzer = HardenEKSAnalyzer()
        self.cluster_analyzer = None
        self.kubernetes_client = None
        self.report_generator = ReportGenerator()
        self.bedrock_agent = None
        self.cluster_monitor = None
        self.remediation_manager = None
        self.compliance_manager = ComplianceManager()
        self.cluster_comparison = ClusterComparison()
        self.history_manager = HistoryManager()
        self.security_hub = None
        self.initialized = False

    def initialize_aws(self, aws_access_key, aws_secret_key, region, cluster_name, knowledge_base_id):
        try:
            self.aws_utils = AWSUtils(aws_access_key, aws_secret_key, region, cluster_name)
            
            # Initialize the Kubernetes client with admin permissions
            self.kubernetes_client = KubernetesClient(cluster_name, region)
            
            # Initialize the cluster analyzer
            self.cluster_analyzer = ClusterAnalyzer(cluster_name, region)
            
            # Initialize the Bedrock agent with knowledge base
            self.bedrock_agent = BedrockAgent(
                aws_access_key=aws_access_key,
                aws_secret_key=aws_secret_key,
                region=region,
                knowledge_base_id=knowledge_base_id
            )
            
            # Initialize cluster monitor
            self.cluster_monitor = ClusterMonitor(self.aws_utils)
            
            # Initialize remediation manager
            self.remediation_manager = RemediationManager(
                aws_access_key=aws_access_key,
                aws_secret_key=aws_secret_key,
                region=region
            )
            
            # Initialize Security Hub integration
            self.security_hub = SecurityHubIntegration(
                aws_access_key=aws_access_key,
                aws_secret_key=aws_secret_key,
                region=region
            )
            
            # Initialize Kubernetes client with admin permissions
            try:
                if self.kubernetes_client.initialize():
                    logger.info("Kubernetes client initialized with admin permissions")
                else:
                    logger.warning("Kubernetes client initialization failed")
            except Exception as k8s_error:
                logger.warning(f"Kubernetes client initialization error: {k8s_error}")
            
            # Initialize cluster analyzer
            try:
                if self.cluster_analyzer.initialize():
                    logger.info("Cluster analyzer initialized successfully")
                else:
                    logger.warning("Cluster analyzer initialization failed")
            except Exception as analyzer_error:
                logger.warning(f"Cluster analyzer initialization error: {analyzer_error}")
            
            self.initialized = True
            return True
        except Exception as e:
            logger.warning(f"Failed to initialize AWS services: {self._sanitize_log_input(str(e))}")
            return False

    def generate_review(self, inputs):
        if not self.initialized:
            raise Exception("AWS services not initialized")

        try:
            # Get cluster details
            cluster_details = self.aws_utils.get_cluster_details()
            
            # Run HardenEKS analysis
            hardeneks_results = self.hardeneks_analyzer.analyze_cluster(cluster_details, inputs)
            
            # Analyze best practices
            analysis_results = self.best_practices_analyzer.analyze_cluster(cluster_details, inputs)
            
            # Merge results
            analysis_results['hardeneks'] = hardeneks_results
            analysis_results['hardeneks_score'] = hardeneks_results['hardeneks_score']
            analysis_results['high_priority'].extend(hardeneks_results['high_priority'])
            analysis_results['medium_priority'].extend(hardeneks_results['medium_priority'])
            analysis_results['low_priority'].extend(hardeneks_results['low_priority'])
            
            # Save results to history
            self.history_manager.save_scan_results(
                cluster_name=self.aws_utils.cluster_name,
                analysis_results=analysis_results
            )
            
            # Send findings to Security Hub if enabled
            if self.security_hub and self.security_hub.is_security_hub_enabled():
                self.security_hub.send_findings(
                    cluster_name=self.aws_utils.cluster_name,
                    analysis_results=analysis_results
                )
            
            # Get KB insights for each pillar
            kb_insights = {}
            for pillar, fields in inputs.items():
                kb_insights[pillar] = {}
                for field, value in fields.items():
                    kb_response = self.bedrock_agent.analyze_pillar_field(pillar, field, value)
                    kb_insights[pillar][field] = kb_response
            
            # Generate report
            report = self.report_generator.generate_report(
                inputs=inputs,
                cluster_details=cluster_details,
                analysis_results=analysis_results,
                kb_insights=kb_insights
            )
            
            return report
        except Exception as e:
            logger.warning(f"Failed to generate review: {self._sanitize_log_input(str(e))}")
            raise

class BedrockAgent:
    def _sanitize_log_input(self, text: str) -> str:
        """Sanitize input for logging to prevent log injection."""
        if not isinstance(text, str):
            return str(text)
        # Remove newlines and control characters
        sanitized = re.sub(r'[\r\n\t\x00-\x1f\x7f-\x9f]', '', text)
        return sanitized[:200]  # Limit length
    
    def __init__(self, aws_access_key, aws_secret_key, region, knowledge_base_id):
        try:
            # Initialize Bedrock runtime client
            self.bedrock_runtime = boto3.client(
                service_name='bedrock-runtime',
                region_name=region,
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key
            )
            # Initialize Bedrock agent runtime client
            self.bedrock_agent_runtime = boto3.client(
                service_name='bedrock-agent-runtime',
                region_name=region,
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key
            )
            self.knowledge_base_id = knowledge_base_id
            self.region = region
            
        except Exception as e:
            logger.warning(f"Failed to initialize Bedrock agent: {self._sanitize_log_input(str(e))}")
            raise

    def get_knowledge_base_response(self, question, context=None):
        try:
            # Query the knowledge base using retrieve
            response = self.bedrock_agent_runtime.retrieve(
                knowledgeBaseId=self.knowledge_base_id,
                retrievalQuery={
                    'text': question
                },
                retrievalConfiguration={
                    'vectorSearchConfiguration': {
                        'numberOfResults': 5
                    }
                }
            )
            
            if 'retrievalResults' in response:
                # Extract and format the response
                retrieved_results = [result.get('content', {}).get('text', '') 
                                  for result in response.get('retrievalResults', [])]
                
                # Use these results to generate a response using Claude
                synthesized_prompt = f"""Based on the following information from the knowledge base:

{' '.join(retrieved_results)}

Question: {question}

Please provide a detailed analysis including:
1. Assessment of the current state
2. Best practices recommendations
3. Potential risks or concerns
4. Improvement suggestions
5. Specific actionable steps"""

                # Call Claude to synthesize the response
                request_body = json.dumps({
                    "prompt": f"\n\nHuman: {synthesized_prompt}\n\nAssistant:",
                    "max_tokens_to_sample": 2000,
                    "temperature": 0.7,
                    "top_p": 0.9,
                })

                claude_response = self.bedrock_runtime.invoke_model(
                    modelId="anthropic.claude-v2",  # Using Claude v2 model
                    contentType="application/json",
                    accept="application/json",
                    body=request_body
                )
                
                response_body = json.loads(claude_response['body'].read())
                return response_body.get('completion', 'No response generated')
            
            return "No relevant information found in knowledge base"
            
        except Exception as e:
            logger.error(f"Failed to query knowledge base: {self._sanitize_log_input(str(e))}")
            return "Error querying knowledge base"

    def analyze_pillar_field(self, pillar, field, value):
        try:
            # Construct context-aware prompt
            prompt = f"""
            For the {pillar} pillar, analyze this {field}:
            
            Current Configuration/Status:
            {value}
            
            Please provide a comprehensive analysis considering:
            1. Current state assessment
            2. Compliance with AWS EKS best practices
            3. Security considerations
            4. Performance implications
            5. Cost optimization opportunities
            6. Specific recommendations for improvement
            7. Risk assessment
            8. Industry standard compliance
            """
            
            # Get response from knowledge base
            kb_response = self.get_knowledge_base_response(prompt)
            
            # Format the response
            formatted_response = f"""
            ### Analysis for {field}
            
            {kb_response}
            
            ---
            """
            
            return formatted_response
            
        except Exception as e:
            logger.error(f"Failed to analyze field: {self._sanitize_log_input(str(e))}")
            return "Error analyzing field"




    def invoke_model(self, prompt):
        try:
            # Prepare the prompt with knowledge base ID
            full_prompt = f"""Using the knowledge base with ID {self.knowledge_base_id}, 
            please answer the following question:

            {prompt}

            Provide a detailed answer based on the information in the knowledge base."""

            # Prepare the request body
            body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 1000,
                "messages": [
                    {
                        "role": "user",
                        "content": full_prompt
                    }
                ],
                "temperature": 0.7
            }
            
            # Invoke the model
            response = self.bedrock_runtime.invoke_model(
                modelId="anthropic.claude-3-sonnet-20240229-v1:0",
                body=json.dumps(body)
            )
            
            # Parse and return the response
            response_body = json.loads(response['body'].read())
            return response_body['messages'][0]['content']
            
        except Exception as e:
            logger.warning(f"Failed to invoke Bedrock model: {self._sanitize_log_input(str(e))}")
            raise

def main():
    st.title("AgentK8s - EKS Operational Review Agent 🤖")

    # Initialize session state
    if 'agent' not in st.session_state:
        st.session_state.agent = EKSOperationalReviewAgent()
        st.session_state.form_inputs = {}
    
    # AWS Configuration sidebar
    with st.sidebar:
        st.header("AWS Configuration")
        with st.form("aws_config"):
            aws_access_key = st.text_input("AWS Access Key", type="password")
            aws_secret_key = st.text_input("AWS Secret Key", type="password")
            aws_region = st.text_input("AWS Region", value="us-east-1")
            cluster_name = st.text_input("EKS Cluster Name", value=DEFAULT_CLUSTER_NAME)
            knowledge_base_id = st.text_input("Knowledge Base ID")
            
            if st.form_submit_button("Initialize"):
                if aws_access_key and aws_secret_key and knowledge_base_id:
                    try:
                        if st.session_state.agent.initialize_aws(
                            aws_access_key, aws_secret_key, aws_region, cluster_name, knowledge_base_id
                        ):
                            st.success("Successfully initialized AWS services and connected to knowledge base!")
                        else:
                            st.error("Failed to initialize AWS services")
                    except Exception as e:
                        st.error(f"Error initializing AWS services: {str(e)}")
                else:
                    st.error("Please provide AWS credentials and Knowledge Base ID")

    # Create tabs for different features
    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
        "Analysis", "Cluster Analysis", "HardenEKS", "Monitoring", "Remediation", "Compliance", "History", "Comparison"
    ])

    with tab1:
        # Main form
        for pillar, data in PILLARS.items():
            st.header(pillar)
            st.text(data["description"])
            
            for field in data["fields"]:
                with st.expander(f"{field}", expanded=True):
                    col1, col2 = st.columns([1, 1])
                    
                    with col1:
                        default_value = DEFAULT_VALUES.get(pillar, {}).get(field, "")
                        value = st.text_area(
                            "Current Configuration/Status",
                            value=default_value,
                            height=200 if len(default_value.split('\n')) > 5 else 100,
                            key=f"{pillar}_{field}"
                        )
                        
                        if pillar not in st.session_state.form_inputs:
                            st.session_state.form_inputs[pillar] = {}
                        st.session_state.form_inputs[pillar][field] = value
                    
                    with col2:
                        if st.session_state.agent and st.session_state.agent.initialized:
                            if st.button(f"Analyze {field}", key=f"analyze_{pillar}_{field}"):
                                with st.spinner(f"Analyzing {field}..."):
                                    analysis = st.session_state.agent.bedrock_agent.analyze_pillar_field(
                                        pillar, field, value
                                    )
                                    st.markdown(analysis)

        # Generate Report button
        if st.button("Generate Report"):
            if not st.session_state.agent.initialized:
                st.error("Please initialize AWS services first")
                return

            with st.spinner("Generating comprehensive review..."):
                try:
                    # Get cluster details
                    cluster_details = st.session_state.agent.aws_utils.get_cluster_details()
                    
                    # Run HardenEKS analysis
                    hardeneks_results = st.session_state.agent.hardeneks_analyzer.analyze_cluster(
                        cluster_details, st.session_state.form_inputs
                    )
                    
                    # Analyze cluster with best practices
                    analysis_results = st.session_state.agent.best_practices_analyzer.analyze_cluster(
                        cluster_details, st.session_state.form_inputs
                    )
                    
                    # Merge results
                    analysis_results['hardeneks'] = hardeneks_results
                    analysis_results['hardeneks_score'] = hardeneks_results['hardeneks_score']
                    analysis_results['high_priority'].extend(hardeneks_results['high_priority'])
                    analysis_results['medium_priority'].extend(hardeneks_results['medium_priority'])
                    analysis_results['low_priority'].extend(hardeneks_results['low_priority'])
                    
                    # Save to history
                    st.session_state.agent.history_manager.save_scan_results(
                        cluster_name=cluster_name,
                        analysis_results=analysis_results
                    )
                    
                    # Generate PDF report
                    report_generator = ReportGenerator()
                    pdf_file = report_generator.generate_report(
                        cluster_details=cluster_details,
                        analysis_results=analysis_results,
                        inputs=st.session_state.form_inputs
                    )
                    
                    # Generate CSV report
                    csv_generator = CSVGenerator()
                    csv_file = csv_generator.generate_csv(
                        analysis_results=analysis_results,
                        cluster_details=cluster_details
                    )
                    
                    if pdf_file:
                        with open(pdf_file, "rb") as file:
                            st.download_button(
                                label="Download PDF Report",
                                data=file,
                                file_name=pdf_file,
                                mime="application/pdf"
                            )
                    
                    if csv_file:
                        with open(csv_file, "rb") as file:
                            st.download_button(
                                label="Download CSV Action Items",
                                data=file,
                                file_name=csv_file,
                                mime="text/csv"
                            )
                    
                    st.success("Report generated successfully!")
                    
                    # Display summary of findings
                    st.subheader("Summary of Findings")
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.error(f"High Priority: {len(analysis_results['high_priority'])}")
                    with col2:
                        st.warning(f"Medium Priority: {len(analysis_results['medium_priority'])}")
                    with col3:
                        st.info(f"Low Priority: {len(analysis_results['low_priority'])}")
                    
                    # Display HardenEKS score
                    st.metric("HardenEKS Score", f"{analysis_results['hardeneks_score']}%")
                    
                    # Display top findings
                    st.subheader("Top Findings")
                    for finding in analysis_results['high_priority'][:5]:  # Show top 5 high priority findings
                        st.error(f"• {finding['title']}: {finding['description']}")
                
                except Exception as e:
                    st.error(f"Error generating report: {e}")
                    logging.error(f"Report generation error: {e}", exc_info=True)

    with tab2:
        st.header("Comprehensive Cluster Analysis")
        if st.session_state.agent.initialized:
            if st.button("Analyze Cluster with Admin Permissions", key="analyze_cluster_admin"):
                if st.session_state.agent.cluster_analyzer and st.session_state.agent.cluster_analyzer.initialized:
                    with st.spinner("Analyzing cluster with admin permissions..."):
                        try:
                            # Run comprehensive cluster analysis
                            analysis_results = st.session_state.agent.cluster_analyzer.analyze_cluster()
                            
                            # Display cluster info
                            st.subheader("Cluster Information")
                            cluster_info = analysis_results.get('cluster_info', {})
                            st.metric("Namespaces", cluster_info.get('namespaces', 0))
                            st.metric("Pods", cluster_info.get('pods', 0))
                            st.metric("Deployments", cluster_info.get('deployments', 0))
                            st.metric("Services", cluster_info.get('services', 0))
                            
                            # Display findings
                            st.subheader("Findings")
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.error(f"High Priority: {len(analysis_results.get('high_priority', []))}")
                            with col2:
                                st.warning(f"Medium Priority: {len(analysis_results.get('medium_priority', []))}")
                            with col3:
                                st.info(f"Low Priority: {len(analysis_results.get('low_priority', []))}")
                            
                            # Display high priority findings
                            st.subheader("High Priority Findings")
                            for finding in analysis_results.get('high_priority', []):
                                with st.expander(f"{finding.get('title', 'Unknown')}"):
                                    st.write(f"**Category:** {finding.get('category', 'Unknown')}")
                                    st.write(f"**Description:** {finding.get('description', 'No description')}")
                                    st.write(f"**Impact:** {finding.get('impact', 'No impact information')}")
                                    
                                    st.write("**Action Items:**")
                                    for item in finding.get('action_items', []):
                                        st.write(f"- {item}")
                                    
                                    if 'affected_resources' in finding:
                                        st.write("**Affected Resources:**")
                                        for resource in finding.get('affected_resources', []):
                                            st.write(f"- {resource}")
                            
                            # Display medium priority findings
                            st.subheader("Medium Priority Findings")
                            for finding in analysis_results.get('medium_priority', []):
                                with st.expander(f"{finding.get('title', 'Unknown')}"):
                                    st.write(f"**Category:** {finding.get('category', 'Unknown')}")
                                    st.write(f"**Description:** {finding.get('description', 'No description')}")
                                    st.write(f"**Impact:** {finding.get('impact', 'No impact information')}")
                                    
                                    st.write("**Action Items:**")
                                    for item in finding.get('action_items', []):
                                        st.write(f"- {item}")
                                    
                                    if 'affected_resources' in finding:
                                        st.write("**Affected Resources:**")
                                        for resource in finding.get('affected_resources', []):
                                            st.write(f"- {resource}")
                            
                            # Generate report
                            if st.button("Generate Cluster Analysis Report", key="generate_cluster_analysis_report"):
                                with st.spinner("Generating report..."):
                                    # Get cluster details
                                    cluster_details = st.session_state.agent.aws_utils.get_cluster_details()
                                    
                                    # Use the agent's report generator
                                    report_generator = st.session_state.agent.report_generator
                                    report_file = report_generator.generate_report(
                                        cluster_details=cluster_details,
                                        analysis_results=analysis_results,
                                        inputs=st.session_state.form_inputs
                                    )
                                    
                                    if report_file:
                                        with open(report_file, "rb") as file:
                                            st.download_button(
                                                label="Download Cluster Analysis Report",
                                                data=file,
                                                file_name=report_file,
                                                mime="application/pdf"
                                            )
                        except Exception as e:
                            st.error(f"Error analyzing cluster: {e}")
                            logger.error(f"Cluster analysis error: {e}", exc_info=True)
                else:
                    st.error("Kubernetes client not initialized. Please check your AWS credentials and cluster configuration.")
        else:
            st.info("Please initialize AWS services first")


    with tab3:
        st.header("HardenEKS Analysis")
        if st.session_state.agent.initialized:
            if st.button("Run HardenEKS Analysis", key="run_hardeneks_analysis"):
                with st.spinner("Running HardenEKS analysis..."):
                    try:
                        # Get cluster details
                        cluster_details = st.session_state.agent.aws_utils.get_cluster_details()
                        
                        # Run HardenEKS analysis
                        hardeneks_results = st.session_state.agent.hardeneks_analyzer.analyze_cluster(
                            cluster_details, st.session_state.form_inputs
                        )
                        
                        # Display HardenEKS score
                        st.metric("HardenEKS Score", f"{hardeneks_results['hardeneks_score']}%")
                        
                        # Display findings
                        st.subheader("Security Findings")
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.error(f"High Priority: {len(hardeneks_results['high_priority'])}")
                        with col2:
                            st.warning(f"Medium Priority: {len(hardeneks_results['medium_priority'])}")
                        with col3:
                            st.info(f"Low Priority: {len(hardeneks_results['low_priority'])}")
                        
                        # Display failed checks
                        st.subheader("Failed Security Checks")
                        for check in hardeneks_results['failed_checks']:
                            st.error(f"• {check['check']}")
                        
                        # Display high priority findings
                        st.subheader("High Priority Findings")
                        for finding in hardeneks_results['high_priority']:
                            with st.expander(f"{finding['title']}"):
                                st.write(f"**Category:** {finding['category']}")
                                st.write(f"**Description:** {finding['description']}")
                                st.write(f"**Impact:** {finding['impact']}")
                                
                                st.write("**Action Items:**")
                                for item in finding['action_items']:
                                    st.write(f"- {item}")
                                
                                if 'reference' in finding:
                                    st.write(f"**Reference:** [{finding['reference']}]({finding['reference']})")
                        
                        # Generate report
                        if st.button("Generate HardenEKS Report", key="generate_hardeneks_report"):
                            with st.spinner("Generating report..."):
                                # Use the original report generator
                                report_generator = st.session_state.agent.report_generator
                                report_file = report_generator.generate_report(
                                    cluster_details=cluster_details,
                                    analysis_results=hardeneks_results,
                                    inputs=st.session_state.form_inputs
                                )
                                
                                if report_file:
                                    with open(report_file, "rb") as file:
                                        st.download_button(
                                            label="Download HardenEKS Report",
                                            data=file,
                                            file_name=report_file,
                                            mime="application/pdf"
                                        )
                    except Exception as e:
                        st.error(f"Error running HardenEKS analysis: {e}")
                        logger.error(f"HardenEKS analysis error: {e}", exc_info=True)
        else:
            st.info("Please initialize AWS services first")
            
    with tab4:
        st.header("Monitoring")
        if st.session_state.agent.initialized:
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Start Monitoring", key="start_monitoring_tab4"):
                    st.session_state.agent.cluster_monitor.start_monitoring(
                        cluster_name=cluster_name,
                        inputs=st.session_state.form_inputs
                    )
                    st.success("Started real-time monitoring")
            with col2:
                if st.button("Stop Monitoring", key="stop_monitoring_tab4"):
                    st.session_state.agent.cluster_monitor.stop_monitoring_cluster()
                    st.success("Stopped monitoring")
            
            # Show monitoring history
            if hasattr(st.session_state.agent.cluster_monitor, 'monitoring_history') and st.session_state.agent.cluster_monitor.monitoring_history:
                st.subheader("Monitoring History")
                history_df = pd.DataFrame(st.session_state.agent.cluster_monitor.monitoring_history)
                st.dataframe(history_df)
                
                # Show trend analysis
                trend = st.session_state.agent.cluster_monitor.get_trend_analysis()
                st.metric("Security Trend", trend['trend'], delta=trend['score_change'])
        else:
            st.info("Please initialize AWS services first")

            
    with tab5:
        st.header("Remediation")
        if st.session_state.agent.initialized:
            # Get cluster details and analysis results
            try:
                cluster_details = st.session_state.agent.aws_utils.get_cluster_details()
                analysis_results = st.session_state.agent.hardeneks_analyzer.analyze_cluster(
                    cluster_details, st.session_state.form_inputs
                )
                
                # Get available remediations
                remediations = st.session_state.agent.remediation_manager.get_available_remediations(
                    analysis_results['failed_checks']
                )
                
                if remediations:
                    st.subheader("Available Remediations")
                    for i, remediation in enumerate(remediations):
                        with st.expander(f"{remediation['name']} - {remediation['check_id']}"):
                            st.write(remediation['description'])
                            st.write(f"Type: {remediation['remediation_type']}")
                            
                            if st.button("Apply Remediation", key=f"remediate_{i}"):
                                result = st.session_state.agent.remediation_manager.apply_remediation(
                                    cluster_name=cluster_name,
                                    template_id=remediation['template_id']
                                )
                                if result['success']:
                                    st.success(result['message'])
                                else:
                                    st.error(result['message'])
                else:
                    st.info("No remediations available for current issues")
            except Exception as e:
                st.error(f"Error loading remediation options: {e}")
        else:
            st.info("Please initialize AWS services first")

    with tab6:
        st.header("Compliance")
        if st.session_state.agent.initialized:
            # Get available frameworks
            frameworks = st.session_state.agent.compliance_manager.get_available_frameworks()
            
            # Select framework
            framework_options = [f"{framework['name']} ({framework['version']})" for framework in frameworks]
            if framework_options:
                selected_framework = st.selectbox(
                    "Select Compliance Framework",
                    options=framework_options
                )
                
                if st.button("Validate Compliance", key="validate_compliance"):
                    # Get selected framework ID
                    selected_index = framework_options.index(selected_framework)
                    framework_id = frameworks[selected_index]['id']
                    
                    # Get cluster details and analysis results
                    cluster_details = st.session_state.agent.aws_utils.get_cluster_details()
                    analysis_results = st.session_state.agent.hardeneks_analyzer.analyze_cluster(
                        cluster_details, st.session_state.form_inputs
                    )
                    
                    # Validate compliance
                    compliance_results = st.session_state.agent.compliance_manager.validate_compliance(
                        framework_id, analysis_results
                    )
                    
                    if compliance_results['success']:
                        st.metric("Compliance Score", f"{compliance_results['compliance_score']}%")
                        
                        # Show compliant controls
                        st.subheader("Compliant Controls")
                        for control in compliance_results['compliant_controls']:
                            st.success(f"{control['id']}: {control['title']}")
                        
                        # Show non-compliant controls
                        st.subheader("Non-Compliant Controls")
                        for control in compliance_results['non_compliant_controls']:
                            st.error(f"{control['id']}: {control['title']}")
                    else:
                        st.error(compliance_results['message'])
            else:
                st.info("No compliance frameworks available")
        else:
            st.info("Please initialize AWS services first")

    with tab7:
        st.header("Historical Analysis")
        if st.session_state.agent.initialized:
            # Get cluster history
            history = st.session_state.agent.history_manager.get_cluster_history(cluster_name)
            
            if history.get('success', False):
                st.metric("Total Scans", history['scan_count'])
                
                # Show trend chart
                if history.get('trend_chart'):
                    st.image(f"data:image/png;base64,{history['trend_chart']}")
                
                # Show scan history
                st.subheader("Scan History")
                for scan in history.get('history', []):
                    with st.expander(f"Scan {scan['timestamp']}"):
                        st.metric("HardenEKS Score", f"{scan['hardeneks_score']}%")
                        st.write(f"Passed Checks: {scan['passed_checks']}")
                        st.write(f"Failed Checks: {scan['failed_checks']}")
                        
                        if st.button("View Details", key=f"view_scan_{scan['timestamp']}"):
                            scan_details = st.session_state.agent.history_manager.get_scan_details(
                                cluster_name, scan['timestamp']
                            )
                            if scan_details.get('success', False):
                                st.json(scan_details['scan_results'])
            else:
                st.info("No history available for this cluster")
        else:
            st.info("Please initialize AWS services first")

    with tab8:
        st.header("Cluster Comparison")
        if st.session_state.agent.initialized:
            st.info("To compare clusters, add multiple clusters to the comparison")
            
            # Add current cluster to comparison
            if st.button("Add Current Cluster to Comparison", key="add_cluster_comparison"):
                if 'comparison_clusters' not in st.session_state:
                    st.session_state.comparison_clusters = []
                
                # Get cluster details and inputs
                cluster_details = st.session_state.agent.aws_utils.get_cluster_details()
                
                # Add to comparison list
                st.session_state.comparison_clusters.append({
                    'details': cluster_details,
                    'inputs': st.session_state.form_inputs
                })
                
                st.success(f"Added {cluster_name} to comparison")
            
            # Show comparison if multiple clusters are available
            if 'comparison_clusters' in st.session_state and len(st.session_state.comparison_clusters) > 1:
                if st.button("Compare Clusters", key="compare_clusters"):
                    comparison_results = st.session_state.agent.cluster_comparison.compare_clusters(
                        st.session_state.comparison_clusters
                    )
                    
                    if comparison_results.get('success', False):
                        # Show comparison chart
                        if comparison_results.get('comparison_chart'):
                            st.image(f"data:image/png;base64,{comparison_results['comparison_chart']}")
                        
                        # Show top issues
                        st.subheader("Common Issues Across Clusters")
                        for issue in comparison_results.get('top_issues', []):
                            st.error(f"{issue['title']} - Affects {len(issue['clusters'])} clusters")
        else:
            st.info("Please initialize AWS services first")

if __name__ == "__main__":
    main()
