import boto3
import logging
import time
import threading
import json
from datetime import datetime
from typing import Dict, List, Any, Optional

from ..analyzers.hardeneks_analyzer import HardenEKSAnalyzer
from ..utils.aws_utils import AWSUtils
from ..utils.report_generator import ReportGenerator

logger = logging.getLogger(__name__)

class ClusterMonitor:
    """
    Provides real-time monitoring of EKS clusters for security issues
    """
    
    def __init__(self, aws_utils: AWSUtils, monitoring_interval: int = 3600):
        """
        Initialize the cluster monitor
        
        Args:
            aws_utils: AWS utilities for interacting with AWS services
            monitoring_interval: Interval in seconds between monitoring runs (default: 1 hour)
        """
        self.aws_utils = aws_utils
        self.monitoring_interval = monitoring_interval
        self.hardeneks_analyzer = HardenEKSAnalyzer()
        self.report_generator = ReportGenerator()
        self.monitoring_thread = None
        self.stop_monitoring = False
        self.monitoring_history = []
        self.security_hub_client = None
        
        # Initialize Security Hub client if available
        try:
            self.security_hub_client = boto3.client(
                'securityhub',
                region_name=self.aws_utils.region,
                aws_access_key_id=self.aws_utils.aws_access_key,
                aws_secret_access_key=self.aws_utils.aws_secret_key
            )
        except Exception as e:
            logger.warning(f"Failed to initialize Security Hub client: {e}")
    
    def start_monitoring(self, cluster_name: str, inputs: Dict[str, Any]):
        """
        Start monitoring the specified cluster
        
        Args:
            cluster_name: Name of the EKS cluster to monitor
            inputs: User inputs about the cluster
        """
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            logger.warning("Monitoring is already running")
            return
        
        self.stop_monitoring = False
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(cluster_name, inputs),
            daemon=True
        )
        self.monitoring_thread.start()
        logger.info(f"Started monitoring for cluster {cluster_name}")
    
    def stop_monitoring_cluster(self):
        """Stop the monitoring thread"""
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.stop_monitoring = True
            self.monitoring_thread.join(timeout=5)
            logger.info("Stopped cluster monitoring")
        else:
            logger.warning("No active monitoring to stop")
    
    def _monitoring_loop(self, cluster_name: str, inputs: Dict[str, Any]):
        """
        Main monitoring loop that runs periodically
        
        Args:
            cluster_name: Name of the EKS cluster to monitor
            inputs: User inputs about the cluster
        """
        while not self.stop_monitoring:
            try:
                # Get cluster details
                cluster_details = self.aws_utils.get_cluster_details()
                
                # Run HardenEKS analysis
                analysis_results = self.hardeneks_analyzer.analyze_cluster(cluster_details, inputs)
                
                # Store results in history
                timestamp = datetime.now().isoformat()
                history_entry = {
                    'timestamp': timestamp,
                    'cluster_name': cluster_name,
                    'hardeneks_score': analysis_results['hardeneks_score'],
                    'passed_checks': len(analysis_results['passed_checks']),
                    'failed_checks': len(analysis_results['failed_checks']),
                    'high_priority_issues': len(analysis_results['high_priority']),
                    'medium_priority_issues': len(analysis_results['medium_priority']),
                    'low_priority_issues': len(analysis_results['low_priority'])
                }
                self.monitoring_history.append(history_entry)
                
                # Limit history size
                if len(self.monitoring_history) > 100:
                    self.monitoring_history = self.monitoring_history[-100:]
                
                # Send findings to Security Hub if enabled
                if self.security_hub_client:
                    self._send_to_security_hub(cluster_name, analysis_results)
                
                logger.info(f"Completed monitoring scan for cluster {cluster_name}")
                
                # Wait until next interval with interruptible sleep
                import threading
                event = threading.Event()
                event.wait(self.monitoring_interval) if not self.stop_monitoring else None
            
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                # Wait for shorter interval on error
                import threading
                event = threading.Event()
                event.wait(300) if not self.stop_monitoring else None  # 5 minutes
    
    def get_monitoring_history(self) -> List[Dict[str, Any]]:
        """
        Get the monitoring history
        
        Returns:
            List of monitoring history entries
        """
        return self.monitoring_history
    
    def get_trend_analysis(self) -> Dict[str, Any]:
        """
        Analyze trends in security posture over time
        
        Returns:
            Trend analysis results
        """
        if not self.monitoring_history:
            return {
                'trend': 'No data',
                'score_change': 0,
                'passed_checks_change': 0,
                'failed_checks_change': 0
            }
        
        # Get first and last entries
        first = self.monitoring_history[0]
        last = self.monitoring_history[-1]
        
        # Calculate changes
        score_change = last['hardeneks_score'] - first['hardeneks_score']
        passed_checks_change = last['passed_checks'] - first['passed_checks']
        failed_checks_change = last['failed_checks'] - first['failed_checks']
        
        # Determine trend
        if score_change > 0:
            trend = 'Improving'
        elif score_change < 0:
            trend = 'Deteriorating'
        else:
            trend = 'Stable'
        
        return {
            'trend': trend,
            'score_change': score_change,
            'passed_checks_change': passed_checks_change,
            'failed_checks_change': failed_checks_change,
            'first_scan': first['timestamp'],
            'latest_scan': last['timestamp']
        }
    
    def _send_to_security_hub(self, cluster_name: str, analysis_results: Dict[str, Any]):
        """
        Send findings to AWS Security Hub
        
        Args:
            cluster_name: Name of the EKS cluster
            analysis_results: Analysis results from HardenEKS analyzer
        """
        try:
            # Get AWS account ID
            sts_client = boto3.client(
                'sts',
                region_name=self.aws_utils.region,
                aws_access_key_id=self.aws_utils.aws_access_key,
                aws_secret_access_key=self.aws_utils.aws_secret_key
            )
            account_id = sts_client.get_caller_identity()["Account"]
            
            # Prepare findings batch
            findings = []
            
            # Add findings for failed checks
            for check in analysis_results['failed_checks']:
                severity = 'HIGH' if any(rec['title'] == check['check'] and rec['priority'].lower() == 'high' 
                                        for rec in analysis_results['high_priority']) else 'MEDIUM'
                
                finding = {
                    'SchemaVersion': '2018-10-08',
                    'Id': f"eks-hardeneks-{cluster_name}-{check['check'].replace(' ', '-').lower()}",
                    'ProductArn': f"arn:aws:securityhub:{self.aws_utils.region}:{account_id}:product/{account_id}/default",
                    'GeneratorId': 'EKS-Operational-Review-Agent',
                    'AwsAccountId': account_id,
                    'Types': ['Software and Configuration Checks/AWS Security Best Practices'],
                    'CreatedAt': datetime.now().isoformat() + 'Z',
                    'UpdatedAt': datetime.now().isoformat() + 'Z',
                    'Severity': {
                        'Label': severity
                    },
                    'Title': f"EKS Cluster {cluster_name}: {check['check']} - Failed",
                    'Description': f"The EKS cluster {cluster_name} failed the {check['check']} security check.",
                    'Resources': [
                        {
                            'Type': 'AwsEksCluster',
                            'Id': f"arn:aws:eks:{self.aws_utils.region}:{account_id}:cluster/{cluster_name}"
                        }
                    ],
                    'Compliance': {
                        'Status': 'FAILED'
                    },
                    'Workflow': {
                        'Status': 'NEW'
                    },
                    'RecordState': 'ACTIVE'
                }
                
                findings.append(finding)
            
            # Send findings in batches of 100 (Security Hub limit)
            for i in range(0, len(findings), 100):
                batch = findings[i:i+100]
                self.security_hub_client.batch_import_findings(Findings=batch)
            
            logger.info(f"Sent {len(findings)} findings to Security Hub")
            
        except Exception as e:
            logger.error(f"Failed to send findings to Security Hub: {e}")