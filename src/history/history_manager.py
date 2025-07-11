import logging
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
import matplotlib.pyplot as plt
import io
import base64

logger = logging.getLogger(__name__)

class HistoryManager:
    """
    Manages historical data for EKS cluster security posture
    """
    
    def __init__(self, storage_dir: str = None):
        """
        Initialize the history manager
        
        Args:
            storage_dir: Directory to store history data (default: ~/.eks-operational-review)
        """
        if storage_dir is None:
            home_dir = os.path.expanduser("~")
            storage_dir = os.path.join(home_dir, ".eks-operational-review")
        
        self.storage_dir = storage_dir
        self.history_dir = os.path.join(storage_dir, "history")
        
        # Create directories if they don't exist
        if not os.path.exists(self.history_dir):
            os.makedirs(self.history_dir)
    
    def save_scan_results(self, cluster_name: str, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Save scan results to history
        
        Args:
            cluster_name: Name of the EKS cluster
            analysis_results: Analysis results from HardenEKS analyzer
            
        Returns:
            Result of the operation
        """
        try:
            # Create cluster directory if it doesn't exist
            cluster_dir = os.path.join(self.history_dir, cluster_name)
            if not os.path.exists(cluster_dir):
                os.makedirs(cluster_dir)
            
            # Create timestamp for the scan
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Create summary of the scan
            summary = {
                'timestamp': timestamp,
                'datetime': datetime.now().isoformat(),
                'cluster_name': cluster_name,
                'hardeneks_score': analysis_results.get('hardeneks_score', 0),
                'passed_checks': len(analysis_results.get('passed_checks', [])),
                'failed_checks': len(analysis_results.get('failed_checks', [])),
                'high_priority_issues': len(analysis_results.get('high_priority', [])),
                'medium_priority_issues': len(analysis_results.get('medium_priority', [])),
                'low_priority_issues': len(analysis_results.get('low_priority', []))
            }
            
            # Save summary to index file
            index_file = os.path.join(cluster_dir, "index.json")
            if os.path.exists(index_file):
                with open(index_file, 'r', encoding='utf-8') as f:
                    index = json.load(f)
            else:
                index = []
            
            index.append(summary)
            
            with open(index_file, 'w', encoding='utf-8') as f:
                json.dump(index, f, indent=2)
            
            # Save full scan results
            scan_file = os.path.join(cluster_dir, f"scan_{timestamp}.json")
            with open(scan_file, 'w', encoding='utf-8') as f:
                json.dump(analysis_results, f, indent=2)
            
            return {
                'success': True,
                'message': f"Saved scan results for cluster {cluster_name}",
                'timestamp': timestamp,
                'scan_file': scan_file
            }
            
        except Exception as e:
            logger.error(f"Failed to save scan results: {e}")
            return {
                'success': False,
                'message': f"Failed to save scan results: {str(e)}"
            }
    
    def get_cluster_history(self, cluster_name: str) -> Dict[str, Any]:
        """
        Get historical data for a cluster
        
        Args:
            cluster_name: Name of the EKS cluster
            
        Returns:
            Historical data for the cluster
        """
        try:
            # Check if cluster directory exists
            cluster_dir = os.path.join(self.history_dir, cluster_name)
            if not os.path.exists(cluster_dir):
                return {
                    'success': False,
                    'message': f"No history found for cluster {cluster_name}"
                }
            
            # Load index file
            index_file = os.path.join(cluster_dir, "index.json")
            if not os.path.exists(index_file):
                return {
                    'success': False,
                    'message': f"No history index found for cluster {cluster_name}"
                }
            
            with open(index_file, 'r', encoding='utf-8') as f:
                index = json.load(f)
            
            # Sort index by timestamp
            index.sort(key=lambda x: x['timestamp'])
            
            # Generate trend chart
            trend_chart = self._generate_trend_chart(index)
            
            return {
                'success': True,
                'cluster_name': cluster_name,
                'history': index,
                'scan_count': len(index),
                'trend_chart': trend_chart,
                'first_scan': index[0] if index else None,
                'latest_scan': index[-1] if index else None
            }
            
        except Exception as e:
            logger.error(f"Failed to get cluster history: {e}")
            return {
                'success': False,
                'message': f"Failed to get cluster history: {str(e)}"
            }
    
    def get_scan_details(self, cluster_name: str, timestamp: str) -> Dict[str, Any]:
        """
        Get details of a specific scan
        
        Args:
            cluster_name: Name of the EKS cluster
            timestamp: Timestamp of the scan
            
        Returns:
            Details of the scan
        """
        try:
            # Check if scan file exists
            scan_file = os.path.join(self.history_dir, cluster_name, f"scan_{timestamp}.json")
            if not os.path.exists(scan_file):
                return {
                    'success': False,
                    'message': f"Scan file not found for cluster {cluster_name} at timestamp {timestamp}"
                }
            
            # Load scan file
            with open(scan_file, 'r', encoding='utf-8') as f:
                scan_results = json.load(f)
            
            return {
                'success': True,
                'cluster_name': cluster_name,
                'timestamp': timestamp,
                'scan_results': scan_results
            }
            
        except Exception as e:
            logger.error(f"Failed to get scan details: {e}")
            return {
                'success': False,
                'message': f"Failed to get scan details: {str(e)}"
            }
    
    def compare_scans(self, cluster_name: str, timestamp1: str, timestamp2: str) -> Dict[str, Any]:
        """
        Compare two scans for a cluster
        
        Args:
            cluster_name: Name of the EKS cluster
            timestamp1: Timestamp of the first scan
            timestamp2: Timestamp of the second scan
            
        Returns:
            Comparison of the two scans
        """
        try:
            # Get scan details
            scan1 = self.get_scan_details(cluster_name, timestamp1)
            scan2 = self.get_scan_details(cluster_name, timestamp2)
            
            if not scan1['success'] or not scan2['success']:
                return {
                    'success': False,
                    'message': f"Failed to get scan details for comparison"
                }
            
            scan1_results = scan1['scan_results']
            scan2_results = scan2['scan_results']
            
            # Compare scores
            score1 = scan1_results.get('hardeneks_score', 0)
            score2 = scan2_results.get('hardeneks_score', 0)
            score_change = score2 - score1
            
            # Compare passed checks
            passed_checks1 = {check['check'] for check in scan1_results.get('passed_checks', [])}
            passed_checks2 = {check['check'] for check in scan2_results.get('passed_checks', [])}
            
            new_passed_checks = passed_checks2 - passed_checks1
            lost_passed_checks = passed_checks1 - passed_checks2
            
            # Compare failed checks
            failed_checks1 = {check['check'] for check in scan1_results.get('failed_checks', [])}
            failed_checks2 = {check['check'] for check in scan2_results.get('failed_checks', [])}
            
            new_failed_checks = failed_checks2 - failed_checks1
            resolved_failed_checks = failed_checks1 - failed_checks2
            
            return {
                'success': True,
                'cluster_name': cluster_name,
                'timestamp1': timestamp1,
                'timestamp2': timestamp2,
                'score1': score1,
                'score2': score2,
                'score_change': score_change,
                'new_passed_checks': list(new_passed_checks),
                'lost_passed_checks': list(lost_passed_checks),
                'new_failed_checks': list(new_failed_checks),
                'resolved_failed_checks': list(resolved_failed_checks)
            }
            
        except Exception as e:
            logger.error(f"Failed to compare scans: {e}")
            return {
                'success': False,
                'message': f"Failed to compare scans: {str(e)}"
            }
    
    def _generate_trend_chart(self, history: List[Dict[str, Any]]) -> str:
        """
        Generate a trend chart for historical data
        
        Args:
            history: List of historical scan summaries
            
        Returns:
            Base64-encoded PNG image of the chart
        """
        try:
            if not history:
                return ""
            
            # Extract data for plotting
            timestamps = [entry['datetime'] for entry in history]
            scores = [entry['hardeneks_score'] for entry in history]
            high_issues = [entry['high_priority_issues'] for entry in history]
            medium_issues = [entry['medium_priority_issues'] for entry in history]
            low_issues = [entry['low_priority_issues'] for entry in history]
            
            # Create figure with subplots
            fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))
            
            # Plot HardenEKS scores
            ax1.plot(timestamps, scores, marker='o', linestyle='-', color='green')
            ax1.set_title('HardenEKS Score Trend')
            ax1.set_ylabel('Score (%)')
            ax1.set_ylim(0, 100)
            ax1.grid(True)
            plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45, ha='right')
            
            # Plot issues by priority
            ax2.stackplot(timestamps, high_issues, medium_issues, low_issues, 
                         labels=['High', 'Medium', 'Low'],
                         colors=['red', 'orange', 'yellow'])
            ax2.set_title('Security Issues Trend')
            ax2.set_ylabel('Number of Issues')
            ax2.grid(True)
            ax2.legend(loc='upper right')
            plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45, ha='right')
            
            plt.tight_layout()
            
            # Convert plot to base64-encoded PNG
            buf = io.BytesIO()
            plt.savefig(buf, format='png')
            buf.seek(0)
            img_str = base64.b64encode(buf.read()).decode('utf-8')
            plt.close(fig)
            
            return img_str
            
        except Exception as e:
            logger.error(f"Error generating trend chart: {e}")
            return ""