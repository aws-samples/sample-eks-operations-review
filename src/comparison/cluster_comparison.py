import logging
from typing import Dict, List, Any, Optional
import pandas as pd
import matplotlib.pyplot as plt
import io
import base64

from ..analyzers.hardeneks_analyzer import HardenEKSAnalyzer

logger = logging.getLogger(__name__)

class ClusterComparison:
    """
    Compares security postures across multiple EKS clusters
    """
    
    def __init__(self):
        """Initialize the cluster comparison tool"""
        self.hardeneks_analyzer = HardenEKSAnalyzer()
    
    def compare_clusters(self, clusters: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Compare multiple EKS clusters
        
        Args:
            clusters: List of cluster details with inputs
            
        Returns:
            Comparison results
        """
        if not clusters:
            return {
                'success': False,
                'message': 'No clusters provided for comparison'
            }
        
        comparison_results = {
            'success': True,
            'clusters': [],
            'comparison_chart': None,
            'security_categories': {},
            'top_issues': []
        }
        
        # Analyze each cluster
        for cluster in clusters:
            cluster_details = cluster.get('details', {})
            inputs = cluster.get('inputs', {})
            cluster_name = cluster_details.get('cluster', {}).get('name', 'Unknown')
            
            try:
                # Run HardenEKS analysis
                analysis_results = self.hardeneks_analyzer.analyze_cluster(cluster_details, inputs)
                
                # Add cluster results to comparison
                comparison_results['clusters'].append({
                    'name': cluster_name,
                    'hardeneks_score': analysis_results['hardeneks_score'],
                    'passed_checks': len(analysis_results['passed_checks']),
                    'failed_checks': len(analysis_results['failed_checks']),
                    'high_priority_issues': len(analysis_results['high_priority']),
                    'medium_priority_issues': len(analysis_results['medium_priority']),
                    'low_priority_issues': len(analysis_results['low_priority']),
                    'analysis_results': analysis_results
                })
                
                # Collect security categories
                for check in analysis_results['failed_checks']:
                    category = next((rec['category'] for rec in analysis_results['high_priority'] + 
                                    analysis_results['medium_priority'] + analysis_results['low_priority'] 
                                    if rec['title'] == check['check']), 'Unknown')
                    
                    if category not in comparison_results['security_categories']:
                        comparison_results['security_categories'][category] = {
                            'total_checks': 0,
                            'failed_checks': 0,
                            'clusters_with_issues': set()
                        }
                    
                    comparison_results['security_categories'][category]['failed_checks'] += 1
                    comparison_results['security_categories'][category]['clusters_with_issues'].add(cluster_name)
                
                # Collect top issues
                for issue in analysis_results['high_priority']:
                    existing_issue = next((i for i in comparison_results['top_issues'] if i['title'] == issue['title']), None)
                    if existing_issue:
                        existing_issue['clusters'].add(cluster_name)
                    else:
                        issue_copy = issue.copy()
                        issue_copy['clusters'] = {cluster_name}
                        comparison_results['top_issues'].append(issue_copy)
            
            except Exception as e:
                logger.error(f"Error analyzing cluster {cluster_name}: {e}")
        
        # Convert sets to lists for JSON serialization
        for category in comparison_results['security_categories'].values():
            category['clusters_with_issues'] = list(category['clusters_with_issues'])
        
        for issue in comparison_results['top_issues']:
            issue['clusters'] = list(issue['clusters'])
        
        # Sort top issues by number of affected clusters
        comparison_results['top_issues'].sort(key=lambda x: len(x['clusters']), reverse=True)
        comparison_results['top_issues'] = comparison_results['top_issues'][:10]  # Limit to top 10
        
        # Generate comparison chart
        comparison_results['comparison_chart'] = self._generate_comparison_chart(comparison_results['clusters'])
        
        return comparison_results
    
    def _generate_comparison_chart(self, clusters: List[Dict[str, Any]]) -> str:
        """
        Generate a comparison chart for clusters
        
        Args:
            clusters: List of cluster analysis results
            
        Returns:
            Base64-encoded PNG image of the chart
        """
        try:
            # Create DataFrame for plotting
            df = pd.DataFrame({
                'Cluster': [cluster['name'] for cluster in clusters],
                'HardenEKS Score': [cluster['hardeneks_score'] for cluster in clusters],
                'High Priority Issues': [cluster['high_priority_issues'] for cluster in clusters],
                'Medium Priority Issues': [cluster['medium_priority_issues'] for cluster in clusters],
                'Low Priority Issues': [cluster['low_priority_issues'] for cluster in clusters]
            })
            
            # Create figure with subplots
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 6))
            
            # Plot HardenEKS scores
            df.plot(x='Cluster', y='HardenEKS Score', kind='bar', ax=ax1, color='green', legend=False)
            ax1.set_title('HardenEKS Score by Cluster')
            ax1.set_ylabel('Score (%)')
            ax1.set_ylim(0, 100)
            
            # Plot issues by priority
            df.plot(x='Cluster', y=['High Priority Issues', 'Medium Priority Issues', 'Low Priority Issues'], 
                   kind='bar', stacked=True, ax=ax2)
            ax2.set_title('Security Issues by Cluster')
            ax2.set_ylabel('Number of Issues')
            
            plt.tight_layout()
            
            # Convert plot to base64-encoded PNG
            buf = io.BytesIO()
            plt.savefig(buf, format='png')
            buf.seek(0)
            img_str = base64.b64encode(buf.read()).decode('utf-8')
            plt.close(fig)
            
            return img_str
            
        except Exception as e:
            logger.error(f"Error generating comparison chart: {e}")
            return ""
    
    def get_cluster_differences(self, cluster1: Dict[str, Any], cluster2: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get detailed differences between two clusters
        
        Args:
            cluster1: First cluster analysis results
            cluster2: Second cluster analysis results
            
        Returns:
            Differences between the clusters
        """
        differences = {
            'cluster1': cluster1['name'],
            'cluster2': cluster2['name'],
            'score_difference': cluster1['hardeneks_score'] - cluster2['hardeneks_score'],
            'unique_passed_checks': {
                'cluster1': [],
                'cluster2': []
            },
            'unique_failed_checks': {
                'cluster1': [],
                'cluster2': []
            }
        }
        
        # Get passed checks for each cluster
        passed_checks1 = {check['check'] for check in cluster1['analysis_results']['passed_checks']}
        passed_checks2 = {check['check'] for check in cluster2['analysis_results']['passed_checks']}
        
        # Get failed checks for each cluster
        failed_checks1 = {check['check'] for check in cluster1['analysis_results']['failed_checks']}
        failed_checks2 = {check['check'] for check in cluster2['analysis_results']['failed_checks']}
        
        # Find unique passed checks
        differences['unique_passed_checks']['cluster1'] = list(passed_checks1 - passed_checks2)
        differences['unique_passed_checks']['cluster2'] = list(passed_checks2 - passed_checks1)
        
        # Find unique failed checks
        differences['unique_failed_checks']['cluster1'] = list(failed_checks1 - failed_checks2)
        differences['unique_failed_checks']['cluster2'] = list(failed_checks2 - failed_checks1)
        
        return differences