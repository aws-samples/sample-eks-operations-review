import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self):
        pass

    def generate_report(self, cluster_details=None, analysis_results=None, inputs=None, kb_insights=None):
        """Generate a simple text report"""
        try:
            # Create output directory if it doesn't exist
            output_dir = "reports"
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
                
            # Generate a simple filename with timestamp
            cluster_name = cluster_details.get('cluster', {}).get('name', 'unknown') if cluster_details else 'unknown'
            filename = f"eks_review_report_{cluster_name}_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"
            filepath = os.path.join(output_dir, filename)
            
            # Write a simple text report
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"EKS Operational Review Report\n")
                f.write(f"===========================\n\n")
                f.write(f"Cluster: {cluster_name}\n")
                f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n")
                
                # Write summary
                f.write("Summary\n")
                f.write("-------\n")
                if analysis_results:
                    f.write(f"HardenEKS Score: {analysis_results.get('hardeneks_score', 0)}%\n")
                    f.write(f"High Priority Issues: {len(analysis_results.get('high_priority', []))}\n")
                    f.write(f"Medium Priority Issues: {len(analysis_results.get('medium_priority', []))}\n")
                    f.write(f"Low Priority Issues: {len(analysis_results.get('low_priority', []))}\n\n")
                
                # Write findings
                f.write("Findings\n")
                f.write("--------\n")
                if analysis_results:
                    # High priority
                    f.write("High Priority:\n")
                    for finding in analysis_results.get('high_priority', []):
                        f.write(f"- {finding.get('title', 'Unknown')}: {finding.get('description', 'No description')}\n")
                    f.write("\n")
                    
                    # Medium priority
                    f.write("Medium Priority:\n")
                    for finding in analysis_results.get('medium_priority', []):
                        f.write(f"- {finding.get('title', 'Unknown')}: {finding.get('description', 'No description')}\n")
                    f.write("\n")
                    
                    # Low priority
                    f.write("Low Priority:\n")
                    for finding in analysis_results.get('low_priority', []):
                        f.write(f"- {finding.get('title', 'Unknown')}: {finding.get('description', 'No description')}\n")
                    f.write("\n")
                
                # Write recommendations
                f.write("Recommendations\n")
                f.write("--------------\n")
                if analysis_results:
                    for finding in analysis_results.get('high_priority', []):
                        if 'action_items' in finding:
                            f.write(f"{finding.get('title', 'Unknown')}:\n")
                            for item in finding['action_items']:
                                f.write(f"- {item}\n")
                            f.write("\n")
            
            return filepath
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return None