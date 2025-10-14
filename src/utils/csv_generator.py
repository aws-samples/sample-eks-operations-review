import csv  # Standard csv module is safe for writing
import logging
import os
from datetime import datetime

class CSVGenerator:
    def generate_csv(self, analysis_results, cluster_details, filename=None, best_practices_recommendations=None):
        """
        Generate a CSV file with cluster-specific action items based on actual cluster analysis
        
        Args:
            analysis_results: Analysis results from analyzers with actual cluster state
            cluster_details: Cluster configuration details
            filename: Optional filename for the CSV file
            
        Returns:
            Path to the generated CSV file
        """
        # Create output directory if it doesn't exist
        output_dir = "reports"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        if filename is None:
            cluster_name = cluster_details.get('cluster', {}).get('name', 'unknown')
            filename = os.path.join(output_dir, f"EKS_Review_Action_Items_{cluster_name}_{datetime.now().strftime('%Y%m%d_%H%M')}.csv")
        
        headers = ['Type', 'Priority', 'Category', 'Title', 'Description', 'Current State', 'Impact', 'Action Items', 'Reference']
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            
            # Write cluster-specific findings with current state information
            for priority in ['high_priority', 'medium_priority', 'low_priority']:
                for finding in analysis_results.get(priority, []):
                    writer.writerow([
                        'Cluster-Specific Finding',
                        priority.split('_')[0].capitalize() if '_' in priority else priority.capitalize(),
                        finding.get('category', ''),
                        finding.get('title', ''),
                        finding.get('description', ''),
                        finding.get('current_state', 'Not specified'),
                        finding.get('impact', ''),
                        '\n'.join(finding.get('action_items', [])),
                        finding.get('reference', '')
                    ])
            
            # Add passed checks as informational items
            for check in analysis_results.get('passed_checks', []):
                writer.writerow([
                    'Passed Check',
                    'Info',
                    'Security',
                    f"{check['check']} - Compliant",
                    check.get('details', 'Check passed'),
                    'Compliant',
                    'No action required',
                    'Continue monitoring',
                    ''
                ])
            
            # Add best practices recommendations if available
            if best_practices_recommendations:
                for area, recommendation in best_practices_recommendations.items():
                    if recommendation.get('applicable', False):
                        writer.writerow([
                            'Best Practice Recommendation',
                            recommendation.get('priority', 'Medium'),
                            area,
                            f'{area} Best Practices',
                            recommendation.get('analysis', 'No analysis available')[:200] + '...' if len(recommendation.get('analysis', '')) > 200 else recommendation.get('analysis', 'No analysis available'),
                            'Needs Review',
                            'Operational efficiency and best practices compliance',
                            f'Review {area.lower()} configuration and implement recommended best practices',
                            'AWS EKS Best Practices Guide'
                        ])
        
        return filename