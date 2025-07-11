try:
    import defusedcsv as csv
except ImportError:
    import csv
    import logging
    logging.warning("defusedcsv not available, using standard csv module")
import os
from datetime import datetime

class CSVGenerator:
    def generate_csv(self, analysis_results, cluster_details, filename=None):
        """
        Generate a CSV file with action items, clearly marking which are applicable to the current cluster
        
        Args:
            analysis_results: Analysis results from analyzers
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
        
        headers = ['Type', 'Priority', 'Category', 'Title', 'Description', 'Impact', 'Action Items', 'Reference']
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            
            # Directly write all HardenEKS findings as cluster-specific
            for priority in ['high_priority', 'medium_priority', 'low_priority']:
                for finding in analysis_results[priority]:
                    writer.writerow([
                        'Cluster-Specific',
                        priority.split('_')[0].capitalize() if '_' in priority else priority.capitalize(),
                        finding.get('category', ''),
                        finding.get('title', ''),
                        finding.get('description', ''),
                        finding.get('impact', ''),
                        '\n'.join(finding.get('action_items', [])),
                        finding.get('reference', '')
                    ])
        
        return filename