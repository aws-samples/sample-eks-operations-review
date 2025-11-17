"""
Report Generation Utilities
"""
from typing import Dict, Any
import json
from datetime import datetime

class ReportGenerator:
    """Generate various report formats"""
    
    def __init__(self):
        pass
    
    def generate_json_report(self, analysis_results: Dict[str, Any], cluster_name: str) -> str:
        """Generate JSON report"""
        report = {
            'cluster_name': cluster_name,
            'generated_at': datetime.now().isoformat(),
            'analysis_results': analysis_results
        }
        
        return json.dumps(report, indent=2, default=str)
    
    def generate_summary_report(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary"""
        health = analysis_results.get('health_analysis', {})
        security = analysis_results.get('security_analysis', {})
        
        return {
            'cluster_status': health.get('cluster_info', {}).get('status', 'Unknown'),
            'security_score': security.get('security_score', 0),
            'total_nodes': health.get('node_analysis', {}).get('total_nodes', 0),
            'critical_issues': len([c for c in security.get('checks', []) if c.get('severity') == 'HIGH' and c.get('status') == 'FAIL']),
            'recommendations_count': len(security.get('recommendations', []))
        }
