"""
Unified Cluster Analyzer - Consolidates all analysis types with accurate cluster data
Addresses accuracy issues identified in the engineering review
"""

import logging
import re
from typing import Dict, List, Any, Optional
from datetime import datetime
from .cluster_state_analyzer import ClusterStateAnalyzer
from .hardeneks_analyzer import HardenEKSAnalyzer
from .cluster_analyzer import ClusterAnalyzer

logger = logging.getLogger(__name__)

def _sanitize_log_input(text: str) -> str:
    """Sanitize input for logging to prevent log injection."""
    if not isinstance(text, str):
        return str(text)
    sanitized = re.sub(r'[\r\n\t\x00-\x1f\x7f-\x9f]', '', text)
    return sanitized[:200]

class UnifiedClusterAnalyzer:
    """
    Unified analyzer that consolidates all analysis types and ensures accuracy
    by using actual cluster state from AWS APIs
    """
    
    def __init__(self, aws_access_key: str, aws_secret_key: str, region: str):
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self.region = region
        self.state_analyzer = None
        self.hardeneks_analyzer = None
        self.k8s_analyzer = None
        
    def analyze_cluster(self, cluster_name: str) -> Dict[str, Any]:
        """
        Perform comprehensive, accurate cluster analysis
        
        Returns:
            Dict containing consolidated analysis results with accurate metadata
        """
        try:
            # Initialize analyzers
            self.state_analyzer = ClusterStateAnalyzer(
                self.aws_access_key, self.aws_secret_key, self.region, cluster_name
            )
            
            self.hardeneks_analyzer = HardenEKSAnalyzer(
                self.aws_access_key, self.aws_secret_key, self.region
            )
            
            self.k8s_analyzer = ClusterAnalyzer(cluster_name, self.region)
            
            # Get comprehensive cluster state
            cluster_state = self.state_analyzer.get_comprehensive_cluster_state()
            
            # Get accurate cluster metadata (fixes N/A issues)
            cluster_metadata = self._extract_accurate_metadata(cluster_state)
            
            # Run security analysis
            security_analysis = self.hardeneks_analyzer.analyze_cluster(cluster_name)
            
            # Run workload analysis if K8s access available
            workload_analysis = self._safe_k8s_analysis(cluster_name)
            
            # Consolidate findings with validation
            consolidated_findings = self._consolidate_and_validate_findings(
                cluster_state, security_analysis, workload_analysis
            )
            
            # Calculate overall scores
            scores = self._calculate_scores(consolidated_findings)
            
            return {
                'cluster_metadata': cluster_metadata,
                'cluster_state': cluster_state,
                'security_analysis': security_analysis,
                'workload_analysis': workload_analysis,
                'consolidated_findings': consolidated_findings,
                'scores': scores,
                'analysis_timestamp': datetime.utcnow().isoformat(),
                'accuracy_validation': self._validate_accuracy(cluster_state, consolidated_findings)
            }
            
        except Exception as e:
            logger.error(f"Error in unified cluster analysis: {_sanitize_log_input(str(e))}")
            raise
    
    def _extract_accurate_metadata(self, cluster_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract accurate cluster metadata from AWS API data
        Fixes the N/A issues in reports
        """
        cluster_info = cluster_state.get('cluster_info', {})
        vpc_config = cluster_info.get('vpc_config', {})
        
        return {
            'cluster_name': cluster_info.get('name', 'Unknown'),
            'region': self.region,  # Use the region from initialization
            'kubernetes_version': cluster_info.get('version', 'Unknown'),
            'platform_version': cluster_info.get('platform_version', 'Unknown'),
            'status': cluster_info.get('status', 'Unknown'),
            'created_at': cluster_info.get('created_at', 'Unknown'),
            'endpoint': cluster_info.get('endpoint', 'Unknown'),
            'vpc_id': vpc_config.get('vpcId', 'Unknown'),
            'subnet_ids': vpc_config.get('subnetIds', []),
            'security_group_ids': vpc_config.get('securityGroupIds', []),
            'endpoint_config': {
                'private_access': vpc_config.get('endpointPrivateAccess', False),
                'public_access': vpc_config.get('endpointPublicAccess', False),
                'public_access_cidrs': vpc_config.get('publicAccessCidrs', [])
            }
        }
    
    def _safe_k8s_analysis(self, cluster_name: str) -> Dict[str, Any]:
        """
        Safely attempt Kubernetes analysis with fallback
        """
        try:
            if self.k8s_analyzer.initialize():
                return self.k8s_analyzer.analyze_cluster()
            else:
                return {'status': 'kubernetes_access_unavailable', 'findings': []}
        except Exception as e:
            logger.warning(f"Kubernetes analysis failed: {_sanitize_log_input(str(e))}")
            return {'status': 'kubernetes_analysis_failed', 'error': str(e), 'findings': []}
    
    def _consolidate_and_validate_findings(self, cluster_state: Dict[str, Any], 
                                         security_analysis: Dict[str, Any],
                                         workload_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Consolidate findings from all analyzers and validate against actual cluster state
        """
        all_findings = {
            'high_priority': [],
            'medium_priority': [],
            'low_priority': [],
            'passed_checks': [],
            'failed_checks': []
        }
        
        # Add security findings with validation
        for finding in security_analysis.get('high_priority', []):
            if self._validate_finding_against_cluster_state(finding, cluster_state):
                all_findings['high_priority'].append(finding)
        
        for finding in security_analysis.get('medium_priority', []):
            if self._validate_finding_against_cluster_state(finding, cluster_state):
                all_findings['medium_priority'].append(finding)
        
        for finding in security_analysis.get('low_priority', []):
            if self._validate_finding_against_cluster_state(finding, cluster_state):
                all_findings['low_priority'].append(finding)
        
        # Add workload findings if available
        if workload_analysis.get('status') not in ['kubernetes_access_unavailable', 'kubernetes_analysis_failed']:
            for priority in ['high_priority', 'medium_priority', 'low_priority']:
                for finding in workload_analysis.get(priority, []):
                    all_findings[priority].append(finding)
        
        # Add passed/failed checks
        all_findings['passed_checks'].extend(security_analysis.get('passed_checks', []))
        all_findings['failed_checks'].extend(security_analysis.get('failed_checks', []))
        
        return all_findings
    
    def _validate_finding_against_cluster_state(self, finding: Dict[str, Any], 
                                              cluster_state: Dict[str, Any]) -> bool:
        """
        Validate that a finding is accurate based on actual cluster state
        """
        try:
            # Validate endpoint configuration findings
            if 'endpoint' in finding.get('title', '').lower():
                return self._validate_endpoint_finding(finding, cluster_state)
            
            # Validate encryption findings
            if 'encryption' in finding.get('title', '').lower():
                return self._validate_encryption_finding(finding, cluster_state)
            
            # Validate logging findings
            if 'logging' in finding.get('title', '').lower():
                return self._validate_logging_finding(finding, cluster_state)
            
            # Validate addon findings
            if 'addon' in finding.get('title', '').lower():
                return self._validate_addon_finding(finding, cluster_state)
            
            # Default to true for other findings (but log for review)
            logger.info(f"Finding validation not implemented for: {finding.get('title', 'Unknown')}")
            return True
            
        except Exception as e:
            logger.warning(f"Error validating finding: {_sanitize_log_input(str(e))}")
            return False
    
    def _validate_endpoint_finding(self, finding: Dict[str, Any], 
                                 cluster_state: Dict[str, Any]) -> bool:
        """
        Validate endpoint configuration findings against actual state
        """
        security_state = cluster_state.get('security_state', {})
        endpoint_access = security_state.get('endpoint_access', {})
        
        private_access = endpoint_access.get('private', False)
        public_access = endpoint_access.get('public', False)
        
        # Only flag as issue if there's actually a problem
        if not private_access and not public_access:
            # This would be a real issue - cluster inaccessible
            return True
        elif public_access and endpoint_access.get('public_cidrs') == ['0.0.0.0/0']:
            # Public access with unrestricted CIDRs is a valid concern
            return True
        elif not private_access and public_access:
            # Only public access might be a concern depending on use case
            return True
        
        return False  # No real endpoint issue found
    
    def _validate_encryption_finding(self, finding: Dict[str, Any], 
                                   cluster_state: Dict[str, Any]) -> bool:
        """
        Validate encryption findings against actual state
        """
        security_state = cluster_state.get('security_state', {})
        secrets_encryption = security_state.get('secrets_encryption', {})
        
        # Only flag if encryption is actually disabled
        return not secrets_encryption.get('enabled', False)
    
    def _validate_logging_finding(self, finding: Dict[str, Any], 
                                cluster_state: Dict[str, Any]) -> bool:
        """
        Validate logging findings against actual state
        """
        logging_state = cluster_state.get('logging_state', {})
        enabled_types = logging_state.get('enabled_types', [])
        
        # Only flag if no logging types are enabled
        return len(enabled_types) == 0
    
    def _validate_addon_finding(self, finding: Dict[str, Any], 
                              cluster_state: Dict[str, Any]) -> bool:
        """
        Validate addon findings against actual state
        """
        addons_state = cluster_state.get('addons_state', {})
        installed_addons = addons_state.get('installed_addons', {})
        
        # Extract addon name from finding
        title = finding.get('title', '')
        for addon_name in installed_addons.keys():
            if addon_name in title.lower():
                # Addon exists, so update recommendation is valid
                return True
        
        # Addon not found, so recommendation might not be applicable
        return False
    
    def _calculate_scores(self, consolidated_findings: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate overall security and compliance scores
        """
        total_checks = (
            len(consolidated_findings['high_priority']) +
            len(consolidated_findings['medium_priority']) +
            len(consolidated_findings['low_priority']) +
            len(consolidated_findings['passed_checks'])
        )
        
        if total_checks == 0:
            return {'security_score': 0, 'total_checks': 0}
        
        passed_checks = len(consolidated_findings['passed_checks'])
        security_score = (passed_checks / total_checks) * 100
        
        return {
            'security_score': round(security_score, 1),
            'total_checks': total_checks,
            'passed_checks': passed_checks,
            'failed_checks': total_checks - passed_checks,
            'high_priority_issues': len(consolidated_findings['high_priority']),
            'medium_priority_issues': len(consolidated_findings['medium_priority']),
            'low_priority_issues': len(consolidated_findings['low_priority'])
        }
    
    def _validate_accuracy(self, cluster_state: Dict[str, Any], 
                         consolidated_findings: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate the accuracy of the analysis
        """
        validation_results = {
            'metadata_accuracy': self._check_metadata_accuracy(cluster_state),
            'finding_accuracy': self._check_finding_accuracy(consolidated_findings, cluster_state),
            'overall_confidence': 0.0
        }
        
        # Calculate overall confidence score
        metadata_score = 1.0 if validation_results['metadata_accuracy']['complete'] else 0.5
        finding_score = validation_results['finding_accuracy']['validated_percentage'] / 100
        
        validation_results['overall_confidence'] = (metadata_score + finding_score) / 2
        
        return validation_results
    
    def _check_metadata_accuracy(self, cluster_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check if cluster metadata is complete and accurate
        """
        cluster_info = cluster_state.get('cluster_info', {})
        
        required_fields = ['name', 'version', 'status', 'endpoint', 'created_at', 'vpc_config']
        missing_fields = [field for field in required_fields if not cluster_info.get(field)]
        
        return {
            'complete': len(missing_fields) == 0,
            'missing_fields': missing_fields,
            'completeness_percentage': ((len(required_fields) - len(missing_fields)) / len(required_fields)) * 100
        }
    
    def _check_finding_accuracy(self, consolidated_findings: Dict[str, Any], 
                              cluster_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check the accuracy of findings against cluster state
        """
        total_findings = (
            len(consolidated_findings['high_priority']) +
            len(consolidated_findings['medium_priority']) +
            len(consolidated_findings['low_priority'])
        )
        
        if total_findings == 0:
            return {'validated_percentage': 100, 'total_findings': 0, 'validated_findings': 0}
        
        validated_findings = 0
        for priority in ['high_priority', 'medium_priority', 'low_priority']:
            for finding in consolidated_findings[priority]:
                if self._validate_finding_against_cluster_state(finding, cluster_state):
                    validated_findings += 1
        
        return {
            'validated_percentage': (validated_findings / total_findings) * 100,
            'total_findings': total_findings,
            'validated_findings': validated_findings
        }
