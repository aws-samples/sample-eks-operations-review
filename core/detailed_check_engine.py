"""
Detailed Check Engine - Comprehensive EKS Cluster Analysis with Command Traceability
Provides detailed commands, observations, and recommendations for each check
"""
import json
import subprocess
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class DetailedCheckEngine:
    """
    Comprehensive check engine that tracks:
    1. Exact commands executed
    2. Raw observations from commands
    3. Analysis reasoning
    4. Detailed recommendations with implementation steps
    """
    
    def __init__(self, cluster_name: str, region: str, offline_data: Optional[Dict] = None):
        self.cluster_name = cluster_name
        self.region = region
        self.offline_data = offline_data
        self.is_offline = offline_data is not None
        self.check_results = []
        
    def execute_check(self, check_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a single check with full traceability
        
        Args:
            check_config: Configuration for the check including:
                - check_id: Unique identifier
                - title: Check name
                - category: Check category
                - commands: List of commands to execute
                - analysis_function: Function to analyze results
                - compliance_frameworks: List of applicable frameworks
        
        Returns:
            Detailed check result with commands, observations, and recommendations
        """
        check_id = check_config['check_id']
        title = check_config['title']
        category = check_config['category']
        commands = check_config.get('commands', [])
        
        result = {
            'check_id': check_id,
            'title': title,
            'category': category,
            'timestamp': datetime.now().isoformat(),
            'commands_executed': [],
            'raw_observations': [],
            'analysis': {},
            'status': 'UNKNOWN',
            'severity': check_config.get('severity', 'MEDIUM'),
            'compliance_frameworks': check_config.get('compliance_frameworks', []),
            'recommendations': []
        }
        
        try:
            # Execute each command and capture results
            for cmd_config in commands:
                cmd_result = self._execute_command(cmd_config)
                result['commands_executed'].append(cmd_result)
                result['raw_observations'].append(cmd_result['observation'])
            
            # Analyze results
            if 'analysis_function' in check_config:
                analysis = check_config['analysis_function'](result['commands_executed'])
                result['analysis'] = analysis
                result['status'] = analysis.get('status', 'UNKNOWN')
                result['findings'] = analysis.get('findings', [])
                result['reasoning'] = analysis.get('reasoning', '')
            
            # Generate recommendations
            if result['status'] in ['FAILED', 'WARNING']:
                result['recommendations'] = self._generate_detailed_recommendations(
                    check_config, result
                )
            
        except Exception as e:
            logger.error(f"Check {check_id} failed: {str(e)}")
            result['error'] = str(e)
            result['status'] = 'ERROR'
        
        self.check_results.append(result)
        return result
    
    def _execute_command(self, cmd_config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single command and capture detailed results"""
        cmd = cmd_config['command']
        description = cmd_config.get('description', '')
        
        result = {
            'command': cmd,
            'description': description,
            'execution_time': datetime.now().isoformat(),
            'observation': {},
            'success': False
        }
        
        try:
            if self.is_offline:
                # Extract from offline data
                result['observation'] = self._extract_offline_data(cmd_config)
                result['success'] = True
                result['source'] = 'offline_data'
            else:
                # Execute AWS CLI command
                result['observation'] = self._execute_aws_command(cmd)
                result['success'] = True
                result['source'] = 'aws_api'
        except Exception as e:
            result['error'] = str(e)
            result['observation'] = {'error': str(e)}
        
        return result
    
    def _execute_aws_command(self, cmd: str) -> Dict[str, Any]:
        """Execute AWS CLI command and return parsed result"""
        try:
            # Replace placeholders
            cmd = cmd.replace('{cluster_name}', self.cluster_name)
            cmd = cmd.replace('{region}', self.region)
            
            # Execute command
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                try:
                    return json.loads(result.stdout) if result.stdout else {}
                except json.JSONDecodeError:
                    return {'raw_output': result.stdout}
            else:
                return {'error': result.stderr, 'returncode': result.returncode}
        except Exception as e:
            return {'error': str(e)}
    
    def _extract_offline_data(self, cmd_config: Dict[str, Any]) -> Dict[str, Any]:
        """Extract relevant data from offline JSON"""
        data_path = cmd_config.get('offline_path', '')
        if not data_path or not self.offline_data:
            return {}
        
        # Navigate nested dictionary
        current = self.offline_data
        for key in data_path.split('.'):
            if isinstance(current, dict):
                current = current.get(key, {})
            else:
                return {}
        
        return current
    
    def _generate_detailed_recommendations(self, check_config: Dict[str, Any], 
                                          result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate detailed, actionable recommendations"""
        recommendations = []
        
        base_rec = check_config.get('recommendation_template', {})
        
        recommendation = {
            'priority': result['severity'],
            'title': f"Remediate {result['title']}",
            'description': base_rec.get('description', ''),
            'business_impact': base_rec.get('business_impact', ''),
            'implementation_steps': base_rec.get('steps', []),
            'aws_cli_commands': base_rec.get('commands', []),
            'verification_steps': base_rec.get('verification', []),
            'estimated_effort': base_rec.get('effort', 'Medium'),
            'compliance_impact': result['compliance_frameworks'],
            'aws_documentation': base_rec.get('documentation_links', []),
            'risk_if_not_fixed': base_rec.get('risk', ''),
            'prerequisites': base_rec.get('prerequisites', [])
        }
        
        recommendations.append(recommendation)
        return recommendations
    
    def get_all_results(self) -> List[Dict[str, Any]]:
        """Return all check results"""
        return self.check_results
    
    def get_summary(self) -> Dict[str, Any]:
        """Generate summary of all checks"""
        total = len(self.check_results)
        passed = sum(1 for r in self.check_results if r['status'] == 'PASSED')
        failed = sum(1 for r in self.check_results if r['status'] == 'FAILED')
        warnings = sum(1 for r in self.check_results if r['status'] == 'WARNING')
        errors = sum(1 for r in self.check_results if r['status'] == 'ERROR')
        
        return {
            'total_checks': total,
            'passed': passed,
            'failed': failed,
            'warnings': warnings,
            'errors': errors,
            'compliance_score': (passed / total * 100) if total > 0 else 0,
            'checks_by_category': self._group_by_category(),
            'checks_by_severity': self._group_by_severity(),
            'checks_by_framework': self._group_by_framework()
        }
    
    def _group_by_category(self) -> Dict[str, List[Dict[str, Any]]]:
        """Group checks by category"""
        grouped = {}
        for result in self.check_results:
            category = result['category']
            if category not in grouped:
                grouped[category] = []
            grouped[category].append(result)
        return grouped
    
    def _group_by_severity(self) -> Dict[str, int]:
        """Count checks by severity"""
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for result in self.check_results:
            severity = result.get('severity', 'MEDIUM')
            if severity in severity_counts:
                severity_counts[severity] += 1
        return severity_counts
    
    def _group_by_framework(self) -> Dict[str, Dict[str, int]]:
        """Group checks by compliance framework"""
        frameworks = {}
        for result in self.check_results:
            for framework in result.get('compliance_frameworks', []):
                if framework not in frameworks:
                    frameworks[framework] = {'total': 0, 'passed': 0, 'failed': 0}
                frameworks[framework]['total'] += 1
                if result['status'] == 'PASSED':
                    frameworks[framework]['passed'] += 1
                elif result['status'] == 'FAILED':
                    frameworks[framework]['failed'] += 1
        return frameworks
