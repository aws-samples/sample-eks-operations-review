"""
Comprehensive Check Engine - Tracks all commands, observations, and reasoning
Provides detailed audit trail for every check performed
"""
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
import json

class CheckResult:
    """Detailed result for a single check"""
    def __init__(self, check_id: str, title: str, category: str, severity: str):
        self.check_id = check_id
        self.title = title
        self.category = category
        self.severity = severity
        self.status = "NOT_RUN"
        self.commands_executed = []
        self.observations = []
        self.reasoning = ""
        self.raw_data = {}
        self.recommendation = {}
        self.compliance_frameworks = []
        self.timestamp = datetime.now().isoformat()
    
    def add_command(self, command: str, description: str, output: Any):
        """Record a command that was executed"""
        self.commands_executed.append({
            'command': command,
            'description': description,
            'output': output,
            'timestamp': datetime.now().isoformat()
        })
    
    def add_observation(self, observation: str, severity: str = "INFO"):
        """Record an observation from the check"""
        self.observations.append({
            'text': observation,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        })
    
    def set_result(self, status: str, reasoning: str, recommendation: Dict[str, Any]):
        """Set the final result of the check"""
        self.status = status
        self.reasoning = reasoning
        self.recommendation = recommendation
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for reporting"""
        return {
            'check_id': self.check_id,
            'title': self.title,
            'category': self.category,
            'severity': self.severity,
            'status': self.status,
            'commands_executed': self.commands_executed,
            'observations': self.observations,
            'reasoning': self.reasoning,
            'raw_data': self.raw_data,
            'recommendation': self.recommendation,
            'compliance_frameworks': self.compliance_frameworks,
            'timestamp': self.timestamp
        }

class ComprehensiveCheckEngine:
    """
    Engine that executes checks with full audit trail
    Tracks every command, observation, and decision
    """
    
    def __init__(self, cluster_data: Dict[str, Any], is_offline: bool = False):
        self.cluster_data = cluster_data
        self.is_offline = is_offline
        self.results = []
    
    def execute_check(self, check_definition: Dict[str, Any]) -> CheckResult:
        """Execute a single check with full tracking"""
        result = CheckResult(
            check_id=check_definition['check_id'],
            title=check_definition['title'],
            category=check_definition['category'],
            severity=check_definition['severity']
        )
        result.compliance_frameworks = check_definition.get('compliance_frameworks', [])
        
        # Execute commands and collect data
        for cmd_def in check_definition.get('commands', []):
            output = self._execute_command(cmd_def)
            result.add_command(
                command=cmd_def['command'],
                description=cmd_def['description'],
                output=output
            )
            result.raw_data[cmd_def.get('data_key', 'output')] = output
        
        # Run analysis function
        analysis_func = check_definition.get('analysis_function')
        if analysis_func:
            analysis_result = analysis_func(result.raw_data, self.cluster_data)
            
            # Record observations
            for obs in analysis_result.get('observations', []):
                result.add_observation(obs['text'], obs.get('severity', 'INFO'))
            
            # Set final result
            result.set_result(
                status=analysis_result['status'],
                reasoning=analysis_result['reasoning'],
                recommendation=analysis_result.get('recommendation', {})
            )
        
        self.results.append(result)
        return result
    
    def _execute_command(self, cmd_def: Dict[str, Any]) -> Any:
        """Execute command or retrieve from offline data"""
        if self.is_offline:
            # Navigate offline data path
            path = cmd_def.get('offline_path', '').split('.')
            data = self.cluster_data
            for key in path:
                if key:
                    data = data.get(key, {})
            return data
        else:
            # For online mode, this would execute actual AWS CLI/kubectl commands
            # Placeholder for now - actual implementation would use boto3/kubectl
            return {"note": "Online execution not implemented in this version"}
    
    def get_all_results(self) -> List[Dict[str, Any]]:
        """Get all check results"""
        return [r.to_dict() for r in self.results]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics"""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.status == "PASSED")
        failed = sum(1 for r in self.results if r.status == "FAILED")
        warning = sum(1 for r in self.results if r.status == "WARNING")
        manual = sum(1 for r in self.results if r.status == "MANUAL_REVIEW")
        
        return {
            'total_checks': total,
            'passed': passed,
            'failed': failed,
            'warning': warning,
            'manual_review': manual,
            'compliance_percentage': (passed / total * 100) if total > 0 else 0
        }
