import boto3
import logging
import json
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class SecurityHubIntegration:
    """
    Integrates with AWS Security Hub for centralized security findings
    """
    
    def __init__(self, aws_access_key: str, aws_secret_key: str, region: str):
        """
        Initialize the Security Hub integration
        
        Args:
            aws_access_key: AWS access key
            aws_secret_key: AWS secret key
            region: AWS region
        """
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self.region = region
        
        # Initialize Security Hub client
        self.security_hub_client = boto3.client(
            'securityhub',
            region_name=region,
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key
        )
        
        # Initialize STS client for account ID
        self.sts_client = boto3.client(
            'sts',
            region_name=region,
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key
        )
        
        # Get AWS account ID
        try:
            self.account_id = self.sts_client.get_caller_identity()["Account"]
        except Exception as e:
            logger.error(f"Failed to get AWS account ID: {e}")
            self.account_id = None
    
    def is_security_hub_enabled(self) -> bool:
        """
        Check if Security Hub is enabled in the account
        
        Returns:
            True if Security Hub is enabled, False otherwise
        """
        try:
            self.security_hub_client.get_findings(MaxResults=1)
            return True
        except Exception as e:
            logger.warning(f"Security Hub is not enabled: {e}")
            return False
    
    def enable_security_hub(self) -> Dict[str, Any]:
        """
        Enable Security Hub in the account
        
        Returns:
            Result of the operation
        """
        try:
            response = self.security_hub_client.enable_security_hub(
                EnableDefaultStandards=True
            )
            logger.info("Security Hub enabled successfully")
            return {
                'success': True,
                'message': 'Security Hub enabled successfully',
                'response': response
            }
        except Exception as e:
            logger.error(f"Failed to enable Security Hub: {e}")
            return {
                'success': False,
                'message': f"Failed to enable Security Hub: {str(e)}"
            }
    
    def send_findings(self, cluster_name: str, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send findings to Security Hub
        
        Args:
            cluster_name: Name of the EKS cluster
            analysis_results: Analysis results from HardenEKS analyzer
            
        Returns:
            Result of the operation
        """
        if not self.account_id:
            return {
                'success': False,
                'message': 'AWS account ID not available'
            }
        
        try:
            # Prepare findings batch
            findings = []
            
            # Add findings for failed checks
            for check in analysis_results.get('failed_checks', []):
                # Find the recommendation for this check
                recommendation = next(
                    (rec for rec in analysis_results.get('high_priority', []) + 
                     analysis_results.get('medium_priority', []) + 
                     analysis_results.get('low_priority', []) 
                     if rec.get('title') == check.get('check')),
                    None
                )
                
                if not recommendation:
                    continue
                
                # Determine severity based on priority
                priority = recommendation.get('priority', '').lower()
                if priority == 'high':
                    severity = 'HIGH'
                elif priority == 'medium':
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'
                
                # Create finding
                finding = {
                    'SchemaVersion': '2018-10-08',
                    'Id': f"eks-hardeneks-{cluster_name}-{check['check'].replace(' ', '-').lower()}",
                    'ProductArn': f"arn:aws:securityhub:{self.region}:{self.account_id}:product/{self.account_id}/default",
                    'GeneratorId': 'EKS-Operational-Review-Agent',
                    'AwsAccountId': self.account_id,
                    'Types': ['Software and Configuration Checks/AWS Security Best Practices'],
                    'CreatedAt': datetime.now().isoformat() + 'Z',
                    'UpdatedAt': datetime.now().isoformat() + 'Z',
                    'Severity': {
                        'Label': severity
                    },
                    'Title': f"EKS Cluster {cluster_name}: {check['check']} - Failed",
                    'Description': recommendation.get('description', ''),
                    'Remediation': {
                        'Recommendation': {
                            'Text': '; '.join(recommendation.get('action_items', [])),
                            'Url': recommendation.get('reference', '')
                        }
                    },
                    'Resources': [
                        {
                            'Type': 'AwsEksCluster',
                            'Id': f"arn:aws:eks:{self.region}:{self.account_id}:cluster/{cluster_name}"
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
            sent_count = 0
            for i in range(0, len(findings), 100):
                batch = findings[i:i+100]
                self.security_hub_client.batch_import_findings(Findings=batch)
                sent_count += len(batch)
            
            logger.info(f"Sent {sent_count} findings to Security Hub")
            
            return {
                'success': True,
                'message': f"Sent {sent_count} findings to Security Hub",
                'sent_count': sent_count
            }
            
        except Exception as e:
            logger.error(f"Failed to send findings to Security Hub: {e}")
            return {
                'success': False,
                'message': f"Failed to send findings to Security Hub: {str(e)}"
            }
    
    def get_existing_findings(self, cluster_name: str) -> Dict[str, Any]:
        """
        Get existing findings for a cluster from Security Hub
        
        Args:
            cluster_name: Name of the EKS cluster
            
        Returns:
            Existing findings for the cluster
        """
        if not self.account_id:
            return {
                'success': False,
                'message': 'AWS account ID not available'
            }
        
        try:
            # Create filters for the cluster
            filters = {
                'ResourceId': [
                    {
                        'Value': f"arn:aws:eks:{self.region}:{self.account_id}:cluster/{cluster_name}",
                        'Comparison': 'EQUALS'
                    }
                ],
                'GeneratorId': [
                    {
                        'Value': 'EKS-Operational-Review-Agent',
                        'Comparison': 'EQUALS'
                    }
                ]
            }
            
            # Get findings
            response = self.security_hub_client.get_findings(
                Filters=filters,
                MaxResults=100
            )
            
            findings = response.get('Findings', [])
            
            # Continue pagination if there are more findings
            while 'NextToken' in response:
                response = self.security_hub_client.get_findings(
                    Filters=filters,
                    MaxResults=100,
                    NextToken=response['NextToken']
                )
                findings.extend(response.get('Findings', []))
            
            return {
                'success': True,
                'findings': findings,
                'count': len(findings)
            }
            
        except Exception as e:
            logger.error(f"Failed to get findings from Security Hub: {e}")
            return {
                'success': False,
                'message': f"Failed to get findings from Security Hub: {str(e)}"
            }
    
    def update_finding_status(self, finding_id: str, status: str) -> Dict[str, Any]:
        """
        Update the status of a finding in Security Hub
        
        Args:
            finding_id: ID of the finding
            status: New status (RESOLVED, SUPPRESSED, etc.)
            
        Returns:
            Result of the operation
        """
        if not self.account_id:
            return {
                'success': False,
                'message': 'AWS account ID not available'
            }
        
        try:
            # Update finding
            response = self.security_hub_client.batch_update_findings(
                FindingIdentifiers=[
                    {
                        'Id': finding_id,
                        'ProductArn': f"arn:aws:securityhub:{self.region}:{self.account_id}:product/{self.account_id}/default"
                    }
                ],
                Workflow={
                    'Status': status
                }
            )
            
            return {
                'success': True,
                'message': f"Updated finding status to {status}",
                'response': response
            }
            
        except Exception as e:
            logger.error(f"Failed to update finding status: {e}")
            return {
                'success': False,
                'message': f"Failed to update finding status: {str(e)}"
            }