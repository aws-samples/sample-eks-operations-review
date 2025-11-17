"""
AWS Client Management - Secure authentication with IAM roles
"""
import boto3
from botocore.exceptions import ClientError
from typing import Dict, Optional
import logging

logger = logging.getLogger(__name__)

class AWSClientManager:
    """Manages AWS client connections with IAM role support"""
    
    def __init__(self, region: str = 'us-west-2', role_arn: Optional[str] = None):
        self.region = region
        self.role_arn = role_arn
        self._clients = {}
        self._session = None
        
    def get_clients(self) -> Dict[str, any]:
        """Get AWS service clients"""
        if not self._clients:
            self._initialize_clients()
        return self._clients
    
    def _initialize_clients(self):
        """Initialize AWS service clients"""
        try:
            if self.role_arn:
                self._session = self._assume_role()
            else:
                self._session = boto3.Session()
            
            self._clients = {
                'eks': self._session.client('eks', region_name=self.region),
                'ec2': self._session.client('ec2', region_name=self.region),
                'iam': self._session.client('iam', region_name=self.region),
                'logs': self._session.client('logs', region_name=self.region),
                'sts': self._session.client('sts', region_name=self.region)
            }
            
            # Test connection
            self._test_connection()
            
        except Exception as e:
            logger.error(f"Failed to initialize AWS clients: {e}")
            raise
    
    def _assume_role(self) -> boto3.Session:
        """Assume IAM role for secure access"""
        try:
            sts_client = boto3.client('sts')
            assumed_role = sts_client.assume_role(
                RoleArn=self.role_arn,
                RoleSessionName='AgentK8sSession'
            )
            
            credentials = assumed_role['Credentials']
            return boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
        except ClientError as e:
            logger.error(f"Failed to assume role {self.role_arn}: {e}")
            raise
    
    def _test_connection(self):
        """Test AWS connection"""
        try:
            # Test STS connection
            identity = self._clients['sts'].get_caller_identity()
            logger.info(f"AWS connection successful. Account: {identity.get('Account')}")
            
            # Test EKS access
            clusters = self._clients['eks'].list_clusters()
            logger.info(f"EKS access confirmed. Found {len(clusters.get('clusters', []))} clusters")
            
        except ClientError as e:
            logger.error(f"AWS connection test failed: {e}")
            raise
    
    def get_account_id(self) -> str:
        """Get AWS account ID"""
        try:
            identity = self._clients['sts'].get_caller_identity()
            return identity['Account']
        except Exception as e:
            logger.error(f"Failed to get account ID: {e}")
            return "unknown"
