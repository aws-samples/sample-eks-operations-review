"""
Production configuration for EKS Operational Review Agent
"""
import os
import logging
from typing import Dict, Any

class Config:
    """Production configuration settings"""
    
    # AWS Configuration
    AWS_DEFAULT_REGION = os.getenv('AWS_DEFAULT_REGION', 'us-west-2')
    AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
    
    # Bedrock Configuration
    BEDROCK_KNOWLEDGE_BASE_ID = os.getenv('BEDROCK_KNOWLEDGE_BASE_ID')
    BEDROCK_MODEL_ARN = os.getenv('BEDROCK_MODEL_ARN', 'anthropic.claude-3-5-sonnet-20241022-v2:0')
    
    # Application Configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    STREAMLIT_SERVER_PORT = int(os.getenv('STREAMLIT_SERVER_PORT', '8501'))
    STREAMLIT_SERVER_ADDRESS = os.getenv('STREAMLIT_SERVER_ADDRESS', '127.0.0.1')
    
    # Security Configuration
    MAX_REPORT_SIZE_MB = int(os.getenv('MAX_REPORT_SIZE_MB', '50'))
    SESSION_TIMEOUT_MINUTES = int(os.getenv('SESSION_TIMEOUT_MINUTES', '30'))
    
    # Rate Limiting
    MAX_REQUESTS_PER_MINUTE = int(os.getenv('MAX_REQUESTS_PER_MINUTE', '10'))
    
    # Monitoring Configuration
    ENABLE_METRICS = os.getenv('ENABLE_METRICS', 'true').lower() == 'true'
    METRICS_PORT = int(os.getenv('METRICS_PORT', '9090'))
    
    @classmethod
    def validate(cls) -> Dict[str, Any]:
        """Validate configuration and return validation results"""
        errors = []
        warnings = []
        
        # Check required AWS credentials
        if not cls.AWS_ACCESS_KEY_ID:
            errors.append("AWS_ACCESS_KEY_ID not set")
        if not cls.AWS_SECRET_ACCESS_KEY:
            errors.append("AWS_SECRET_ACCESS_KEY not set")
            
        # Check optional configurations
        if not cls.BEDROCK_KNOWLEDGE_BASE_ID:
            warnings.append("BEDROCK_KNOWLEDGE_BASE_ID not set - KB features disabled")
            
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings
        }

def setup_logging():
    """Setup production logging configuration"""
    log_level = getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO)
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('eks_review.log')
        ]
    )
    
    # Reduce noise from boto3
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
