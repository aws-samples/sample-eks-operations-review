"""
Core configuration management
"""
import os
from dataclasses import dataclass
from typing import Optional

@dataclass
class Config:
    """Application configuration"""
    
    # AWS Configuration
    aws_region: str = os.getenv('AWS_DEFAULT_REGION', 'us-west-2')
    aws_access_key: Optional[str] = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_key: Optional[str] = os.getenv('AWS_SECRET_ACCESS_KEY')
    
    # Application Configuration
    app_title: str = "AgentK8s - EKS Operations Review"
    app_icon: str = "🚀"
    debug: bool = os.getenv('DEBUG', 'false').lower() == 'true'
    
    # Multi-Agent Configuration
    enable_multi_agent: bool = os.getenv('ENABLE_MULTI_AGENT', 'false').lower() == 'true'
    
    # Bedrock Configuration  
    bedrock_model_id: str = "anthropic.claude-3-5-sonnet-20240620-v1:0"
    bedrock_knowledge_base_id: Optional[str] = os.getenv('BEDROCK_KNOWLEDGE_BASE_ID')
    
    # Performance Configuration
    cache_ttl: int = 300  # 5 minutes
    max_concurrent_analyses: int = 4
    
    def validate(self) -> bool:
        """Validate configuration"""
        if not self.aws_region:
            return False
        return True
