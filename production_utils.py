"""
Production utilities for error handling, monitoring, and security
"""
import time
import functools
import logging
from typing import Dict, Any, Callable
from datetime import datetime, timedelta
import streamlit as st

logger = logging.getLogger(__name__)

class RateLimiter:
    """Simple rate limiter for API calls"""
    
    def __init__(self, max_requests: int = 10, window_minutes: int = 1):
        self.max_requests = max_requests
        self.window_minutes = window_minutes
        self.requests = []
    
    def is_allowed(self) -> bool:
        """Check if request is allowed under rate limit"""
        now = datetime.now()
        cutoff = now - timedelta(minutes=self.window_minutes)
        
        # Remove old requests
        self.requests = [req_time for req_time in self.requests if req_time > cutoff]
        
        if len(self.requests) < self.max_requests:
            self.requests.append(now)
            return True
        return False

def retry_with_backoff(max_retries: int = 3, backoff_factor: float = 1.0):
    """Decorator for retrying functions with exponential backoff"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries - 1:
                        logger.warning(f"Function {func.__name__} failed after {max_retries} attempts: {e}")
                        raise
                    
                    wait_time = backoff_factor * (2 ** attempt)
                    logger.warning(f"Attempt {attempt + 1} failed for {func.__name__}: {e}. Retrying in {wait_time}s")
                    time.sleep(wait_time)
            
            return None
        return wrapper
    return decorator

def handle_errors(func: Callable) -> Callable:
    """Decorator for consistent error handling"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {str(e)}", exc_info=True)
            st.error(f"An error occurred: {str(e)}")
            return None
    return wrapper

def validate_input(data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and sanitize input data"""
    errors = []
    sanitized = {}
    
    for key, value in data.items():
        if isinstance(value, str):
            # Basic sanitization
            sanitized_value = value.strip()[:1000]  # Limit length
            if not sanitized_value:
                errors.append(f"{key} cannot be empty")
            else:
                sanitized[key] = sanitized_value
        else:
            sanitized[key] = value
    
    return {
        'valid': len(errors) == 0,
        'errors': errors,
        'data': sanitized
    }

def monitor_performance(func: Callable) -> Callable:
    """Decorator to monitor function performance"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time
            logger.info(f"{func.__name__} completed in {execution_time:.2f}s")
            return result
        except Exception as e:
            execution_time = time.time() - start_time
            logger.warning(f"{func.__name__} failed after {execution_time:.2f}s: {e}")
            raise
    return wrapper

class HealthChecker:
    """Health check utilities for production monitoring"""
    
    @staticmethod
    def check_aws_connectivity() -> Dict[str, Any]:
        """Check AWS service connectivity"""
        try:
            import boto3
            sts = boto3.client('sts')
            sts.get_caller_identity()
            return {'status': 'healthy', 'message': 'AWS connectivity OK'}
        except Exception as e:
            return {'status': 'unhealthy', 'message': f'AWS connectivity failed: {e}'}
    
    @staticmethod
    def check_bedrock_connectivity(region: str, kb_id: str = None) -> Dict[str, Any]:
        """Check Bedrock service connectivity"""
        try:
            import boto3
            bedrock = boto3.client('bedrock', region_name=region)
            bedrock.list_foundation_models()
            
            if kb_id:
                bedrock_agent = boto3.client('bedrock-agent', region_name=region)
                bedrock_agent.get_knowledge_base(knowledgeBaseId=kb_id)
            
            return {'status': 'healthy', 'message': 'Bedrock connectivity OK'}
        except Exception as e:
            return {'status': 'unhealthy', 'message': f'Bedrock connectivity failed: {e}'}
    
    @staticmethod
    def get_system_health() -> Dict[str, Any]:
        """Get overall system health status"""
        checks = {
            'aws': HealthChecker.check_aws_connectivity(),
            'timestamp': datetime.now().isoformat()
        }
        
        overall_status = 'healthy' if all(
            check.get('status') == 'healthy' 
            for check in checks.values() 
            if isinstance(check, dict) and 'status' in check
        ) else 'unhealthy'
        
        return {
            'status': overall_status,
            'checks': checks
        }
