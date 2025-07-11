"""
Security configuration and utilities for the EKS Operational Review Agent.
This module centralizes security settings and provides utilities for secure operations.
"""

import os
import re
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class SecurityConfig:
    """Centralized security configuration and utilities."""
    
    # Security constants
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    MAX_LOG_LENGTH = 200
    MAX_INPUT_LENGTH = 4000
    ALLOWED_FILE_EXTENSIONS = {'.pdf', '.txt', '.json', '.yaml', '.yml'}
    
    # Regex patterns for validation
    AWS_REGION_PATTERN = re.compile(r'^[a-z]{2}-[a-z]+-\d{1,2}$')
    CLUSTER_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\-_]*[a-zA-Z0-9]$')
    
    @staticmethod
    def sanitize_log_input(text: str) -> str:
        """
        Sanitize input for logging to prevent log injection.
        
        Args:
            text: Input text to sanitize
            
        Returns:
            Sanitized text safe for logging
        """
        if not isinstance(text, str):
            text = str(text)
        
        # Remove newlines and control characters
        sanitized = re.sub(r'[\r\n\t\x00-\x1f\x7f-\x9f]', '', text)
        
        # Limit length
        return sanitized[:SecurityConfig.MAX_LOG_LENGTH]
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Sanitize filename to prevent path traversal attacks.
        
        Args:
            filename: Original filename
            
        Returns:
            Sanitized filename
        """
        if not isinstance(filename, str):
            filename = str(filename)
        
        # Remove path separators and dangerous characters
        sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', filename)
        
        # Limit length and remove leading/trailing dots and spaces
        sanitized = sanitized.strip('. ')[:50]
        
        return sanitized if sanitized else 'unknown'
    
    @staticmethod
    def validate_aws_region(region: str) -> bool:
        """
        Validate AWS region format.
        
        Args:
            region: AWS region string
            
        Returns:
            True if valid, False otherwise
        """
        if not isinstance(region, str):
            return False
        
        return bool(SecurityConfig.AWS_REGION_PATTERN.match(region))
    
    @staticmethod
    def validate_cluster_name(cluster_name: str) -> bool:
        """
        Validate EKS cluster name format.
        
        Args:
            cluster_name: Cluster name to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not isinstance(cluster_name, str):
            return False
        
        # Check length (1-100 characters)
        if not (1 <= len(cluster_name) <= 100):
            return False
        
        return bool(SecurityConfig.CLUSTER_NAME_PATTERN.match(cluster_name))
    
    @staticmethod
    def secure_filepath(directory: str, filename: str) -> Path:
        """
        Create a secure filepath preventing directory traversal.
        
        Args:
            directory: Base directory
            filename: Filename
            
        Returns:
            Secure Path object
            
        Raises:
            ValueError: If path is invalid or potential traversal detected
        """
        # Convert to Path objects for secure handling
        base_dir = Path(directory).resolve()
        file_path = base_dir / SecurityConfig.sanitize_filename(filename)
        
        # Ensure the resolved path is within the base directory
        try:
            file_path.resolve().relative_to(base_dir)
        except ValueError:
            raise ValueError("Invalid file path - potential directory traversal")
        
        return file_path
    
    @staticmethod
    def validate_file_extension(filename: str) -> bool:
        """
        Validate file extension against allowed list.
        
        Args:
            filename: Filename to check
            
        Returns:
            True if extension is allowed, False otherwise
        """
        if not isinstance(filename, str):
            return False
        
        file_ext = Path(filename).suffix.lower()
        return file_ext in SecurityConfig.ALLOWED_FILE_EXTENSIONS
    
    @staticmethod
    def sanitize_input_text(text: str, max_length: Optional[int] = None) -> str:
        """
        Sanitize user input text.
        
        Args:
            text: Input text to sanitize
            max_length: Maximum allowed length (default: MAX_INPUT_LENGTH)
            
        Returns:
            Sanitized text
        """
        if not isinstance(text, str):
            text = str(text)
        
        # Use default max length if not specified
        if max_length is None:
            max_length = SecurityConfig.MAX_INPUT_LENGTH
        
        # Strip and limit length
        sanitized = text.strip()[:max_length]
        
        return sanitized
    
    @staticmethod
    def validate_url(url: str, allowed_domains: Optional[List[str]] = None) -> bool:
        """
        Validate URL to prevent SSRF attacks.
        
        Args:
            url: URL to validate
            allowed_domains: List of allowed domains (default: AWS domains)
            
        Returns:
            True if URL is valid and safe, False otherwise
        """
        try:
            from urllib.parse import urlparse
            
            parsed = urlparse(url)
            
            # Only allow HTTPS URLs
            if parsed.scheme != 'https':
                return False
            
            # Default to AWS domains if not specified
            if allowed_domains is None:
                allowed_domains = ['.amazonaws.com', '.aws.amazon.com']
            
            # Check if domain is in allowed list
            return any(parsed.netloc.endswith(domain) for domain in allowed_domains)
            
        except Exception:
            return False
    
    @staticmethod
    def get_secure_temp_dir() -> Path:
        """
        Get a secure temporary directory.
        
        Returns:
            Path to secure temporary directory
        """
        import tempfile
        
        # Create secure temporary directory
        temp_dir = Path(tempfile.mkdtemp(prefix='eks_review_'))
        
        # Set restrictive permissions (owner only)
        temp_dir.chmod(0o700)
        
        return temp_dir
    
    @staticmethod
    def validate_json_input(json_str: str, max_size: Optional[int] = None) -> bool:
        """
        Validate JSON input for security.
        
        Args:
            json_str: JSON string to validate
            max_size: Maximum allowed size in bytes
            
        Returns:
            True if valid, False otherwise
        """
        if not isinstance(json_str, str):
            return False
        
        # Check size
        if max_size is None:
            max_size = SecurityConfig.MAX_FILE_SIZE
        
        if len(json_str.encode('utf-8')) > max_size:
            return False
        
        # Try to parse JSON
        try:
            import json
            json.loads(json_str)
            return True
        except (json.JSONDecodeError, ValueError):
            return False
    
    @staticmethod
    def mask_sensitive_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Mask sensitive data in dictionaries for logging.
        
        Args:
            data: Dictionary containing potentially sensitive data
            
        Returns:
            Dictionary with sensitive values masked
        """
        sensitive_keys = {
            'password', 'secret', 'key', 'token', 'credential',
            'access_key', 'secret_key', 'api_key', 'auth'
        }
        
        masked_data = {}
        
        for key, value in data.items():
            key_lower = key.lower()
            
            # Check if key contains sensitive information
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                masked_data[key] = '***MASKED***'
            elif isinstance(value, dict):
                # Recursively mask nested dictionaries
                masked_data[key] = SecurityConfig.mask_sensitive_data(value)
            elif isinstance(value, list):
                # Handle lists that might contain dictionaries
                masked_list = []
                for item in value:
                    if isinstance(item, dict):
                        masked_list.append(SecurityConfig.mask_sensitive_data(item))
                    else:
                        masked_list.append(item)
                masked_data[key] = masked_list
            else:
                masked_data[key] = value
        
        return masked_data

class SecureLogger:
    """Secure logging wrapper that automatically sanitizes inputs."""
    
    def __init__(self, logger_name: str):
        self.logger = logging.getLogger(logger_name)
    
    def info(self, message: str, *args, **kwargs):
        """Log info message with sanitization."""
        sanitized_message = SecurityConfig.sanitize_log_input(message)
        self.logger.info(sanitized_message, *args, **kwargs)
    
    def warning(self, message: str, *args, **kwargs):
        """Log warning message with sanitization."""
        sanitized_message = SecurityConfig.sanitize_log_input(message)
        self.logger.warning(sanitized_message, *args, **kwargs)
    
    def error(self, message: str, *args, **kwargs):
        """Log error message with sanitization."""
        sanitized_message = SecurityConfig.sanitize_log_input(message)
        self.logger.error(sanitized_message, *args, **kwargs)
    
    def debug(self, message: str, *args, **kwargs):
        """Log debug message with sanitization."""
        sanitized_message = SecurityConfig.sanitize_log_input(message)
        self.logger.debug(sanitized_message, *args, **kwargs)

# Environment variable validation
def get_secure_env_var(var_name: str, default: Optional[str] = None, required: bool = False) -> Optional[str]:
    """
    Securely get environment variable with validation.
    
    Args:
        var_name: Environment variable name
        default: Default value if not found
        required: Whether the variable is required
        
    Returns:
        Environment variable value or default
        
    Raises:
        ValueError: If required variable is missing
    """
    value = os.getenv(var_name, default)
    
    if required and value is None:
        raise ValueError(f"Required environment variable {var_name} is not set")
    
    if value is not None:
        # Sanitize the value
        value = SecurityConfig.sanitize_input_text(value)
    
    return value