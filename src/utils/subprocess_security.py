"""
Secure subprocess utilities with static command execution
"""
import subprocess  # nosec B404 - subprocess usage is secured with static validation
import shlex
import logging
from typing import List, Optional, Tuple, Dict, Any

logger = logging.getLogger(__name__)

def secure_subprocess_run(cmd: List[str], **kwargs) -> subprocess.CompletedProcess:
    """Securely run subprocess with completely static command mapping"""
    # Ensure cmd is a list
    if not isinstance(cmd, list) or len(cmd) < 2:
        raise ValueError("Command must be a list with at least 2 elements")
    
    # Map to static commands only - no dynamic construction
    cmd_key = tuple(cmd[:2])  # Use first two elements as key
    
    # Set secure defaults
    secure_kwargs = {
        'shell': False,  # Never use shell=True
        'capture_output': True,
        'text': True,
        'timeout': 30,  # Default timeout
        'check': False,  # Don't raise on non-zero exit
        **kwargs
    }
    
    logger.info(f"Executing static command: {cmd[0]} {cmd[1]}")
    
    # Execute only pre-approved static commands
    if cmd_key == ('kubectl', 'version'):
        return subprocess.run(['kubectl', 'version', '--client'], **secure_kwargs)  # nosec B603 B607 - static command
    elif cmd_key == ('kubectl', 'apply') and len(cmd) >= 4 and cmd[2] == '-f':
        # Validate file path is safe (no shell metacharacters)
        file_path = cmd[3]
        if not _is_safe_file_path(file_path):
            raise ValueError(f"Unsafe file path: {file_path}")
        return subprocess.run(['kubectl', 'apply', '-f', file_path], **secure_kwargs)  # nosec B603 B607 - static command with validated path
    elif cmd_key == ('aws', 'eks') and len(cmd) >= 6:
        if cmd[2] == 'update-kubeconfig' and cmd[3] == '--name' and cmd[5] == '--region':
            cluster_name = _sanitize_cluster_name(cmd[4])
            region = _sanitize_region(cmd[6])
            return subprocess.run(['aws', 'eks', 'update-kubeconfig', '--name', cluster_name, '--region', region], **secure_kwargs)  # nosec B603 B607 - static command with sanitized args
    elif cmd_key == ('aws', 'sts') and len(cmd) == 3 and cmd[2] == 'get-caller-identity':
        return subprocess.run(['aws', 'sts', 'get-caller-identity'], **secure_kwargs)  # nosec B603 B607 - static command
    
    # If no static mapping found, reject
    raise ValueError(f"Command not in static allowlist: {cmd_key}")

def _is_safe_file_path(path: str) -> bool:
    """Validate file path contains no shell metacharacters"""
    import os
    import tempfile
    
    # Check for dangerous characters
    dangerous_chars = ['&', '|', ';', '$', '`', '(', ')', '<', '>', '"', "'", '\\', '\n', '\r']
    if any(char in path for char in dangerous_chars):
        return False
    
    # Only allow files in secure temp directory or current directory
    secure_temp_dir = tempfile.gettempdir()  # nosec B108 - using system temp dir securely
    abs_path = os.path.abspath(path)
    secure_temp_abs = os.path.abspath(secure_temp_dir)
    current_dir_abs = os.path.abspath('.')
    
    return (abs_path.startswith(secure_temp_abs) or 
            abs_path.startswith(current_dir_abs)) and '..' not in path

def _sanitize_cluster_name(name: str) -> str:
    """Sanitize cluster name to alphanumeric and hyphens only"""
    import re
    if not re.match(r'^[a-zA-Z0-9-]+$', name):
        raise ValueError(f"Invalid cluster name: {name}")
    return name

def _sanitize_region(region: str) -> str:
    """Sanitize AWS region to valid format"""
    import re
    if not re.match(r'^[a-z0-9-]+$', region):
        raise ValueError(f"Invalid region: {region}")
    return region
