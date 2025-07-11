import boto3
import logging
import yaml
import os
import re
import subprocess
import shutil
import shlex
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class RemediationManager:
    """
    Manages automated remediation of security issues in EKS clusters
    """
    
    def __init__(self, aws_access_key: str, aws_secret_key: str, region: str):
        """
        Initialize the remediation manager
        
        Args:
            aws_access_key: AWS access key
            aws_secret_key: AWS secret key
            region: AWS region
        """
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self.region = region
        self.cluster_name = None  # Will be set during apply_remediation
        self.remediation_templates = self._load_remediation_templates()
        self.applied_remediations = []  # Track applied remediations
        
        # Initialize AWS clients
        self.eks_client = boto3.client(
            'eks',
            region_name=region,
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key
        )
        self.cloudformation_client = boto3.client(
            'cloudformation',
            region_name=region,
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key
        )
        self.kubectl_available = self._check_kubectl_availability()
    
    def _load_remediation_templates(self) -> Dict[str, Any]:
        """
        Load remediation templates from YAML files
        
        Returns:
            Dictionary of remediation templates
        """
        templates = {}
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        
        # Create templates directory if it doesn't exist
        if not os.path.exists(template_dir):
            os.makedirs(template_dir)
            self._create_default_templates(template_dir)
        
        # Load templates from files
        for filename in os.listdir(template_dir):
            if filename.endswith('.yaml') or filename.endswith('.yml'):
                try:
                    with open(os.path.join(template_dir, filename), 'r', encoding='utf-8') as file:
                        template = yaml.safe_load(file)
                        template_id = os.path.splitext(filename)[0]
                        templates[template_id] = template
                except Exception as e:
                    logger.error(f"Error loading template {filename}: {e}")
        
        return templates
    
    def _create_default_templates(self, template_dir: str):
        """
        Create default remediation templates
        
        Args:
            template_dir: Directory to store templates
        """
        # Template for enabling IRSA
        irsa_template = {
            'name': 'Enable IRSA',
            'description': 'Enable IAM Roles for Service Accounts',
            'check_id': 'IRSA Implementation',
            'remediation_type': 'cloudformation',
            'template': {
                'AWSTemplateFormatVersion': '2010-09-09',
                'Resources': {
                    'EKSOIDCProvider': {
                        'Type': 'AWS::IAM::OIDCProvider',
                        'Properties': {
                            'Url': '{{cluster.oidc_issuer_url}}',
                            'ClientIdList': ['sts.amazonaws.com'],
                            'ThumbprintList': ['9e99a48a9960b14926bb7f3b02e22da2b0ab7280']
                        }
                    }
                },
                'Outputs': {
                    'OIDCProviderARN': {
                        'Value': {'Fn::GetAtt': ['EKSOIDCProvider', 'Arn']}
                    }
                }
            }
        }
        
        # Template for enabling secrets encryption
        secrets_encryption_template = {
            'name': 'Enable Secrets Encryption',
            'description': 'Enable envelope encryption for Kubernetes secrets',
            'check_id': 'Secrets Encryption',
            'remediation_type': 'eks_api',
            'api_call': {
                'method': 'associate_encryption_config',
                'params': {
                    'clusterName': '{{cluster.name}}',
                    'encryptionConfig': [{
                        'resources': ['secrets'],
                        'provider': {
                            'keyArn': 'arn:aws:kms:{{region}}:{{aws_account_id}}:key/{{kms_key_id}}'
                        }
                    }]
                }
            }
        }
        
        # Template for enabling network policies
        network_policies_template = {
            'name': 'Enable Network Policies',
            'description': 'Install Calico for network policy enforcement',
            'check_id': 'Network Policies',
            'remediation_type': 'kubernetes',
            'manifest': '''
apiVersion: v1
kind: Namespace
metadata:
  name: calico-system
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: calico-node
  namespace: calico-system
  labels:
    k8s-app: calico-node
spec:
  selector:
    matchLabels:
      k8s-app: calico-node
  template:
    metadata:
      labels:
        k8s-app: calico-node
    spec:
      serviceAccountName: calico-node
      containers:
      - name: calico-node
        image: calico/node:v3.25.0
        env:
        - name: DATASTORE_TYPE
          value: "kubernetes"
        - name: FELIX_LOGSEVERITYSCREEN
          value: "info"
        - name: CALICO_NETWORKING_BACKEND
          value: "none"
        - name: CLUSTER_TYPE
          value: "k8s,ecs"
        - name: CALICO_DISABLE_FILE_LOGGING
          value: "true"
        - name: FELIX_TYPHAK8SSERVICENAME
          value: "calico-typha"
        - name: FELIX_DEFAULTENDPOINTTOHOSTACTION
          value: "ACCEPT"
        securityContext:
          privileged: true
        resources:
          requests:
            cpu: 250m
'''
        }
        
        # Template for enabling audit logging
        audit_logging_template = {
            'name': 'Enable Audit Logging',
            'description': 'Enable Kubernetes audit logging for the cluster',
            'check_id': 'Audit Logging',
            'remediation_type': 'eks_api',
            'api_call': {
                'method': 'update_cluster_config',
                'params': {
                    'name': '{{cluster.name}}',
                    'logging': {
                        'clusterLogging': [{
                            'types': [
                                'api',
                                'audit',
                                'authenticator',
                                'controllerManager',
                                'scheduler'
                            ],
                            'enabled': True
                        }]
                    }
                }
            }
        }
        
        # Template for enabling pod security standards
        pod_security_template = {
            'name': 'Enable Pod Security Standards',
            'description': 'Enable Pod Security Standards for the cluster',
            'check_id': 'Pod Security Standards',
            'remediation_type': 'kubernetes',
            'manifest': '''
apiVersion: v1
kind: Namespace
metadata:
  name: default
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
apiVersion: v1
kind: Namespace
metadata:
  name: kube-system
  labels:
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/audit: baseline
    pod-security.kubernetes.io/warn: baseline
'''
        }
        
        # Template for updating VPC CNI
        vpc_cni_template = {
            'name': 'Update VPC CNI Plugin',
            'description': 'Update the VPC CNI plugin to the latest version',
            'check_id': 'VPC CNI Version',
            'remediation_type': 'eks_api',
            'api_call': {
                'method': 'update_addon',
                'params': {
                    'clusterName': '{{cluster.name}}',
                    'addonName': 'vpc-cni',
                    'addonVersion': 'latest',
                    'resolveConflicts': 'OVERWRITE'
                }
            }
        }
        
        # Write templates to files
        with open(os.path.join(template_dir, 'irsa.yaml'), 'w', encoding='utf-8') as file:
            yaml.dump(irsa_template, file)
        
        with open(os.path.join(template_dir, 'secrets_encryption.yaml'), 'w', encoding='utf-8') as file:
            yaml.dump(secrets_encryption_template, file)
        
        with open(os.path.join(template_dir, 'network_policies.yaml'), 'w', encoding='utf-8') as file:
            yaml.dump(network_policies_template, file)
            
        with open(os.path.join(template_dir, 'audit_logging.yaml'), 'w', encoding='utf-8') as file:
            yaml.dump(audit_logging_template, file)
            
        with open(os.path.join(template_dir, 'pod_security.yaml'), 'w', encoding='utf-8') as file:
            yaml.dump(pod_security_template, file)
            
        with open(os.path.join(template_dir, 'vpc_cni.yaml'), 'w', encoding='utf-8') as file:
            yaml.dump(vpc_cni_template, file)
    
    def _check_kubectl_availability(self) -> bool:
        """
        Check if kubectl is available
        
        Returns:
            True if kubectl is available, False otherwise
        """
        try:
            # Find kubectl in common installation paths
            kubectl_paths = [
                "/usr/local/bin/kubectl",
                "/usr/bin/kubectl",
                "/bin/kubectl"
            ]
            
            kubectl_cmd = None
            for path in kubectl_paths:
                if os.path.exists(path) and os.access(path, os.X_OK):
                    kubectl_cmd = path
                    break
            
            # If not found in common paths, try PATH
            if not kubectl_cmd:
                kubectl_cmd = shutil.which("kubectl")
                if not kubectl_cmd:
                    logger.warning("kubectl not found in PATH or common locations")
                    return False
            
            # Run kubectl version with timeout
            result = subprocess.run(["kubectl", "version", "--client"], 
                                   capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            logger.error("Timeout while checking kubectl availability")
            return False
        except Exception as e:
            logger.error(f"Error checking kubectl availability: {e}")
            return False
    
    def get_available_remediations(self, failed_checks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Get available remediation actions for failed checks
        
        Args:
            failed_checks: List of failed security checks
            
        Returns:
            List of available remediation actions
        """
        # Define default remediations
        default_remediations = [
            {
                'check_id': 'IRSA Implementation',
                'template_id': 'irsa',
                'name': 'Enable IRSA',
                'description': 'Enable IAM Roles for Service Accounts',
                'remediation_type': 'cloudformation'
            },
            {
                'check_id': 'Secrets Encryption',
                'template_id': 'secrets_encryption',
                'name': 'Enable Secrets Encryption',
                'description': 'Enable envelope encryption for Kubernetes secrets',
                'remediation_type': 'eks_api'
            },
            {
                'check_id': 'Network Policies',
                'template_id': 'network_policies',
                'name': 'Enable Network Policies',
                'description': 'Install Calico for network policy enforcement',
                'remediation_type': 'kubernetes'
            },
            {
                'check_id': 'VPC CNI Version',
                'template_id': 'vpc_cni',
                'name': 'Update VPC CNI Plugin',
                'description': 'Update the VPC CNI plugin to the latest version',
                'remediation_type': 'eks_api'
            },
            {
                'check_id': 'Audit Logging',
                'template_id': 'audit_logging',
                'name': 'Enable Audit Logging',
                'description': 'Enable Kubernetes audit logging for the cluster',
                'remediation_type': 'eks_api'
            },
            {
                'check_id': 'Pod Security Standards',
                'template_id': 'pod_security',
                'name': 'Enable Pod Security Standards',
                'description': 'Enable Pod Security Standards for the cluster',
                'remediation_type': 'kubernetes'
            }
        ]
        
        # Filter out already applied remediations
        available_remediations = [r for r in default_remediations if r['template_id'] not in self.applied_remediations]
        
        # Filter for failed checks
        if failed_checks:
            failed_check_ids = [check.get('check') for check in failed_checks]
            available_remediations = [r for r in available_remediations if r['check_id'] in failed_check_ids]
        
        return available_remediations
    
    def apply_remediation(self, cluster_name: str, template_id: str, parameters: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Apply a remediation action
        
        Args:
            cluster_name: Name of the EKS cluster
            template_id: ID of the remediation template to apply
            parameters: Additional parameters for the remediation
            
        Returns:
            Result of the remediation action
        """
        # Validate inputs
        if not self._is_valid_cluster_name(cluster_name):
            return {
                'success': False,
                'message': "Invalid cluster name format"
            }
            
        if not self._is_valid_template_id(template_id):
            return {
                'success': False,
                'message': "Invalid template ID format"
            }
        
        # Store cluster name for later use
        self.cluster_name = cluster_name
        
        if template_id not in self.remediation_templates:
            return {
                'success': False,
                'message': f"Remediation template {template_id} not found"
            }
        
        template = self.remediation_templates[template_id]
        remediation_type = template.get('remediation_type')
        
        # Apply remediation based on type
        try:
            if remediation_type == 'kubernetes':
                result = self._apply_kubernetes_remediation(template, parameters)
            elif remediation_type == 'eks_api':
                result = self._apply_eks_api_remediation(template, parameters)
            elif remediation_type == 'cloudformation':
                result = self._apply_cloudformation_remediation(template, parameters)
            else:
                return {
                    'success': False,
                    'message': f"Unsupported remediation type: {remediation_type}"
                }
                
            # If successful, add to applied remediations
            if result['success']:
                self.applied_remediations.append(template_id)
                
            return result
        except Exception as e:
            logger.error(f"Error applying remediation {template_id}: {e}")
            return {
                'success': False,
                'message': f"Error applying remediation: {str(e)}"
            }
    
    def _is_valid_cluster_name(self, name: str) -> bool:
        """
        Validate cluster name to prevent injection
        
        Args:
            name: Cluster name to validate
            
        Returns:
            True if valid, False otherwise
        """
        # EKS cluster names must be alphanumeric with hyphens and start with letter
        return bool(name and re.match(r'^[a-zA-Z][-a-zA-Z0-9]{1,99}$', name))
    
    def _is_valid_template_id(self, template_id: str) -> bool:
        """
        Validate template ID to prevent injection
        
        Args:
            template_id: Template ID to validate
            
        Returns:
            True if valid, False otherwise
        """
        # Template IDs should be alphanumeric with underscores
        return bool(template_id and re.match(r'^[a-zA-Z0-9_]{1,64}$', template_id))
    
    def _apply_kubernetes_remediation(self, template: Dict[str, Any], parameters: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Apply Kubernetes manifest remediation
        
        Args:
            template: Remediation template
            parameters: Additional parameters
            
        Returns:
            Result of the remediation
        """
        if not self.kubectl_available:
            return {
                'success': False,
                'message': "kubectl not available"
            }
            
        manifest = template.get('manifest')
        if not manifest:
            return {
                'success': False,
                'message': "No manifest provided in template"
            }
            
        # Replace parameters in manifest
        if parameters:
            for key, value in parameters.items():
                manifest = manifest.replace(f"{{{{{key}}}}}", str(value))
                
        # Apply manifest using kubectl
        try:
            # Find kubectl in common installation paths
            kubectl_paths = [
                "/usr/local/bin/kubectl",
                "/usr/bin/kubectl",
                "/bin/kubectl"
            ]
            
            kubectl_cmd = None
            for path in kubectl_paths:
                if os.path.exists(path) and os.access(path, os.X_OK):
                    kubectl_cmd = path
                    break
            
            # If not found in common paths, try PATH
            if not kubectl_cmd:
                kubectl_cmd = shutil.which("kubectl")
                if not kubectl_cmd:
                    return {
                        'success': False,
                        'message': "kubectl not found"
                    }
            
            # Write manifest to temporary file
            import tempfile
            with tempfile.NamedTemporaryFile(suffix='.yaml', delete=False, mode='w') as temp_file:
                temp_file.write(manifest)
                temp_file.flush()
                temp_file_path = temp_file.name
                
            # Set secure permissions
            os.chmod(temp_file_path, 0o600)
            
            # Apply manifest
            result = subprocess.run(["kubectl", "apply", "-f", temp_file_path], capture_output=True, text=True, timeout=60)
            
            # Clean up temporary file
            try:
                os.unlink(temp_file_path)
            except Exception as e:
                logger.warning(f"Failed to remove temporary file {temp_file_path}: {e}")
            
            if result.returncode != 0:
                return {
                    'success': False,
                    'message': f"Failed to apply manifest: {result.stderr}"
                }
                
            return {
                'success': True,
                'message': f"Successfully applied {template.get('name')}",
                'details': result.stdout
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'message': "Timeout while applying manifest"
            }
        except Exception as e:
            logger.error(f"Error applying manifest: {e}")
            return {
                'success': False,
                'message': f"Error applying manifest: {str(e)}"
            }
    
    def _apply_eks_api_remediation(self, template: Dict[str, Any], parameters: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Apply EKS API remediation
        
        Args:
            template: Remediation template
            parameters: Additional parameters
            
        Returns:
            Result of the remediation
        """
        api_call = template.get('api_call')
        if not api_call:
            return {
                'success': False,
                'message': "No API call provided in template"
            }
            
        method = api_call.get('method')
        params = api_call.get('params', {})
        
        # Replace parameters in params
        if parameters:
            import json
            params_str = json.dumps(params)
            for key, value in parameters.items():
                params_str = params_str.replace(f"{{{{{key}}}}}", str(value))
            params = json.loads(params_str)
            
        # Replace cluster name
        if 'clusterName' in params:
            params['clusterName'] = self.cluster_name
        elif 'name' in params:
            params['name'] = self.cluster_name
            
        # Call EKS API
        try:
            if not hasattr(self.eks_client, method):
                return {
                    'success': False,
                    'message': f"Method {method} not found in EKS client"
                }
                
            response = getattr(self.eks_client, method)(**params)
            
            return {
                'success': True,
                'message': f"Successfully applied {template.get('name')}",
                'details': str(response)
            }
        except Exception as e:
            logger.error(f"Error calling EKS API: {e}")
            return {
                'success': False,
                'message': f"Error calling EKS API: {str(e)}"
            }
    
    def _apply_cloudformation_remediation(self, template: Dict[str, Any], parameters: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Apply CloudFormation remediation
        
        Args:
            template: Remediation template
            parameters: Additional parameters
            
        Returns:
            Result of the remediation
        """
        cf_template = template.get('template')
        if not cf_template:
            return {
                'success': False,
                'message': "No CloudFormation template provided"
            }
            
        # Replace parameters in template
        import json
        template_str = json.dumps(cf_template)
        
        # Get cluster details for parameter replacement
        try:
            cluster = self.eks_client.describe_cluster(name=self.cluster_name)['cluster']
            
            # Replace cluster parameters
            template_str = template_str.replace("{{cluster.name}}", self.cluster_name)
            template_str = template_str.replace("{{cluster.oidc_issuer_url}}", cluster.get('identity', {}).get('oidc', {}).get('issuer', ''))
            template_str = template_str.replace("{{region}}", self.region)
            
            # Replace additional parameters
            if parameters:
                for key, value in parameters.items():
                    template_str = template_str.replace(f"{{{{{key}}}}}", str(value))
                    
            cf_template = json.loads(template_str)
            
            # Create CloudFormation stack
            stack_name = f"{self.cluster_name}-{template.get('name', 'remediation').replace(' ', '-').lower()}"
            
            response = self.cloudformation_client.create_stack(
                StackName=stack_name,
                TemplateBody=json.dumps(cf_template),
                Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM'],
                OnFailure='DELETE'
            )
            
            return {
                'success': True,
                'message': f"Successfully initiated {template.get('name')}",
                'details': f"CloudFormation stack {stack_name} creation initiated"
            }
        except Exception as e:
            logger.error(f"Error applying CloudFormation remediation: {e}")
            return {
                'success': False,
                'message': f"Error applying CloudFormation remediation: {str(e)}"
            }