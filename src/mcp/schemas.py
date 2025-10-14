"""
Model Context Protocol (MCP) schemas for EKS Operational Review Agent
"""

class MCPSchemas:
    """
    Defines schemas for Model Context Protocol integration
    """
    
    # Schema for EKS cluster context
    CLUSTER_CONTEXT = {
        "title": "EKSClusterContext",
        "description": "Context about an EKS cluster configuration",
        "type": "object",
        "properties": {
            "cluster_name": {"type": "string"},
            "kubernetes_version": {"type": "string"},
            "region": {"type": "string"},
            "networking": {
                "type": "object",
                "properties": {
                    "vpc_id": {"type": "string"},
                    "endpoint_public_access": {"type": "boolean"},
                    "endpoint_private_access": {"type": "boolean"},
                    "network_policies_enabled": {"type": "boolean"},
                    "custom_networking_enabled": {"type": "boolean"}
                }
            },
            "security": {
                "type": "object",
                "properties": {
                    "secrets_encryption": {"type": "boolean"},
                    "oidc_provider": {"type": "boolean"},
                    "audit_logging": {"type": "boolean"}
                }
            },
            "nodegroups": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "capacity_type": {"type": "string"},
                        "instance_type": {"type": "string"},
                        "availability_zones": {"type": "array", "items": {"type": "string"}}
                    }
                }
            },
            "addons": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "version": {"type": "string"}
                    }
                }
            }
        }
    }
    
    # Schema for recommendations
    RECOMMENDATION = {
        "title": "EKSRecommendation",
        "description": "A recommendation for improving an EKS cluster",
        "type": "object",
        "properties": {
            "category": {"type": "string"},
            "title": {"type": "string"},
            "description": {"type": "string"},
            "impact": {"type": "string"},
            "priority": {"type": "string", "enum": ["High", "Medium", "Low"]},
            "action_items": {"type": "array", "items": {"type": "string"}},
            "reference": {"type": "string"},
            "reasoning": {"type": "string"}
        },
        "required": ["category", "title", "description", "impact", "priority", "action_items"]
    }