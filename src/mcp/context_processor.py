"""
Model Context Protocol (MCP) context processor for EKS Operational Review Agent
"""
import json
from typing import Dict, Any, List

class MCPContextProcessor:
    """
    Processes and formats context for Model Context Protocol
    """
    
    @staticmethod
    def format_context(cluster_context: Dict[str, Any], recommendations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Format cluster context and recommendations for MCP
        
        Args:
            cluster_context: Structured cluster context
            recommendations: List of recommendations
            
        Returns:
            Formatted MCP context
        """
        return {
            "cluster": cluster_context,
            "recommendations": recommendations,
            "metadata": {
                "version": "1.0",
                "format": "eks-operational-review"
            }
        }
    
    @staticmethod
    def to_json(context: Dict[str, Any]) -> str:
        """
        Convert context to JSON string
        
        Args:
            context: MCP context
            
        Returns:
            JSON string representation
        """
        return json.dumps(context, indent=2)
    
    @staticmethod
    def extract_reasoning(recommendation: Dict[str, Any]) -> str:
        """
        Extract or generate reasoning for a recommendation
        
        Args:
            recommendation: Recommendation dictionary
            
        Returns:
            Reasoning string
        """
        if "reasoning" in recommendation:
            return recommendation["reasoning"]
        
        # Generate reasoning if not provided
        reasoning = f"Based on the analysis of the cluster configuration, {recommendation['title'].lower()} "
        reasoning += f"which has a {recommendation['impact'].lower()}. "
        reasoning += "This recommendation is provided to help improve the cluster's "
        
        category = recommendation.get("category", "").lower()
        if "security" in category:
            reasoning += "security posture."
        elif "networking" in category:
            reasoning += "network configuration and performance."
        elif "cost" in category:
            reasoning += "cost efficiency."
        elif "reliability" in category:
            reasoning += "reliability and availability."
        elif "performance" in category:
            reasoning += "performance and scalability."
        elif "operations" in category:
            reasoning += "operational excellence."
        elif "compliance" in category:
            reasoning += "compliance with best practices."
        else:
            reasoning += "overall health and configuration."
            
        return reasoning