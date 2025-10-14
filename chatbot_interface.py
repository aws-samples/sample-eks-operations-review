import streamlit as st
import json
from datetime import datetime

class EKSChatbot:
    def __init__(self, analysis_data):
        self.analysis_data = analysis_data
        self.conversation_history = []
    
    def process_query(self, user_query):
        """Process user query and generate response"""
        query_lower = user_query.lower()
        
        # Security-related queries
        if any(word in query_lower for word in ['security', 'vulnerability', 'risk', 'encryption', 'logging']):
            return self._handle_security_query(user_query)
        
        # Infrastructure queries
        elif any(word in query_lower for word in ['node', 'infrastructure', 'capacity', 'resource']):
            return self._handle_infrastructure_query(user_query)
        
        # Add-on queries
        elif any(word in query_lower for word in ['addon', 'add-on', 'degraded', 'coredns', 'ebs', 'metrics']):
            return self._handle_addon_query(user_query)
        
        # Cost queries
        elif any(word in query_lower for word in ['cost', 'money', 'savings', 'spot', 'optimization']):
            return self._handle_cost_query(user_query)
        
        # Network queries
        elif any(word in query_lower for word in ['network', 'vpc', 'subnet', 'endpoint', 'cidr']):
            return self._handle_network_query(user_query)
        
        # Pod/workload queries
        elif any(word in query_lower for word in ['pod', 'pending', 'workload', 'deployment', 'namespace']):
            return self._handle_workload_query(user_query)
        
        # Summary/report queries
        elif any(word in query_lower for word in ['summary', 'report', 'overview', 'status', 'health']):
            return self._handle_summary_query(user_query)
        
        # Recommendation queries
        elif any(word in query_lower for word in ['recommend', 'fix', 'improve', 'action', 'priority']):
            return self._handle_recommendation_query(user_query)
        
        else:
            return self._handle_general_query(user_query)
    
    def _handle_security_query(self, query):
        """Handle security-related queries"""
        security_data = self.analysis_data.get('security_domains', {})
        health_data = self.analysis_data.get('health_data', {})
        
        response = "🔒 **Security Analysis Summary:**\n\n"
        
        if 'error' not in security_data:
            security_score = health_data.get('security_analysis', {}).get('security_score', 0)
            response += f"**Current Security Score:** {security_score}/100\n\n"
            
            high_priority = security_data.get('high_priority', 0)
            medium_priority = security_data.get('medium_priority', 0)
            
            response += f"**Critical Issues:** {high_priority} high-priority, {medium_priority} medium-priority\n\n"
            
            response += "**Key Security Issues:**\n"
            
            # Get specific security issues
            domains = security_data.get('domains', {})
            for domain_name, findings in domains.items():
                if findings:
                    domain_display = domain_name.replace('_', ' ').title()
                    response += f"\n**{domain_display}:**\n"
                    for finding in findings[:2]:  # Show top 2 issues per domain
                        priority_icon = "🔴" if finding.get('priority') == 'HIGH' else "🟡"
                        response += f"{priority_icon} {finding.get('issue', 'Unknown issue')}\n"
            
            response += "\n**Immediate Actions Required:**\n"
            response += "• Enable secrets encryption with AWS KMS\n"
            response += "• Configure comprehensive audit logging\n"
            response += "• Restrict API endpoint access from 0.0.0.0/0\n"
            response += "• Enable private endpoint access\n"
        
        return response
    
    def _handle_infrastructure_query(self, query):
        """Handle infrastructure-related queries"""
        aws_data = self.analysis_data.get('aws_inspection', {})
        k8s_data = self.analysis_data.get('k8s_data', {})
        
        response = "🏗️ **Infrastructure Analysis:**\n\n"
        
        # Cluster overview
        cluster_info = aws_data.get('cluster_overview', {})
        if 'error' not in cluster_info:
            response += f"**Cluster:** {cluster_info.get('name', 'N/A')}\n"
            response += f"**Status:** {cluster_info.get('status', 'N/A')}\n"
            response += f"**Kubernetes Version:** {cluster_info.get('version', 'N/A')}\n\n"
        
        # Node information
        nodes = aws_data.get('nodes', [])
        if nodes and 'error' not in nodes:
            response += f"**Nodes:** {len(nodes)} total\n"
            for i, node in enumerate(nodes[:3]):  # Show first 3 nodes
                response += f"• Node {i+1}: {node.get('instance_type', 'N/A')} - {node.get('state', 'N/A')}\n"
        
        # Kubernetes nodes
        if 'error' not in k8s_data.get('nodes_k8s', {}):
            k8s_nodes = k8s_data.get('nodes_k8s', [])
            if k8s_nodes:
                response += f"\n**Node Capacity:**\n"
                for node in k8s_nodes[:2]:  # Show first 2 nodes
                    response += f"• {node.get('name', 'Unknown')}: {node.get('capacity', {}).get('cpu', 'N/A')} CPU, {node.get('capacity', {}).get('memory', 'N/A')} Memory\n"
        
        # Resource issues
        response += "\n**Resource Issues:**\n"
        if 'error' not in k8s_data.get('pods', {}):
            pending_pods = len([p for p in k8s_data.get('pods', []) if p.get('status') == 'Pending'])
            if pending_pods > 0:
                response += f"🔴 {pending_pods} pods unable to schedule due to resource constraints\n"
        
        return response
    
    def _handle_addon_query(self, query):
        """Handle add-on related queries"""
        addon_data = self.analysis_data.get('health_data', {}).get('addon_deep_analysis', {})
        
        response = "🔌 **Add-on Health Analysis:**\n\n"
        
        if 'error' not in addon_data:
            total_addons = addon_data.get('total_addons', 0)
            healthy_addons = addon_data.get('healthy_addons', 0)
            degraded_addons = addon_data.get('degraded_addons', 0)
            
            response += f"**Total Add-ons:** {total_addons}\n"
            response += f"**Healthy:** {healthy_addons}\n"
            response += f"**Degraded:** {degraded_addons}\n\n"
            
            if addon_data.get('critical_issues'):
                response += "**Critical Issues:**\n"
                for issue in addon_data['critical_issues']:
                    response += f"🔴 {issue}\n"
            
            response += "\n**Root Cause:** Resource constraints preventing pod scheduling\n"
            response += "**Solution:** Increase node capacity or optimize resource requests\n"
        
        return response
    
    def _handle_cost_query(self, query):
        """Handle cost-related queries"""
        cost_data = self.analysis_data.get('cost_analysis', {})
        
        response = "💰 **Cost Optimization Analysis:**\n\n"
        
        if 'error' not in cost_data:
            cost_score = cost_data.get('cost_optimization_score', 0)
            spot_usage = cost_data.get('spot_usage_percent', 0)
            
            response += f"**Cost Optimization Score:** {cost_score:.0f}/100\n"
            response += f"**Current Spot Usage:** {spot_usage:.1f}%\n\n"
            
            if cost_data.get('savings_opportunities'):
                response += "**Savings Opportunities:**\n"
                for opportunity in cost_data['savings_opportunities'][:3]:
                    response += f"💡 {opportunity}\n"
            
            response += "\n**Potential Savings:**\n"
            response += "• Spot instances: 60-90% cost reduction\n"
            response += "• Right-sizing: 20-30% cost reduction\n"
            response += "• Reserved instances: 30-60% cost reduction\n"
        
        return response
    
    def _handle_network_query(self, query):
        """Handle network-related queries"""
        network_data = self.analysis_data.get('health_data', {}).get('network_analysis', {})
        
        response = "🌐 **Network Configuration Analysis:**\n\n"
        
        if 'error' not in network_data:
            response += f"**VPC CIDR:** {network_data.get('vpc_cidr', 'N/A')}\n"
            response += f"**Total IPs:** {network_data.get('total_vpc_ips', 'N/A'):,}\n"
            response += f"**IP Exhaustion Risk:** {network_data.get('ip_exhaustion_risk', 'N/A')}\n\n"
            
            if network_data.get('network_issues'):
                response += "**Network Security Issues:**\n"
                for issue in network_data['network_issues']:
                    response += f"🔴 {issue}\n"
            
            response += "\n**Subnet Utilization:**\n"
            subnets = network_data.get('subnets', [])
            for subnet in subnets[:3]:  # Show first 3 subnets
                response += f"• {subnet.get('subnet_id', 'N/A')}: {subnet.get('utilization_percent', 0):.1f}% used\n"
        
        return response
    
    def _handle_workload_query(self, query):
        """Handle workload-related queries"""
        k8s_data = self.analysis_data.get('k8s_data', {})
        
        response = "☸️ **Workload Analysis:**\n\n"
        
        # Pods analysis
        if 'error' not in k8s_data.get('pods', {}):
            pods = k8s_data.get('pods', [])
            running_pods = len([p for p in pods if p.get('status') == 'Running'])
            pending_pods = len([p for p in pods if p.get('status') == 'Pending'])
            failed_pods = len([p for p in pods if p.get('status') == 'Failed'])
            
            response += f"**Pods:** {len(pods)} total\n"
            response += f"• Running: {running_pods}\n"
            response += f"• Pending: {pending_pods}\n"
            response += f"• Failed: {failed_pods}\n\n"
            
            if pending_pods > 0:
                response += "**Problem Pods:**\n"
                problem_pods = [p for p in pods if p.get('status') != 'Running']
                for pod in problem_pods[:3]:  # Show first 3 problem pods
                    response += f"🔴 {pod.get('name', 'Unknown')} ({pod.get('namespace', 'Unknown')}) - {pod.get('status', 'Unknown')}\n"
        
        # Namespaces
        if 'error' not in k8s_data.get('namespaces', {}):
            namespaces = k8s_data.get('namespaces', [])
            response += f"\n**Namespaces:** {len(namespaces)} total\n"
            for ns in namespaces:
                response += f"• {ns.get('name', 'Unknown')} ({ns.get('status', 'Unknown')})\n"
        
        return response
    
    def _handle_summary_query(self, query):
        """Handle summary/overview queries"""
        response = "📊 **Cluster Health Summary:**\n\n"
        
        # Overall health
        security_score = self.analysis_data.get('health_data', {}).get('security_analysis', {}).get('security_score', 0)
        reliability_score = self.analysis_data.get('reliability', {}).get('reliability_score', 0)
        cost_score = self.analysis_data.get('cost_analysis', {}).get('cost_optimization_score', 0)
        upgrade_score = self.analysis_data.get('upgrade_analysis', {}).get('upgrade_readiness_score', 0)
        
        overall_health = (security_score + reliability_score + cost_score + upgrade_score) / 4
        
        if overall_health >= 80:
            health_status = "🎉 EXCELLENT"
        elif overall_health >= 60:
            health_status = "⚠️ GOOD"
        else:
            health_status = "🚨 NEEDS ATTENTION"
        
        response += f"**Overall Health:** {health_status} ({overall_health:.0f}/100)\n\n"
        
        response += "**Domain Scores:**\n"
        response += f"• Security: {security_score}/100\n"
        response += f"• Reliability: {reliability_score}/100\n"
        response += f"• Cost Optimization: {cost_score:.0f}/100\n"
        response += f"• Upgrade Readiness: {upgrade_score}/100\n\n"
        
        # Critical issues count
        security_domains = self.analysis_data.get('security_domains', {})
        high_priority = security_domains.get('high_priority', 0)
        degraded_addons = self.analysis_data.get('health_data', {}).get('addon_deep_analysis', {}).get('degraded_addons', 0)
        
        response += "**Critical Issues:**\n"
        response += f"• {high_priority} high-priority security issues\n"
        response += f"• {degraded_addons} degraded add-ons\n"
        
        if 'error' not in self.analysis_data.get('k8s_data', {}).get('pods', {}):
            pending_pods = len([p for p in self.analysis_data.get('k8s_data', {}).get('pods', []) if p.get('status') == 'Pending'])
            response += f"• {pending_pods} pending pods\n"
        
        return response
    
    def _handle_recommendation_query(self, query):
        """Handle recommendation queries"""
        response = "💡 **Actionable Recommendations:**\n\n"
        
        response += "**🔴 High Priority (Immediate):**\n"
        response += "1. Enable secrets encryption with AWS KMS\n"
        response += "2. Configure audit logging (audit, api, authenticator)\n"
        response += "3. Restrict API endpoint from 0.0.0.0/0 to specific IPs\n"
        response += "4. Fix degraded add-ons (resource constraints)\n\n"
        
        response += "**🟡 Medium Priority (30 days):**\n"
        response += "1. Enable private endpoint access\n"
        response += "2. Implement spot instances for cost savings\n"
        response += "3. Configure proper autoscaling ranges\n"
        response += "4. Set up comprehensive monitoring\n\n"
        
        response += "**🟢 Low Priority (90 days):**\n"
        response += "1. Plan Kubernetes version upgrades\n"
        response += "2. Implement network policies\n"
        response += "3. Set up backup and disaster recovery\n"
        response += "4. Regular security compliance checks\n"
        
        return response
    
    def _handle_general_query(self, query):
        """Handle general queries"""
        return """
        🤖 **EKS Cluster Assistant**
        
        I can help you with:
        • **Security** - vulnerabilities, encryption, logging
        • **Infrastructure** - nodes, capacity, resources
        • **Add-ons** - health status, degraded services
        • **Cost** - optimization opportunities, savings
        • **Network** - configuration, security, subnets
        • **Workloads** - pods, deployments, namespaces
        • **Summary** - overall health and status
        • **Recommendations** - prioritized action items
        
        Try asking: "What are the security issues?" or "Show me cost savings opportunities"
        """
    
    def add_to_history(self, user_query, bot_response):
        """Add conversation to history"""
        self.conversation_history.append({
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'user': user_query,
            'bot': bot_response
        })
