import logging

logger = logging.getLogger(__name__)

class CostAnalyzer:
    def __init__(self):
        self.cost_checks = {
            'compute': self._analyze_compute_costs,
            'storage': self._analyze_storage_costs,
            'network': self._analyze_network_costs
        }

    def analyze_costs(self, cluster_details, inputs):
        """Analyze cluster cost optimization opportunities"""
        cost_results = {
            'findings': [],
            'recommendations': [],
            'potential_savings': {}
        }

        for check_name, check_func in self.cost_checks.items():
            try:
                result = check_func(cluster_details, inputs)
                cost_results['findings'].extend(result.get('findings', []))
                cost_results['recommendations'].extend(result.get('recommendations', []))
                if result.get('potential_savings'):
                    cost_results['potential_savings'][check_name] = result['potential_savings']
                    
            except Exception as e:
                logger.error(f"Error in cost analysis {check_name}: {e}")

        return cost_results

    def _analyze_compute_costs(self, cluster_details, inputs):
        """Analyze compute-related costs"""
        cost_info = inputs.get('💸 Cost Optimization', {}).get('Resource Utilization', '')
        
        findings = []
        recommendations = []
        
        # Check for spot instance usage
        if 'spot' not in cost_info.lower():
            recommendations.append({
                'category': 'compute',
                'priority': 'high',
                'recommendation': 'Consider using Spot instances for non-critical workloads'
            })

        # Check node utilization
        if 'utilization' in cost_info.lower():
            findings.append({
                'category': 'compute',
                'finding': 'Node utilization could be optimized'
            })

        return {
            'findings': findings,
            'recommendations': recommendations
        }

    def _analyze_storage_costs(self, cluster_details, inputs):
        """Analyze storage-related costs"""
        cost_info = inputs.get('💸 Cost Optimization', {}).get('Resource Utilization', '')
        
        findings = []
        recommendations = []

        # Check storage utilization
        if 'storage' in cost_info.lower():
            findings.append({
                'category': 'storage',
                'finding': 'Storage resources could be optimized'
            })

        return {
            'findings': findings,
            'recommendations': recommendations
        }

    def _analyze_network_costs(self, cluster_details, inputs):
        """Analyze network-related costs"""
        cost_info = inputs.get('💸 Cost Optimization', {}).get('Resource Utilization', '')
        
        findings = []
        recommendations = []

        # Check network optimization
        if 'network' in cost_info.lower():
            findings.append({
                'category': 'network',
                'finding': 'Network costs could be optimized'
            })

        return {
            'findings': findings,
            'recommendations': recommendations
        }
