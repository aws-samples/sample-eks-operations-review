import unittest
from analyzers.oldbest_practices_analyzer import EKSBestPracticesAnalyzer
from src.analyzers.security_analyzer import SecurityAnalyzer
from src.analyzers.cost_analyzer import CostAnalyzer

class TestBestPracticesAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = EKSBestPracticesAnalyzer()

    def test_analyze_inputs(self):
        test_inputs = {
            "🔐 Security": {
                "IAM Configuration": "IRSA not implemented",
                "Network Policies": "Network policies missing"
            }
        }
        
        results = self.analyzer.analyze_inputs(test_inputs)
        
        self.assertTrue('high_priority' in results)
        self.assertTrue('medium_priority' in results)
        self.assertTrue('low_priority' in results)

class TestSecurityAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = SecurityAnalyzer()

    def test_analyze_security(self):
        test_cluster_details = {
            'cluster': {
                'name': 'test-cluster',
                'version': '1.24'
            }
        }
        
        test_inputs = {
            "🔐 Security": {
                "IAM Configuration": "IRSA not implemented",
                "Network Policies": "Network policies missing"
            }
        }
        
        results = self.analyzer.analyze_security(test_cluster_details, test_inputs)
        
        self.assertTrue('status' in results)
        self.assertTrue('recommendations' in results)

class TestCostAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = CostAnalyzer()

    def test_analyze_costs(self):
        test_cluster_details = {
            'cluster': {
                'name': 'test-cluster',
                'version': '1.24'
            }
        }
        
        test_inputs = {
            "💸 Cost Optimization": {
                "Resource Utilization": "No spot instances in use"
            }
        }
        
        results = self.analyzer.analyze_costs(test_cluster_details, test_inputs)
        
        self.assertTrue('findings' in results)
        self.assertTrue('recommendations' in results)

if __name__ == '__main__':
    unittest.main()
