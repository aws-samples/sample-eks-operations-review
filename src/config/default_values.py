import os

# Default cluster name - can be overridden by environment variable
DEFAULT_CLUSTER_NAME = os.getenv("DEFAULT_CLUSTER_NAME", "workshop")

# Default form values
DEFAULT_VALUES = {
    "📋 General Information": {
                "Application Overview": """Total Applications: 12
        Number of Applications by Platform:
        - Windows: 3
        - Linux: 8
        - Others: 1

        Container and Serverless Usage:
        - Containerized Applications: 7
        - Serverless Applications: 3
        - Microservices Rearchitected: 5

        Cloud Distribution:
        - AWS: 85%
        - Other Clouds: GCP (10%), Azure (5%)
        - Distribution Split: Multi-cloud with AWS primary

        Container Environment:
        - Current Container Platform: Amazon EKS
        - Container Management Team: Platform Engineering
        - Architecture Design Team: Cloud Architecture
        - Container Benefits Realized: Improved scalability, resource utilization""",

                "Environment Details": """For each environment (Prod/Dev/UAT):
        Name: Production EKS Cluster
        EKS Cluster Design & Scale:
        EKS Cluster Name: {cluster_name}
        Kubernetes Version: 1.30
        Cluster Creation Tool: eksctl
        Node Types: m5.large, c5.xlarge
        Pod Count:
        - Normal Traffic: 120
        - Peak Traffic: 200
        - Low Traffic: 80
        Node Count:
        - Normal Traffic: 5
        - Peak Traffic: 8
        - Low Traffic: 3
        Expected Growth: 20% in 6 months
        Service Count: 25
        Communication Pattern: REST, gRPC
        Stateful Workloads: 3 databases""",

                "Cluster Configuration": """Autoscaling Solution: Cluster Autoscaler
        Ingress Controller: AWS ALB Ingress Controller
        CNI Details:
        - Type: AWS VPC CNI
        - Configuration: Custom networking enabled
        CoreDNS:
        - Settings: Default configuration
        - Replica Count: 2
        Add-ons Deployed: 
        - AWS Load Balancer Controller
        - Cluster Autoscaler
        - Container Insights
        Fargate Usage: Limited to dev workloads
        Multi-tenant Requirements: Namespace isolation"""
            },

#    "📋 General Information": {
#        "Application Overview": """Total Applications: \nNumber of Applications by Platform:\n- Windows: \n- Linux: \n- Others: \n\nContainer and Serverless Usage:\n- Containerized Applications: \n- Serverless Applications: \n- Microservices Rearchitected: \n\nCloud Distribution:\n- AWS: \n- Other Clouds (specify): \n- Distribution Split: \n\nContainer Environment:\n- Current Container Platform: \n- Container Management Team: \n- Architecture Design Team: \n- Container Benefits Realized: """,
#        
#        "Environment Details": """For each environment (Prod/Dev/UAT):\nName: \nEKS Cluster Design & Scale:\nEKS Cluster Name: workshop\nKubernetes Version: \nCluster Creation Tool: \nNode Types: \nPod Count:\n- Normal Traffic: \n- Peak Traffic: \n- Low Traffic: \nNode Count:\n- Normal Traffic: \n- Peak Traffic: \n- Low Traffic: \nExpected Growth: \nService Count: \nCommunication Pattern: \nStateful Workloads: """,
 #       
 #       "Cluster Configuration": """Autoscaling Solution: \nIngress Controller: \nCNI Details:\n- Type: \n- Configuration: \nCoreDNS:\n- Settings: \n- Replica Count: \nAdd-ons Deployed: \nFargate Usage: \nMulti-tenant Requirements: """
#    },
    "🛠️ DevOps & Observability": {
        "DevOps Implementation": """Automation Status:\nCI/CD Practices Implemented:\nCurrent CI/CD Tools:""",
        "Observability Stack": """Logging Solution:\nMetrics Platform:\nTracing Implementation:\nService Mesh:\n3rd Party Integrations:""",
        "Support Requirements": """Current Issues:\nArchitecture Concerns:\nHelp Needed:""",
        "Workload Information": """Team/Department:\nProject Name:\nWorkload Description:"""
    },
    "💡 Cluster Health": {
        "Cluster Status": """Current control plane health:\nAPI server response time:\netcd cluster status:""",
        "Node Health": """Number of nodes:\nNode types:\nNode issues:\nResource pressure:""",
        "Pod Scheduling Issues": """Scheduling delays:\nResource constraints:\nPod evictions:\nQuota issues:"""
    },
    "💸 Cost Optimization": {
        "Resource Utilization": """CPU utilization:\nMemory utilization:\nStorage utilization:\nIdle resources:\nSpot instance usage:""",
        "Cost Allocation": """Monthly costs:\nCost breakdown:\nCost allocation tags:\nChargeback mechanism:""",
        "Optimization Opportunities": """Right-sizing opportunities:\nSpot instance potential:\nScaling optimization:\nStorage optimization:"""
    },
    "🔐 Security": {
        "IAM Configuration": """IRSA implementation:\nIAM roles:\nSecurity policies:\nAccess patterns:""",
        "Secret Management": """Secret storage:\nSecret rotation:\nEncryption configuration:\nKey management:""",
        "Network Policies": """Network policy implementation:\nSegmentation:\nSecurity groups:\nAccess controls:"""
    },
    "📈 Monitoring": {
        "Monitoring Tools": """Monitoring stack:\nMetrics collection:\nTracing implementation:\nLogging setup:""",
        "Alert Configuration": """Alert types:\nAlert thresholds:\nAlert routing:\nResponse procedures:""",
        "Metric Collection": """Custom metrics:\nSystem metrics:\nBusiness metrics:\nRetention policy:"""
    }
}

    
