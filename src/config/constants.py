BEST_PRACTICES_URLS = {
    "security": {
        "main": "https://aws.github.io/aws-eks-best-practices/security/docs/",
        "iam": "https://docs.aws.amazon.com/eks/latest/userguide/security-iam.html",
        "runtime": "https://docs.aws.amazon.com/eks/latest/userguide/security_groups.html",
        "network": "https://docs.aws.amazon.com/eks/latest/userguide/network_reqs.html",
        "detective": "https://docs.aws.amazon.com/eks/latest/userguide/logging-monitoring.html",
        "pods": "https://docs.aws.amazon.com/eks/latest/userguide/pod-security-standards.html"
    },
    "networking": {
        "main": "https://docs.aws.amazon.com/eks/latest/userguide/eks-networking.html",
        "vpc_cni": "https://docs.aws.amazon.com/eks/latest/userguide/managing-vpc-cni.html",
        "security_groups": "https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html",
        "load_balancing": "https://docs.aws.amazon.com/eks/latest/userguide/network-load-balancing.html",
        "service_mesh": "https://docs.aws.amazon.com/app-mesh/latest/userguide/getting-started-kubernetes.html"
    },
    "reliability": {
        "main": "https://docs.aws.amazon.com/eks/latest/userguide/disaster-recovery-resiliency.html",
        "applications": "https://docs.aws.amazon.com/eks/latest/userguide/application-management.html",
        "controlplane": "https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html",
        "dataplane": "https://docs.aws.amazon.com/eks/latest/userguide/eks-node-management.html",
        "storage": "https://docs.aws.amazon.com/eks/latest/userguide/storage.html"
    },
    "cost_optimization": {
        "main": "https://aws.github.io/aws-eks-best-practices/cost_optimization/",
        "compute": "https://aws.github.io/aws-eks-best-practices/cost_optimization/cost_opt_compute/",
        "storage": "https://aws.github.io/aws-eks-best-practices/cost_optimization/cost_opt_storage/",
        "networking": "https://aws.github.io/aws-eks-best-practices/cost_optimization/cost_opt_networking/",
        "observability": "https://aws.github.io/aws-eks-best-practices/cost_optimization/cost_opt_observability/"
    },
    "scalability": {
        "main": "https://docs.aws.amazon.com/eks/latest/userguide/autoscaling.html",
        "cluster": "https://docs.aws.amazon.com/eks/latest/userguide/autoscaling.html#cluster-autoscaler",
        "hpa": "https://docs.aws.amazon.com/eks/latest/userguide/horizontal-pod-autoscaler.html",
        "vpa": "https://docs.aws.amazon.com/eks/latest/userguide/vertical-pod-autoscaler.html"
    },
    "operations": {
        "main": "https://docs.aws.amazon.com/eks/latest/userguide/eks-operations.html",
        "monitoring": "https://docs.aws.amazon.com/eks/latest/userguide/eks-monitoring.html",
        "logging": "https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html",
        "updates": "https://docs.aws.amazon.com/eks/latest/userguide/update-cluster.html"
    }
}

# Form structure
PILLARS = {
    "📋 General Information": {
        "description": "Application overview, environment details, and cluster configuration.",
        "fields": ["Application Overview", "Environment Details", "Cluster Configuration"]
    },
    "🛠️ DevOps & Observability": {
        "description": "DevOps practices, observability stack, and support requirements.",
        "fields": ["DevOps Implementation", "Observability Stack", "Support Requirements", "Workload Information"]
    },
    "💡 Cluster Health": {
        "description": "Cluster status, node health, and scheduling issues.",
        "fields": ["Cluster Status", "Node Health", "Pod Scheduling Issues"]
    },
    "💸 Cost Optimization": {
        "description": "Resource utilization, cost allocation, and optimization opportunities.",
        "fields": ["Resource Utilization", "Cost Allocation", "Optimization Opportunities"]
    },
    "🔐 Security": {
        "description": "IAM configuration, secrets management, and network policies.",
        "fields": ["IAM Configuration", "Secret Management", "Network Policies"]
    },
    "📈 Monitoring": {
        "description": "Monitoring tools, alerts, and metric collection.",
        "fields": ["Monitoring Tools", "Alert Configuration", "Metric Collection"]
    }
}


    
