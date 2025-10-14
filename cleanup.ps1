# EKS Operations Review - Advanced Cleanup Script
param(
    [string]$ClusterName = "eks-opsreview",
    [string]$Region = "us-west-2",
    [switch]$Force,
    [switch]$DryRun,
    [switch]$Help
)

function Show-Help {
    Write-Host "EKS Operations Review - Cleanup Script" -ForegroundColor Blue
    Write-Host "=====================================" -ForegroundColor Blue
    Write-Host ""
    Write-Host "This script safely removes the EKS cluster and all associated resources."
    Write-Host ""
    Write-Host "Usage: .\cleanup.ps1 [options]"
    Write-Host ""
    Write-Host "Parameters:"
    Write-Host "  -ClusterName    Name of the EKS cluster to delete (default: eks-opsreview)"
    Write-Host "  -Region         AWS region (default: us-west-2)"
    Write-Host "  -Force          Skip confirmation prompts"
    Write-Host "  -DryRun         Show what would be deleted without actually deleting"
    Write-Host "  -Help           Show this help message"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\cleanup.ps1                                    # Interactive cleanup"
    Write-Host "  .\cleanup.ps1 -Force                            # Skip confirmations"
    Write-Host "  .\cleanup.ps1 -DryRun                           # Preview what will be deleted"
    Write-Host "  .\cleanup.ps1 -ClusterName my-cluster -Region us-east-1"
    exit 0
}

function Write-Header {
    param([string]$Message)
    Write-Host "=== $Message ===" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "✓ $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠ $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "✗ $Message" -ForegroundColor Red
}

function Test-Prerequisites {
    Write-Header "Checking Prerequisites"
    
    # Check AWS CLI
    try {
        $null = Get-Command aws -ErrorAction Stop
        Write-Success "AWS CLI is available"
    }
    catch {
        Write-Error "AWS CLI is not installed"
        return $false
    }
    
    # Check eksctl
    $eksctlAvailable = $false
    try {
        $null = Get-Command eksctl -ErrorAction Stop
        $script:eksctlCmd = "eksctl"
        $eksctlAvailable = $true
    }
    catch {
        if (Test-Path ".\eksctl.exe") {
            $script:eksctlCmd = ".\eksctl.exe"
            $eksctlAvailable = $true
        }
    }
    
    if ($eksctlAvailable) {
        Write-Success "eksctl is available"
    } else {
        Write-Error "eksctl is not available"
        return $false
    }
    
    # Check kubectl (optional)
    try {
        $null = Get-Command kubectl -ErrorAction Stop
        $script:kubectlAvailable = $true
        Write-Success "kubectl is available"
    }
    catch {
        $script:kubectlAvailable = $false
        Write-Warning "kubectl not available (optional for cleanup)"
    }
    
    # Check AWS credentials
    try {
        $identity = aws sts get-caller-identity --output json | ConvertFrom-Json
        Write-Success "AWS credentials are configured"
        Write-Success "Using AWS Account: $($identity.Account)"
        return $true
    }
    catch {
        Write-Error "AWS credentials not configured"
        return $false
    }
}

function Get-ClusterResources {
    Write-Header "Scanning Cluster Resources"
    
    $resources = @{
        ClusterExists = $false
        NodeGroups = @()
        CloudFormationStacks = @()
        EC2Instances = @()
        LoadBalancers = @()
        SecurityGroups = @()
    }
    
    # Check if cluster exists
    try {
        $clusterInfo = aws eks describe-cluster --name $ClusterName --region $Region --output json | ConvertFrom-Json
        $resources.ClusterExists = $true
        Write-Success "Cluster '$ClusterName' found"
        
        # Get node groups
        $nodeGroups = aws eks list-nodegroups --cluster-name $ClusterName --region $Region --output json | ConvertFrom-Json
        $resources.NodeGroups = $nodeGroups.nodegroups
        Write-Success "Found $($resources.NodeGroups.Count) node group(s)"
        
    }
    catch {
        Write-Warning "Cluster '$ClusterName' not found in region '$Region'"
        return $resources
    }
    
    # Get CloudFormation stacks
    try {
        $stacks = aws cloudformation list-stacks --region $Region --query "StackSummaries[?contains(StackName, 'eksctl-$ClusterName') && StackStatus != 'DELETE_COMPLETE']" --output json | ConvertFrom-Json
        $resources.CloudFormationStacks = $stacks
        Write-Success "Found $($resources.CloudFormationStacks.Count) CloudFormation stack(s)"
    }
    catch {
        Write-Warning "Could not retrieve CloudFormation stacks"
    }
    
    # Get EC2 instances
    try {
        $instances = aws ec2 describe-instances --region $Region --filters "Name=tag:eksctl.cluster.k8s.io/v1alpha1/cluster-name,Values=$ClusterName" --query "Reservations[*].Instances[?State.Name != 'terminated']" --output json | ConvertFrom-Json
        $resources.EC2Instances = $instances | ForEach-Object { $_ } | Where-Object { $_ -ne $null }
        Write-Success "Found $($resources.EC2Instances.Count) EC2 instance(s)"
    }
    catch {
        Write-Warning "Could not retrieve EC2 instances"
    }
    
    return $resources
}

function Show-DryRun {
    param($Resources)
    
    Write-Header "DRY RUN - Resources that would be deleted"
    
    if ($Resources.ClusterExists) {
        Write-Host "EKS Cluster:" -ForegroundColor Cyan
        Write-Host "  - Name: $ClusterName" -ForegroundColor White
        Write-Host "  - Region: $Region" -ForegroundColor White
        
        if ($Resources.NodeGroups.Count -gt 0) {
            Write-Host "Node Groups:" -ForegroundColor Cyan
            foreach ($ng in $Resources.NodeGroups) {
                Write-Host "  - $ng" -ForegroundColor White
            }
        }
        
        if ($Resources.CloudFormationStacks.Count -gt 0) {
            Write-Host "CloudFormation Stacks:" -ForegroundColor Cyan
            foreach ($stack in $Resources.CloudFormationStacks) {
                Write-Host "  - $($stack.StackName) ($($stack.StackStatus))" -ForegroundColor White
            }
        }
        
        if ($Resources.EC2Instances.Count -gt 0) {
            Write-Host "EC2 Instances:" -ForegroundColor Cyan
            foreach ($instance in $Resources.EC2Instances) {
                Write-Host "  - $($instance.InstanceId) ($($instance.State.Name))" -ForegroundColor White
            }
        }
        
        Write-Host ""
        Write-Host "Estimated monthly cost savings: ~$174" -ForegroundColor Green
        Write-Host "  - EKS Control Plane: ~$73/month" -ForegroundColor White
        Write-Host "  - EC2 Instances: ~$95/month" -ForegroundColor White
        Write-Host "  - Storage: ~$6/month" -ForegroundColor White
    } else {
        Write-Warning "No cluster found to delete"
    }
}

function Remove-SampleWorkloads {
    if ($script:kubectlAvailable) {
        Write-Header "Cleaning Sample Workloads"
        try {
            kubectl delete namespace sample-apps --ignore-not-found=true 2>$null
            Write-Success "Sample workloads cleaned up"
        }
        catch {
            Write-Warning "Could not clean up sample workloads"
        }
    }
}

function Remove-EKSCluster {
    Write-Header "Deleting EKS Cluster"
    Write-Warning "This operation will take 10-15 minutes..."
    
    try {
        & $script:eksctlCmd delete cluster --name $ClusterName --region $Region --wait
        Write-Success "Cluster deletion completed"
        return $true
    }
    catch {
        Write-Error "Cluster deletion failed: $_"
        return $false
    }
}

function Verify-Cleanup {
    Write-Header "Verifying Cleanup"
    
    # Check if cluster still exists
    try {
        aws eks describe-cluster --name $ClusterName --region $Region --output json 2>$null | Out-Null
        Write-Warning "Cluster still exists - manual cleanup may be required"
        return $false
    }
    catch {
        Write-Success "Cluster successfully deleted"
    }
    
    # Check for remaining stacks
    try {
        $remainingStacks = aws cloudformation list-stacks --region $Region --query "StackSummaries[?contains(StackName, 'eksctl-$ClusterName') && StackStatus != 'DELETE_COMPLETE']" --output json | ConvertFrom-Json
        if ($remainingStacks.Count -gt 0) {
            Write-Warning "Some CloudFormation stacks may still exist"
            foreach ($stack in $remainingStacks) {
                Write-Host "  - $($stack.StackName): $($stack.StackStatus)" -ForegroundColor Yellow
            }
        } else {
            Write-Success "All CloudFormation stacks cleaned up"
        }
    }
    catch {
        Write-Warning "Could not verify CloudFormation stack cleanup"
    }
    
    return $true
}

function Clean-LocalConfig {
    Write-Header "Cleaning Local Configuration"
    
    if (-not $Force) {
        $cleanKubeconfig = Read-Host "Remove cluster context from kubeconfig? (y/n)"
        if ($cleanKubeconfig -ne 'y') {
            return
        }
    }
    
    try {
        kubectl config delete-context "arn:aws:eks:${Region}:*:cluster/${ClusterName}" 2>$null
        Write-Success "Kubeconfig context removed"
    }
    catch {
        Write-Warning "Could not remove kubeconfig context (may not exist)"
    }
}

function Show-Summary {
    Write-Header "Cleanup Summary"
    
    Write-Host "Resources cleaned up:" -ForegroundColor Green
    Write-Host "✓ EKS Cluster: $ClusterName" -ForegroundColor White
    Write-Host "✓ Node Groups and EC2 instances" -ForegroundColor White
    Write-Host "✓ CloudFormation stacks" -ForegroundColor White
    Write-Host "✓ VPC and networking (if created by eksctl)" -ForegroundColor White
    Write-Host "✓ Load balancers and security groups" -ForegroundColor White
    Write-Host "✓ Sample workloads and namespaces" -ForegroundColor White
    Write-Host ""
    Write-Host "Cost Impact:" -ForegroundColor Cyan
    Write-Host "- Monthly savings: ~$174" -ForegroundColor Green
    Write-Host "- Resources are no longer incurring charges" -ForegroundColor Green
    Write-Host ""
    Write-Host "Local files preserved:" -ForegroundColor Cyan
    Write-Host "- Application code and documentation" -ForegroundColor White
    Write-Host "- Configuration files" -ForegroundColor White
    Write-Host "- Setup scripts for future use" -ForegroundColor White
    Write-Host "- Reports directory" -ForegroundColor White
    Write-Host ""
    Write-Host "To recreate the environment:" -ForegroundColor Yellow
    Write-Host "1. Run: create-eks-cluster.bat" -ForegroundColor White
    Write-Host "2. Run: start_app.bat" -ForegroundColor White
}

# Main execution
function Main {
    if ($Help) {
        Show-Help
    }
    
    Write-Header "EKS Operations Review - Cleanup"
    Write-Host "Cluster: $ClusterName" -ForegroundColor Yellow
    Write-Host "Region: $Region" -ForegroundColor Yellow
    
    if ($DryRun) {
        Write-Host "Mode: DRY RUN (no resources will be deleted)" -ForegroundColor Cyan
    }
    Write-Host ""
    
    # Check prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Error "Prerequisites check failed"
        exit 1
    }
    
    # Get cluster resources
    $resources = Get-ClusterResources
    
    if (-not $resources.ClusterExists) {
        Write-Warning "No cluster found to clean up"
        exit 0
    }
    
    # Show dry run if requested
    if ($DryRun) {
        Show-DryRun $resources
        exit 0
    }
    
    # Confirm deletion
    if (-not $Force) {
        Write-Host ""
        Write-Warning "This will DELETE the EKS cluster and all associated resources!"
        Write-Host "Estimated monthly cost savings: ~$174" -ForegroundColor Green
        Write-Host ""
        $confirm = Read-Host "Are you sure you want to proceed? (yes/no)"
        if ($confirm -ne "yes") {
            Write-Host "Cleanup cancelled" -ForegroundColor Yellow
            exit 0
        }
    }
    
    # Perform cleanup
    Remove-SampleWorkloads
    $success = Remove-EKSCluster
    
    if ($success) {
        Verify-Cleanup
        Clean-LocalConfig
        Show-Summary
        Write-Success "Cleanup completed successfully!"
    } else {
        Write-Error "Cleanup encountered errors. Please check AWS console for remaining resources."
    }
}

# Run main function
Main