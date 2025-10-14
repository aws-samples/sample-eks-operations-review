#!/bin/bash

# Git commands to push AgentK8s to AWS Samples repository

echo "🚀 Preparing AgentK8s for Git push..."

# Initialize git if not already done
git init

# Add the AWS samples remote repository
git remote add origin https://github.com/aws-samples/sample-eks-operations-review.git

# Check current status
echo "📋 Current git status:"
git status

# Add all files except those in .gitignore
git add .

# Commit with descriptive message
git commit -m "feat: AgentK8s - Ultimate EKS Analyzer with AI Assistant

- Enhanced UI with 10 comprehensive analysis tabs
- Real-time cluster analysis with error handling
- AI-powered chatbot for cluster insights
- Executive PDF reports with AWS CLI commands
- Security assessment with HardenEKS integration
- Multi-analysis modes (Comprehensive, Quick, Security Focus)
- Automated remediation recommendations
- Compliance validation framework
- Historical trend analysis
- Multi-cluster comparison capabilities

Built by Pravinkumar Menghani & Qais Poonawala"

# Push to main branch
echo "🔄 Pushing to GitHub..."
git push -u origin main

echo "✅ Successfully pushed AgentK8s to GitHub!"
echo "🌐 Repository: https://github.com/aws-samples/sample-eks-operations-review"
