import boto3
import os
from botocore.exceptions import ClientError

def get_iam_role_session(role_arn, session_name="eks-review-session"):
    """Get AWS session using IAM role instead of IAM user"""
    try:
        # Create STS client
        sts_client = boto3.client('sts')
        
        # Assume the role
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name
        )
        
        # Extract credentials
        credentials = response['Credentials']
        
        # Create session with assumed role credentials
        session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        return session
    except ClientError as e:
        raise Exception(f"Failed to assume role {role_arn}: {str(e)}")

def get_aws_clients(role_arn=None, region='us-west-2'):
    """Get AWS clients using IAM role or fallback to default credentials"""
    if role_arn:
        session = get_iam_role_session(role_arn)
    else:
        session = boto3.Session()
    
    return {
        'eks': session.client('eks', region_name=region),
        'ec2': session.client('ec2', region_name=region),
        'iam': session.client('iam', region_name=region),
        'cloudwatch': session.client('cloudwatch', region_name=region)
    }
