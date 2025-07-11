import boto3
import json
import logging
import os
import re
import uuid
from typing import Dict, Any
from botocore.exceptions import ClientError, BotoCoreError

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BedrockAgent:
    def _sanitize_log_input(self, text: str) -> str:
        """Sanitize input for logging to prevent log injection."""
        if not isinstance(text, str):
            return str(text)
        # Remove newlines and control characters
        sanitized = re.sub(r'[\r\n\t\x00-\x1f\x7f-\x9f]', '', text)
        return sanitized[:200]  # Limit length
    
    def __init__(self, region_name: str = "us-east-1"):
        """
        Initialize the Bedrock Agent with proper validation.
        
        Args:
            region_name: AWS region name
            
        Raises:
            ValueError: If region format is invalid
            ClientError: If AWS client initialization fails
        """
        # Validate region format
        if not re.match(r'^[a-z]{2}-[a-z]+-\d{1,2}$', region_name):
            raise ValueError(f"Invalid AWS region format: {region_name}")
            
        self.region_name = region_name
        
        try:
            self.bedrock_client = boto3.client('bedrock', region_name=region_name)
            self.bedrock_agent_client = boto3.client('bedrock-agent', region_name=region_name)
            self.bedrock_agent_runtime_client = boto3.client('bedrock-agent-runtime', region_name=region_name)
            self.s3_client = boto3.client('s3', region_name=region_name)
        except (ClientError, BotoCoreError) as e:
            logger.warning(f"Failed to initialize Bedrock clients: {self._sanitize_log_input(str(e))}")
            raise
        
    def create_knowledge_base(self, kb_name, s3_bucket_name, s3_prefix, description="EKS Best Practices Knowledge Base"):
        """
        Create a knowledge base for the Bedrock agent
        
        Args:
            kb_name (str): Name of the knowledge base
            s3_bucket_name (str): S3 bucket name where the PDF is stored
            s3_prefix (str): S3 prefix for the knowledge base data
            description (str): Description of the knowledge base
            
        Returns:
            str: Knowledge base ID
        """
        try:
            # Create data source
            response = self.bedrock_agent_client.create_knowledge_base(
                name=kb_name,
                description=description,
                roleArn=f"arn:aws:iam::{self._get_account_id()}:role/BedrockKnowledgeBaseRole",
                knowledgeBaseConfiguration={
                    'type': 'VECTOR',
                    'vectorKnowledgeBaseConfiguration': {
                        'embeddingModelArn': 'arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-embed-text-v1'
                    }
                },
                storageConfiguration={
                    'type': 'S3',
                    's3Configuration': {
                        'bucketName': s3_bucket_name,
                        'prefix': s3_prefix
                    }
                }
            )
            
            knowledge_base_id = response['knowledgeBase']['knowledgeBaseId']
            logger.info(f"Created knowledge base with ID: {knowledge_base_id}")
            
            return knowledge_base_id
        
        except ClientError as e:
            logger.warning(f"Error creating knowledge base: {self._sanitize_log_input(str(e))}")
            raise
    
    def create_data_source(self, knowledge_base_id, data_source_name, s3_bucket_name, s3_prefix):
        """
        Create a data source for the knowledge base
        
        Args:
            knowledge_base_id (str): Knowledge base ID
            data_source_name (str): Name of the data source
            s3_bucket_name (str): S3 bucket name where the PDF is stored
            s3_prefix (str): S3 prefix for the data source
            
        Returns:
            str: Data source ID
        """
        try:
            response = self.bedrock_agent_client.create_data_source(
                knowledgeBaseId=knowledge_base_id,
                name=data_source_name,
                dataSourceConfiguration={
                    'type': 'S3',
                    's3Configuration': {
                        'bucketName': s3_bucket_name,
                        'inclusionPrefixes': [s3_prefix]
                    }
                },
                vectorIngestionConfiguration={
                    'chunkingConfiguration': {
                        'chunkingStrategy': 'FIXED_SIZE',
                        'fixedSizeChunkingConfiguration': {
                            'maxTokens': 300,
                            'overlapPercentage': 20
                        }
                    }
                }
            )
            
            data_source_id = response['dataSource']['dataSourceId']
            logger.info(f"Created data source with ID: {data_source_id}")
            
            return data_source_id
        
        except ClientError as e:
            logger.warning(f"Error creating data source: {self._sanitize_log_input(str(e))}")
            raise
    
    def create_agent(self, agent_name, knowledge_base_id, description="EKS Best Practices Agent"):
        """
        Create a Bedrock agent with Amazon Claude 3 Sonnet (Nova Pro) as the foundation model
        
        Args:
            agent_name (str): Name of the agent
            knowledge_base_id (str): Knowledge base ID
            description (str): Description of the agent
            
        Returns:
            str: Agent ID
        """
        try:
            response = self.bedrock_agent_client.create_agent(
                agentName=agent_name,
                description=description,
                foundationModel="anthropic.claude-3-sonnet-20240229-v1:0",  # Claude 3 Sonnet (Nova Pro)
                instruction="You are an EKS operational review assistant. Use the knowledge base to answer questions about EKS best practices.",
                roleArn=f"arn:aws:iam::{self._get_account_id()}:role/BedrockAgentRole",
                idleSessionTTLInSeconds=1800,  # 30 minutes
                customerEncryptionKeyArn=None  # Use AWS managed key
            )
            
            agent_id = response['agent']['agentId']
            logger.info(f"Created agent with ID: {agent_id}")
            
            # Associate knowledge base with agent
            self.bedrock_agent_client.associate_agent_knowledge_base(
                agentId=agent_id,
                agentVersion="DRAFT",
                knowledgeBaseId=knowledge_base_id,
                description="EKS Best Practices Knowledge Base"
            )
            
            logger.info(f"Associated knowledge base {knowledge_base_id} with agent {agent_id}")
            
            return agent_id
        
        except ClientError as e:
            logger.warning(f"Error creating agent: {self._sanitize_log_input(str(e))}")
            raise
    
    def prepare_agent(self, agent_id):
        """
        Prepare the agent for use
        
        Args:
            agent_id (str): Agent ID
            
        Returns:
            str: Agent alias ID
        """
        try:
            # Create agent version
            version_response = self.bedrock_agent_client.create_agent_version(
                agentId=agent_id,
                agentVersion="1"
            )
            
            # Create agent alias
            alias_response = self.bedrock_agent_client.create_agent_alias(
                agentId=agent_id,
                agentAliasName="production",
                description="Production alias for EKS Best Practices Agent",
                agentVersion="1"
            )
            
            agent_alias_id = alias_response['agentAlias']['agentAliasId']
            logger.info(f"Created agent alias with ID: {agent_alias_id}")
            
            return agent_alias_id
        
        except ClientError as e:
            logger.warning(f"Error preparing agent: {self._sanitize_log_input(str(e))}")
            raise
    
    def upload_pdf_to_s3(self, pdf_path, s3_bucket_name, s3_key):
        """
        Upload a PDF file to S3
        
        Args:
            pdf_path (str): Local path to the PDF file
            s3_bucket_name (str): S3 bucket name
            s3_key (str): S3 key for the PDF file
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.s3_client.upload_file(pdf_path, s3_bucket_name, s3_key)
            logger.info(f"Uploaded {pdf_path} to s3://{s3_bucket_name}/{s3_key}")
            return True
        
        except ClientError as e:
            logger.error(f"Error uploading PDF to S3: {self._sanitize_log_input(str(e))}")
            return False
    
    def invoke_agent(self, agent_id: str, agent_alias_id: str, input_text: str) -> Dict[str, Any]:
        """
        Invoke the Bedrock agent with input validation.
        
        Args:
            agent_id: Agent ID
            agent_alias_id: Agent alias ID
            input_text: Input text for the agent
            
        Returns:
            dict: Agent response
            
        Raises:
            ValueError: If inputs are invalid
            ClientError: If AWS API call fails
        """
        # Validate inputs
        if not all([agent_id, agent_alias_id, input_text]):
            raise ValueError("All parameters are required")
            
        # Sanitize input text
        input_text = input_text.strip()[:4000]  # Limit length
        if not input_text:
            raise ValueError("Input text cannot be empty")
            
        try:
            response = self.bedrock_agent_runtime_client.invoke_agent(
                agentId=agent_id,
                agentAliasId=agent_alias_id,
                sessionId=f"session-{uuid.uuid4().hex[:8]}",  # Use unique session ID
                inputText=input_text,
                enableTrace=False  # Disable trace for security
            )
            
            # Process the response
            response_stream = response['completion']
            response_content = b''
            
            for event in response_stream:
                if 'chunk' in event:
                    chunk = event['chunk']
                    if 'bytes' in chunk:
                        response_content += chunk['bytes']
            
            return json.loads(response_content.decode('utf-8'))
        
        except ClientError as e:
            logger.warning(f"Error invoking agent: {self._sanitize_log_input(str(e))}")
            raise
    
    def _get_account_id(self):
        """
        Get the AWS account ID
        
        Returns:
            str: AWS account ID
        """
        sts_client = boto3.client('sts', region_name=self.region_name)
        return sts_client.get_caller_identity()["Account"]


def main():
    # Initialize the Bedrock Agent
    agent_handler = BedrockAgent(region_name="us-east-1")
    
    # Configuration
    s3_bucket_name = "eks-best-practices-kb"  # Replace with your S3 bucket name
    s3_prefix = "eks-best-practices/"
    pdf_path = "eks-bpg.pdf"
    
    # Create S3 bucket if it doesn't exist
    try:
        agent_handler.s3_client.create_bucket(
            Bucket=s3_bucket_name,
            CreateBucketConfiguration={'LocationConstraint': agent_handler.region_name}
        )
        logger.info(f"Created S3 bucket: {s3_bucket_name}")
    except ClientError as e:
        if e.response['Error']['Code'] != 'BucketAlreadyOwnedByYou':
            logger.warning(f"Error creating S3 bucket: {self._sanitize_log_input(str(e))}")
            raise
    
    # Upload PDF to S3
    s3_key = f"{s3_prefix}{os.path.basename(pdf_path)}"
    if agent_handler.upload_pdf_to_s3(pdf_path, s3_bucket_name, s3_key):
        # Create knowledge base
        kb_name = "EKSBestPracticesKB"
        knowledge_base_id = agent_handler.create_knowledge_base(
            kb_name=kb_name,
            s3_bucket_name=s3_bucket_name,
            s3_prefix=s3_prefix
        )
        
        # Create data source
        data_source_id = agent_handler.create_data_source(
            knowledge_base_id=knowledge_base_id,
            data_source_name="EKSBestPracticesDataSource",
            s3_bucket_name=s3_bucket_name,
            s3_prefix=s3_prefix
        )
        
        # Create agent
        agent_id = agent_handler.create_agent(
            agent_name="EKSBestPracticesAgent",
            knowledge_base_id=knowledge_base_id
        )
        
        # Prepare agent
        agent_alias_id = agent_handler.prepare_agent(agent_id)
        
        logger.info(f"Agent setup complete. Agent ID: {agent_id}, Alias ID: {agent_alias_id}")
        
        # Test the agent
        test_input = "What are the best practices for EKS security?"
        response = agent_handler.invoke_agent(agent_id, agent_alias_id, test_input)
        
        logger.info(f"Agent response: {response}")
    else:
        logger.error("Failed to upload PDF to S3. Agent setup aborted.")


if __name__ == "__main__":
    main()