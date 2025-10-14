#!/usr/bin/env python3
import boto3
import json

def create_knowledge_base():
    bedrock_agent = boto3.client('bedrock-agent', region_name='us-west-2')
    
    try:
        response = bedrock_agent.create_knowledge_base(
            name='eks-best-practices-kb-new',
            description='EKS best practices knowledge base',
            roleArn='arn:aws:iam::YOUR_ACCOUNT_ID:role/service-role/AmazonBedrockExecutionRoleForKnowledgeBase_XXXXX',
            knowledgeBaseConfiguration={
                'type': 'VECTOR',
                'vectorKnowledgeBaseConfiguration': {
                    'embeddingModelArn': 'arn:aws:bedrock:us-west-2::foundation-model/amazon.titan-embed-text-v2:0',
                    'embeddingModelConfiguration': {
                        'bedrockEmbeddingModelConfiguration': {
                            'dimensions': 1024
                        }
                    }
                }
            },
            storageConfiguration={
                'type': 'OPENSEARCH_SERVERLESS',
                'opensearchServerlessConfiguration': {
                    'collectionArn': 'arn:aws:aoss:us-west-2:YOUR_ACCOUNT_ID:collection/YOUR_COLLECTION_ID',
                    'vectorIndexName': 'bedrock-knowledge-base-default-index',
                    'fieldMapping': {
                        'vectorField': 'bedrock-knowledge-base-default-vector',
                        'textField': 'AMAZON_BEDROCK_TEXT',
                        'metadataField': 'AMAZON_BEDROCK_METADATA'
                    }
                }
            }
        )
        
        kb_id = response['knowledgeBase']['knowledgeBaseId']
        print(f"✅ Knowledge base created successfully: {kb_id}")
        
        # Create data source
        ds_response = bedrock_agent.create_data_source(
            knowledgeBaseId=kb_id,
            name='eks-best-practices-data-source',
            dataSourceConfiguration={
                'type': 'S3',
                's3Configuration': {
                    'bucketArn': 'arn:aws:s3:::agent-kb-8483-bucket',
                    'inclusionPrefixes': ['eks-best-practices/']
                }
            }
        )
        
        ds_id = ds_response['dataSource']['dataSourceId']
        print(f"✅ Data source created successfully: {ds_id}")
        
        return kb_id, ds_id
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return None, None

if __name__ == "__main__":
    create_knowledge_base()
