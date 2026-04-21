"""
COMPASS Base Agent - Shared env/config helpers.

Historically this module also exported LLM client factory helpers; those have
moved to `shared.llm_provider` behind a provider-agnostic interface. The Azure
env readers below remain because `agents/scanner/pipeline/mitre_mapper.py`
still uses `AzureOpenAIChatClient` directly for MCP tool invocation.
"""

import os
import boto3
from dotenv import load_dotenv

load_dotenv()


def get_azure_api_key() -> str:
    """Get Azure OpenAI API key."""
    api_key = os.environ.get('AZURE_OPENAI_API_KEY')
    if not api_key:
        raise ValueError("AZURE_OPENAI_API_KEY environment variable is required")
    return api_key


def get_azure_endpoint() -> str:
    """Get Azure OpenAI endpoint."""
    endpoint = os.environ.get('AZURE_OPENAI_ENDPOINT')
    if not endpoint:
        raise ValueError("AZURE_OPENAI_ENDPOINT environment variable is required")
    return endpoint


def get_deployment_name() -> str:
    """Get Azure OpenAI deployment name."""
    name = os.environ.get('AZURE_OPENAI_CHAT_DEPLOYMENT_NAME') or os.environ.get('AZURE_OPENAI_DEPLOYMENT')
    if not name:
        raise ValueError("AZURE_OPENAI_CHAT_DEPLOYMENT_NAME environment variable is required")
    return name


def get_s3_client():
    """Get boto3 S3 client using environment credentials."""
    aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    aws_region = os.environ.get('AWS_REGION', 'us-east-1')

    if not aws_access_key or not aws_secret_key:
        raise ValueError("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required")

    return boto3.client(
        's3',
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=aws_region
    )


def get_s3_bucket() -> str:
    """Get S3 bucket name."""
    bucket = os.environ.get('S3_BUCKET')
    if not bucket:
        raise ValueError("S3_BUCKET environment variable is required")
    return bucket


def get_scan_folder() -> str:
    """Get scan folder path."""
    return os.environ.get('SCAN_FOLDER_PATH', '/scan')


