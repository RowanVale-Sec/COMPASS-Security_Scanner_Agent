"""
COMPASS Base Agent - Shared env/config helpers.

Historically this module also exported LLM client factory helpers and S3
helpers. LLM client creation moved to `shared.llm_provider`; intermediate
storage moved to `shared.local_store`. The Azure env readers below remain
because `agents/scanner/pipeline/mitre_mapper.py` still uses
`AzureOpenAIChatClient` directly for MCP tool invocation.
"""

import os
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


def get_scan_folder() -> str:
    """Get scan folder path."""
    return os.environ.get('SCAN_FOLDER_PATH', '/scan')
