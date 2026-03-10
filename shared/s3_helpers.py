"""
COMPASS S3 Helpers - Common S3 upload/download utilities for all agents.
"""

import json
from datetime import datetime
from typing import Dict, Any, Optional

from shared.base_agent import get_s3_client, get_s3_bucket


def parse_s3_uri(s3_location: str) -> tuple:
    """Parse an S3 URI into (bucket, key).

    Args:
        s3_location: S3 URI like 's3://bucket-name/path/to/file.json'

    Returns:
        Tuple of (bucket_name, key)

    Raises:
        ValueError: If the URI format is invalid
    """
    if not s3_location.startswith('s3://'):
        raise ValueError(f"Invalid S3 URI format: {s3_location}")

    parts = s3_location[5:].split('/', 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid S3 URI path: {s3_location}")

    return parts[0], parts[1]


def upload_json_to_s3(
    data: Dict[str, Any],
    prefix: str,
    bucket: Optional[str] = None,
    filename_suffix: str = ""
) -> str:
    """Upload JSON data to S3 with timestamped key.

    Args:
        data: Dictionary to upload as JSON
        prefix: S3 key prefix (e.g., 'scan-results', 'inventory', 'threat-models')
        bucket: S3 bucket name (defaults to S3_BUCKET env var)
        filename_suffix: Optional suffix before .json (e.g., '-deduplicated')

    Returns:
        S3 URI of the uploaded file
    """
    s3_client = get_s3_client()
    bucket = bucket or get_s3_bucket()

    timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    key = f"{prefix}/{prefix}-{timestamp}{filename_suffix}.json"

    s3_client.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(data, indent=2),
        ContentType='application/json'
    )

    return f"s3://{bucket}/{key}"


def download_json_from_s3(s3_location: str) -> Dict[str, Any]:
    """Download and parse JSON from S3.

    Args:
        s3_location: S3 URI like 's3://bucket/path/to/file.json'

    Returns:
        Parsed JSON as a dictionary
    """
    bucket, key = parse_s3_uri(s3_location)
    s3_client = get_s3_client()

    response = s3_client.get_object(Bucket=bucket, Key=key)
    content = response['Body'].read().decode('utf-8')
    return json.loads(content)


def save_local_fallback(data: Dict[str, Any], directory: str, prefix: str) -> str:
    """Save JSON locally when S3 upload fails.

    Args:
        data: Dictionary to save as JSON
        directory: Local directory path
        prefix: Filename prefix

    Returns:
        Local file path
    """
    import os
    os.makedirs(directory, exist_ok=True)

    timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    filepath = os.path.join(directory, f"{prefix}-{timestamp}.json")

    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)

    return filepath
