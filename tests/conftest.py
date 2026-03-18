"""Shared test fixtures and configuration."""

import pytest
from pathlib import Path

from cisa_bdsca.config import Config


@pytest.fixture
def mock_config():
    """Create a mock configuration for testing."""
    return Config(
        BLACKDUCK_URL="https://test.blackduck.com",
        BLACKDUCK_API_TOKEN="test_token_123",
        BLACKDUCK_VERIFY_SSL=False,
        EUVD_CACHE_DIR=Path("/tmp/test_cache")
    )


@pytest.fixture
def sample_cve_response():
    """Sample CVE response from Black Duck API with actual CISA structure."""
    return {
        "name": "CVE-2021-44228",
        "description": "Apache Log4j2 Remote Code Execution",
        "publishedDate": "2021-12-10T10:00:00.000Z",
        "updatedDate": "2021-12-15T10:00:00.000Z",
        "severity": "CRITICAL",
        "cvss3": {
            "baseScore": 10.0
        },
        "cisa": {
            "vulnId": "CVE-2021-44228",
            "addedDate": "2021-12-10T10:00:00.000Z",
            "dueDate": "2021-12-24T10:00:00.000Z",
            "requiredAction": "Apply updates per vendor instructions",
            "vulnerabilityName": "Log4Shell"
        }
    }


@pytest.fixture
def sample_bdsa_response():
    """Sample BDSA response from Black Duck API."""
    return {
        "name": "BDSA-2023-1234",
        "description": "Sample BDSA advisory",
        "publishedDate": "2023-01-15T10:00:00.000Z",
        "severity": "HIGH",
        "_meta": {
            "links": [
                {
                    "rel": "related-vulnerability",
                    "href": "https://test.blackduck.com/api/vulnerabilities/CVE-2023-5678",
                    "label": "NVD"
                }
            ]
        }
    }


@pytest.fixture
def sample_euvd_mapping_csv():
    """Sample EUVD-CVE mapping CSV content."""
    return """euvd_id,cve_id
EUVD-2024-1234,CVE-2024-5678
EUVD-2024-5678,CVE-2024-9999
EUVD-2024-9999,CVE-2024-1111
"""
