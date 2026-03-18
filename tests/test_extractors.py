"""Test extractors."""

import pytest

from cisa_bdsca.extractors import (
    determine_source_from_id,
    extract_cisa_data,
)
from cisa_bdsca.models import VulnerabilitySource


def test_determine_source_from_id():
    """Test vulnerability source detection from ID."""
    assert determine_source_from_id("CVE-2021-44228") == VulnerabilitySource.NVD
    assert determine_source_from_id("EUVD-2024-1234") == VulnerabilitySource.EUVD
    assert determine_source_from_id("BDSA-2023-5678") == VulnerabilitySource.BDSA
    
    # Case insensitive
    assert determine_source_from_id("cve-2021-44228") == VulnerabilitySource.NVD


def test_extract_cisa_data():
    """Test CISA data extraction from nested structure."""
    # Response with CISA data in nested structure (actual Black Duck format)
    response = {
        "cisa": {
            "vulnId": "CVE-2021-44228",
            "addedDate": "2021-12-10T10:00:00.000Z",
            "dueDate": "2021-12-24T10:00:00.000Z",
            "requiredAction": "Apply updates per vendor instructions",
            "vulnerabilityName": "Log4Shell"
        }
    }
    
    cisa_data = extract_cisa_data(response)
    
    assert cisa_data is not None
    assert cisa_data.date_added == "2021-12-10T10:00:00.000Z"
    assert cisa_data.due_date == "2021-12-24T10:00:00.000Z"
    assert cisa_data.required_action == "Apply updates per vendor instructions"
    assert cisa_data.has_data() is True


def test_extract_cisa_data_empty():
    """Test extraction with no CISA data."""
    response = {
        "name": "Some Vulnerability",
        "severity": "HIGH"
    }
    
    cisa_data = extract_cisa_data(response)
    assert cisa_data is None


def test_extract_cisa_data_empty():
    """Test extraction with no CISA data."""
    response = {
        "name": "CVE-2023-0001",
        "description": "Some vulnerability"
    }
    
    cisa_data = extract_cisa_data(response)
    
    assert cisa_data is None
