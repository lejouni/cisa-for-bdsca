"""Test data models."""

import pytest
from datetime import datetime

from cisa_bdsca.models import (
    CISAData,
    VulnerabilityInfo,
    VulnerabilitySource,
    MappingSource,
    CollectionResult,
)


def test_cisa_data_model():
    """Test CISAData model."""
    cisa_data = CISAData(
        cisaDateAdded="2021-12-10",
        cisaDueDate="2021-12-24"
    )
    
    assert cisa_data.date_added == "2021-12-10"
    assert cisa_data.has_data() is True


def test_cisa_data_empty():
    """Test empty CISA data."""
    cisa_data = CISAData()
    assert cisa_data.has_data() is False


def test_vulnerability_info_model():
    """Test VulnerabilityInfo model."""
    vuln_info = VulnerabilityInfo(
        id="CVE-2021-44228",
        source=VulnerabilitySource.NVD,
        name="Log4Shell",
        severity="CRITICAL",
        base_score=10.0
    )
    
    assert vuln_info.id == "CVE-2021-44228"
    assert vuln_info.source == VulnerabilitySource.NVD
    assert vuln_info.severity == "CRITICAL"


def test_collection_result():
    """Test CollectionResult model."""
    result = CollectionResult(
        total_count=3,
        success_count=2,
        error_count=1,
        vulnerabilities=[]
    )
    
    assert result.total_count == 3
    assert result.success_count == 2
    assert result.error_count == 1


def test_collection_result_add_error():
    """Test adding errors to collection result."""
    result = CollectionResult(
        total_count=1,
        success_count=0,
        error_count=0,
        vulnerabilities=[]
    )
    
    result.add_error("CVE-2021-1234", "Test error")
    
    assert result.error_count == 1
    assert len(result.errors) == 1
    assert result.errors[0]["vulnerability_id"] == "CVE-2021-1234"


def test_vulnerability_source_enum():
    """Test VulnerabilitySource enum."""
    assert VulnerabilitySource.NVD.value == "NVD"
    assert VulnerabilitySource.EUVD.value == "EUVD"
    assert VulnerabilitySource.BDSA.value == "BDSA"


def test_mapping_source_enum():
    """Test MappingSource enum."""
    assert MappingSource.BLACKDUCK.value == "Black Duck"
    assert MappingSource.ENISA.value == "ENISA"
