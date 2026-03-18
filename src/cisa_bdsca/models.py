"""Data models for CISA vulnerability information.

Pydantic models for type-safe data structures and JSON serialization.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class VulnerabilitySource(str, Enum):
    """Source of vulnerability information."""

    NVD = "NVD"  # CVE from National Vulnerability Database
    EUVD = "EUVD"  # EU Vulnerability Database
    BDSA = "BDSA"  # Black Duck Security Advisory


class MappingSource(str, Enum):
    """Source of CVE mapping for non-CVE vulnerabilities."""

    BLACKDUCK = "Black Duck"  # From Black Duck _meta.links
    ENISA = "ENISA"  # From ENISA EUVD-CVE mapping


class CISAData(BaseModel):
    """CISA (Cybersecurity and Infrastructure Security Agency) vulnerability data.

    If this object exists, the vulnerability is in the CISA KEV catalog.
    Supports both Black Duck format (cisaDateAdded, etc.) and KEV catalog format.
    """

    date_added: Optional[str] = Field(
        default=None,
        alias="cisaDateAdded",
        description="Date added to CISA KEV catalog"
    )
    
    due_date: Optional[str] = Field(
        default=None,
        alias="cisaDueDate",
        description="Remediation due date per CISA directive"
    )
    
    required_action: Optional[str] = Field(
        default=None,
        alias="cisaRequiredAction",
        description="Required action from CISA"
    )
    
    notes: Optional[str] = Field(
        default=None,
        alias="cisaNotes",
        description="Additional notes from CISA"
    )
    
    # Additional fields from KEV catalog (when using --use-kev-catalog)
    vendor_project: Optional[str] = Field(
        default=None,
        description="Vendor or project name"
    )
    
    product: Optional[str] = Field(
        default=None,
        description="Affected product"
    )
    
    vulnerability_name: Optional[str] = Field(
        default=None,
        description="Name of the vulnerability"
    )
    
    short_description: Optional[str] = Field(
        default=None,
        description="Short description of the vulnerability"
    )
    
    known_ransomware_campaign_use: Optional[str] = Field(
        default=None,
        description="'Known' if used in ransomware campaigns, 'Unknown' otherwise"
    )
    
    cwes: Optional[list[str]] = Field(
        default=None,
        description="Common Weakness Enumeration codes"
    )

    class Config:
        """Pydantic configuration."""
        populate_by_name = True
        extra = "allow"  # Allow additional fields

    def has_data(self) -> bool:
        """Check if any CISA data is present."""
        return any([
            self.date_added is not None,
            self.due_date is not None,
            self.required_action is not None,
            self.notes is not None,
        ])


class RelatedCVE(BaseModel):
    """Related CVE information with CISA data."""
    
    id: str = Field(description="CVE ID")
    description: Optional[str] = Field(default=None, description="CVE description")
    published_date: Optional[str] = Field(default=None, description="Publication date")
    updated_date: Optional[str] = Field(default=None, description="Last update date")
    severity: Optional[str] = Field(default=None, description="Severity rating")
    base_score: Optional[float] = Field(default=None, description="CVSS base score")
    cisa_data: Optional[CISAData] = Field(
        default=None,
        description="CISA KEV data for this CVE"
    )


class VulnerabilityInfo(BaseModel):
    """Complete vulnerability information including CISA data."""

    id: str = Field(description="Vulnerability ID (CVE, EUVD, or BDSA)")
    source: VulnerabilitySource = Field(description="Vulnerability source database")
    
    # Vulnerability details from Black Duck
    description: Optional[str] = Field(default=None, description="Vulnerability description")
    published_date: Optional[str] = Field(default=None, description="Publication date")
    updated_date: Optional[str] = Field(default=None, description="Last update date")
    
    # Severity information
    severity: Optional[str] = Field(default=None, description="Severity rating")
    base_score: Optional[float] = Field(default=None, description="CVSS base score")
    
    # Related vulnerabilities (for EUVD/BDSA) - now full objects with CISA data
    related_cves: list[RelatedCVE] = Field(
        default_factory=list,
        description="Related CVEs with their CISA data (for EUVD/BDSA)"
    )
    mapping_source: Optional[MappingSource] = Field(
        default=None,
        description="Source of CVE mapping for non-CVE vulnerabilities"
    )
    
    # CISA data (only at top level for direct CVE queries)
    cisa_data: Optional[CISAData] = Field(
        default=None,
        description="CISA KEV data (only for direct CVE queries)"
    )
    
    # Error information
    error: Optional[str] = Field(
        default=None,
        description="Error message if data could not be retrieved"
    )

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        """Validate vulnerability ID format."""
        if not v:
            raise ValueError("Vulnerability ID cannot be empty")
        
        # Check common formats
        if not (v.startswith("CVE-") or v.startswith("EUVD-") or v.startswith("BDSA-")):
            # Still allow it, but warn in logs
            pass
        
        return v


class CollectionResult(BaseModel):
    """Result of collecting CISA data for multiple vulnerabilities."""

    # Metadata
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the collection was performed"
    )
    total_count: int = Field(description="Total number of vulnerabilities processed")
    success_count: int = Field(description="Number successfully processed")
    error_count: int = Field(description="Number that failed")
    
    # Source breakdown
    cve_count: int = Field(default=0, description="Number of CVE vulnerabilities")
    euvd_count: int = Field(default=0, description="Number of EUVD vulnerabilities")
    bdsa_count: int = Field(default=0, description="Number of BDSA vulnerabilities")
    
    # CISA data availability
    cisa_available_count: int = Field(
        default=0,
        description="Number with CISA data available"
    )
    kev_count: int = Field(
        default=0,
        description="Number in CISA KEV catalog"
    )
    
    # Results
    vulnerabilities: list[VulnerabilityInfo] = Field(
        description="List of vulnerability information"
    )
    
    # Errors
    errors: list[dict[str, str]] = Field(
        default_factory=list,
        description="List of errors encountered"
    )

    class Config:
        """Pydantic configuration."""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

    def add_error(self, vuln_id: str, error_message: str) -> None:
        """Add an error to the results."""
        self.errors.append({
            "vulnerability_id": vuln_id,
            "error": error_message
        })
        self.error_count += 1

    def model_dump_json(self, **kwargs: Any) -> str:
        """Export to JSON string with custom formatting."""
        # Default to indented format for readability
        if "indent" not in kwargs:
            kwargs["indent"] = 2
        return super().model_dump_json(**kwargs)
