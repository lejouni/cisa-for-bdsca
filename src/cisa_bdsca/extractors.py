"""CISA data extraction from Black Duck vulnerability responses.

Extracts KEV status and other CISA-related fields.
"""

import logging
from typing import Any, Optional

from .models import CISAData, VulnerabilityInfo, VulnerabilitySource

logger = logging.getLogger(__name__)


def extract_cisa_data(vuln_response: dict[str, Any]) -> Optional[CISAData]:
    """Extract CISA data from Black Duck vulnerability API response.

    CISA data is only available for CVE (NVD) vulnerabilities in Black Duck.
    Black Duck returns CISA data as a nested object under the 'cisa' key.

    Expected structure:
    {
        "cisa": {
            "vulnId": "CVE-2013-0248",
            "addedDate": "2026-02-07T17:03:26.799Z",
            "dueDate": "2026-02-18T17:03:26.799Z",
            "requiredAction": "Required Action",
            "vulnerabilityName": "Name"
        }
    }

    Args:
        vuln_response: Vulnerability response dictionary from Black Duck API

    Returns:
        CISAData object if any CISA fields found, None otherwise
    """
    try:
        # Check for nested cisa object (primary structure)
        cisa_obj = vuln_response.get("cisa")

        if cisa_obj and isinstance(cisa_obj, dict):
            # Map Black Duck CISA fields to our model fields
            # If cisa object exists, the vulnerability is in KEV catalog
            cisa_fields = {
                "cisaDateAdded": cisa_obj.get("addedDate"),
                "cisaDueDate": cisa_obj.get("dueDate"),
                "cisaRequiredAction": cisa_obj.get("requiredAction"),
                "cisaNotes": cisa_obj.get("vulnerabilityName"),  # Store vuln name in notes
            }

            logger.debug(
                f"Found CISA KEV data: addedDate={cisa_obj.get('addedDate')}, dueDate={cisa_obj.get('dueDate')}"
            )

            cisa_data = CISAData(**cisa_fields)
            return cisa_data

        # Fallback: Check for flat structure (alternative format)
        cisa_fields = {
            "cisaDateAdded": vuln_response.get("cisaDateAdded"),
            "cisaDueDate": vuln_response.get("cisaDueDate"),
            "cisaRequiredAction": vuln_response.get("cisaRequiredAction"),
            "cisaNotes": vuln_response.get("cisaNotes"),
        }

        # Filter out None values
        cisa_fields = {k: v for k, v in cisa_fields.items() if v is not None}

        if cisa_fields:
            logger.debug(f"Found CISA fields in flat structure: {list(cisa_fields.keys())}")
            cisa_data = CISAData(**cisa_fields)
            if cisa_data.has_data():
                return cisa_data

        logger.debug("No CISA data found in vulnerability response")
        return None

    except Exception as e:
        logger.warning(f"Error extracting CISA data: {e}")
        return None


def extract_vulnerability_info(
    vuln_id: str, vuln_response: dict[str, Any], source: VulnerabilitySource
) -> VulnerabilityInfo:
    """Extract vulnerability information from Black Duck API response.

    Args:
        vuln_id: Vulnerability ID
        vuln_response: Vulnerability response from Black Duck API
        source: Vulnerability source (NVD, EUVD, or BDSA)

    Returns:
        VulnerabilityInfo object
    """
    try:
        # Extract basic vulnerability information
        description = vuln_response.get("description", "")
        published_date = vuln_response.get("publishedDate")
        updated_date = vuln_response.get("updatedDate")

        # Extract severity information
        severity = vuln_response.get("severity")
        base_score = None

        # Try to get CVSS score
        if "cvss3" in vuln_response:
            cvss3 = vuln_response["cvss3"]
            if isinstance(cvss3, dict):
                base_score = cvss3.get("baseScore")
        elif "cvss2" in vuln_response:
            cvss2 = vuln_response["cvss2"]
            if isinstance(cvss2, dict):
                base_score = cvss2.get("baseScore")

        # Also check for direct score field
        if base_score is None:
            base_score = vuln_response.get("baseScore")

        # Extract CISA data (only for CVEs)
        cisa_data = None
        if source == VulnerabilitySource.NVD:
            cisa_data = extract_cisa_data(vuln_response)

        # Build VulnerabilityInfo
        vuln_info = VulnerabilityInfo(
            id=vuln_id,
            source=source,
            description=description,
            published_date=published_date,
            updated_date=updated_date,
            severity=severity,
            base_score=base_score,
            cisa_data=cisa_data,
        )

        return vuln_info

    except Exception as e:
        logger.error(f"Error extracting vulnerability info for {vuln_id}: {e}")

        # Return minimal info with error
        return VulnerabilityInfo(
            id=vuln_id, source=source, error=f"Failed to extract vulnerability info: {e}"
        )


def determine_source_from_id(vuln_id: str) -> VulnerabilitySource:
    """Determine vulnerability source from ID prefix.

    Args:
        vuln_id: Vulnerability ID

    Returns:
        VulnerabilitySource enum value
    """
    vuln_id_upper = vuln_id.upper()

    if vuln_id_upper.startswith("CVE-"):
        return VulnerabilitySource.NVD
    elif vuln_id_upper.startswith("EUVD-"):
        return VulnerabilitySource.EUVD
    elif vuln_id_upper.startswith("BDSA-"):
        return VulnerabilitySource.BDSA
    else:
        # Default to NVD for unknown formats
        logger.warning(f"Unknown vulnerability ID format: {vuln_id}, assuming NVD")
        return VulnerabilitySource.NVD
