"""CISA vulnerability data collector for Black Duck SCA.

This module provides functionality to collect CISA (Cybersecurity and Infrastructure
Security Agency) information for vulnerabilities from Black Duck SCA. It supports
CVE (NVD), EUVD, and BDSA vulnerability sources, with automatic resolution of
related CVEs for EUVD and BDSA vulnerabilities.

Usage as a library:
    from cisa_bdsca import collect_cisa_data, BlackDuckClient

    results = collect_cisa_data(
        vuln_ids=["CVE-2021-44228", "BDSA-2023-1234"],
        config=None  # Uses environment variables
    )

Usage as CLI:
    python -m cisa_bdsca collect --ids "CVE-2021-44228,BDSA-2023-1234"
"""

__version__ = "0.1.2"
__all__ = ["collect_cisa_data", "BlackDuckClient"]


# Lazy imports to avoid circular dependencies
def collect_cisa_data(vuln_ids: list[str], config=None):
    """Collect CISA data for given vulnerability IDs.

    Args:
        vuln_ids: List of vulnerability IDs (CVE, EUVD, or BDSA format)
        config: Optional configuration object (uses environment if None)

    Returns:
        CollectionResult object with vulnerabilities and metadata
    """
    from .processor import process_vulnerabilities

    return process_vulnerabilities(vuln_ids, config)


def BlackDuckClient(*args, **kwargs):
    """Get a Black Duck client instance.

    Returns:
        BlackDuckClient instance for advanced usage
    """
    from .client import BlackDuckClient as _BlackDuckClient

    return _BlackDuckClient(*args, **kwargs)
