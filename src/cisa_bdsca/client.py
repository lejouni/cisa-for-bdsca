"""Black Duck API client wrapper.

Provides a high-level interface to Black Duck SCA APIs for vulnerability queries.
"""

import logging
from typing import Any, Optional
from urllib.parse import urljoin

from blackduck import Client

from .config import Config

logger = logging.getLogger(__name__)


class BlackDuckClientError(Exception):
    """Base exception for Black Duck client errors."""

    pass


class BlackDuckAuthenticationError(BlackDuckClientError):
    """Raised when authentication fails."""

    pass


class BlackDuckAPIError(BlackDuckClientError):
    """Raised when API calls fail."""

    pass


class BlackDuckClient:
    """Wrapper around Black Duck SDK for vulnerability queries."""

    def __init__(self, config: Config):
        """Initialize Black Duck client.

        Args:
            config: Configuration object with Black Duck settings

        Raises:
            BlackDuckAuthenticationError: If authentication fails
        """
        self.config = config
        self._client: Optional[Client] = None
        self._authenticate()

    def _authenticate(self) -> None:
        """Authenticate with Black Duck using API token.

        Raises:
            BlackDuckAuthenticationError: If authentication fails
        """
        try:
            logger.info(f"Authenticating to Black Duck at {self.config.blackduck_url}")

            self._client = Client(
                base_url=self.config.blackduck_url,
                token=self.config.blackduck_api_token,
                verify=self.config.blackduck_verify_ssl,
                timeout=60.0,
            )

            # Test connection
            self._client.list_resources()
            logger.info("Successfully authenticated to Black Duck")

        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            raise BlackDuckAuthenticationError(f"Failed to authenticate: {e}") from e

    def get_vulnerability_by_id(self, vuln_id: str) -> Optional[dict[str, Any]]:
        """Get vulnerability details by ID.

        Args:
            vuln_id: Vulnerability ID (CVE-*, EUVD-*, or BDSA-*)

        Returns:
            Vulnerability data dictionary, or None if not found

        Raises:
            BlackDuckAPIError: If API call fails
        """
        if not self._client:
            raise BlackDuckClientError("Client not authenticated")

        try:
            logger.debug(f"Fetching vulnerability: {vuln_id}")

            # Construct vulnerability URL
            vuln_url = urljoin(self.config.blackduck_url, f"/api/vulnerabilities/{vuln_id}")

            # Get vulnerability data
            response = self._client.get_json(vuln_url)

            if response:
                logger.debug(f"Successfully fetched {vuln_id}")
                return response
            else:
                logger.warning(f"Vulnerability not found: {vuln_id}")
                return None

        except Exception as e:
            logger.error(f"Error fetching vulnerability {vuln_id}: {e}")
            raise BlackDuckAPIError(f"Failed to fetch {vuln_id}: {e}") from e

    def get_related_cve_from_bdsa(self, vuln_data: dict[str, Any]) -> Optional[str]:
        """Extract related CVE ID from BDSA vulnerability metadata.

        Parses _meta.links array for related-vulnerability link with label="NVD".

        Args:
            vuln_data: BDSA vulnerability response from Black Duck API

        Returns:
            CVE ID if found, None otherwise
        """
        try:
            meta = vuln_data.get("_meta", {})
            links = meta.get("links", [])

            # Look for related-vulnerability link with NVD label
            for link in links:
                if link.get("rel") == "related-vulnerability":
                    label = link.get("label", "")
                    href = link.get("href", "")

                    # Check if it's an NVD (CVE) link
                    if label == "NVD" or "CVE-" in href:
                        # Extract CVE ID from href
                        # Example: https://.../api/vulnerabilities/CVE-2020-11023
                        cve_id = href.split("/")[-1]
                        if cve_id.startswith("CVE-"):
                            logger.debug(f"Found related CVE: {cve_id}")
                            return cve_id

            logger.debug("No related CVE found in BDSA metadata")
            return None

        except Exception as e:
            logger.error(f"Error extracting related CVE from BDSA: {e}")
            return None

    def get_multiple_related_cves_from_bdsa(self, vuln_data: dict[str, Any]) -> list[str]:
        """Extract all related CVE IDs from BDSA vulnerability metadata.

        Some BDSAs may be related to multiple CVEs.

        Args:
            vuln_data: BDSA vulnerability response from Black Duck API

        Returns:
            List of CVE IDs (may be empty)
        """
        cve_ids = []

        try:
            meta = vuln_data.get("_meta", {})
            links = meta.get("links", [])

            # Look for all related-vulnerability links with NVD label
            for link in links:
                if link.get("rel") == "related-vulnerability":
                    label = link.get("label", "")
                    href = link.get("href", "")

                    # Check if it's an NVD (CVE) link
                    if label == "NVD" or "CVE-" in href:
                        # Extract CVE ID from href
                        cve_id = href.split("/")[-1]
                        if cve_id.startswith("CVE-"):
                            cve_ids.append(cve_id)

            if cve_ids:
                logger.debug(f"Found {len(cve_ids)} related CVEs: {cve_ids}")
            else:
                logger.debug("No related CVEs found in BDSA metadata")

            return cve_ids

        except Exception as e:
            logger.error(f"Error extracting related CVEs from BDSA: {e}")
            return []

    def check_connection(self) -> bool:
        """Check if connection to Black Duck is working.

        Returns:
            True if connection is working

        Raises:
            BlackDuckAPIError: If connection check fails
        """
        try:
            if not self._client:
                return False

            # Simple API call to verify connection
            self._client.list_resources()
            return True

        except Exception as e:
            logger.error(f"Connection check failed: {e}")
            raise BlackDuckAPIError(f"Connection check failed: {e}") from e
