"""CISA KEV Catalog fetcher with caching.

Fetches and caches the CISA Known Exploited Vulnerabilities (KEV) catalog.
Cache is refreshed daily at 07:00 UTC.
"""

import json
import logging
from datetime import datetime, time, timedelta
from typing import Optional

import requests

from .config import Config

logger = logging.getLogger(__name__)


class KEVCatalogError(Exception):
    """Base exception for KEV catalog errors."""
    pass


class KEVCatalog:
    """Manages CISA KEV catalog with caching.

    Lazy-loads KEV catalog from CISA feed with daily refresh at 07:00 UTC.
    Provides lookup by CVE ID.
    """

    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    CACHE_FILENAME = "known_exploited_vulnerabilities.json"

    def __init__(self, config: Config):
        """Initialize KEV catalog.

        Args:
            config: Configuration object with cache directory setting
        """
        self.config = config
        self.cache_dir = config.kev_cache_dir
        self.cache_file = self.cache_dir / self.CACHE_FILENAME
        
        # Lazy-loaded catalog dictionary: {cve_id: vulnerability_data}
        self._catalog: Optional[dict[str, dict]] = None
        
        logger.debug(f"KEV catalog initialized with cache dir: {self.cache_dir}")

    def get_kev_data(self, cve_id: str) -> Optional[dict]:
        """Get KEV data for given CVE ID.

        Lazy-loads catalog on first call.

        Args:
            cve_id: CVE ID (e.g., "CVE-2021-44228")

        Returns:
            Dictionary with KEV data if CVE is in catalog, None otherwise

        Raises:
            KEVCatalogError: If catalog cannot be loaded
        """
        # Ensure catalog is loaded
        if self._catalog is None:
            self._load_catalog()
        
        # Normalize CVE ID (case-insensitive lookup)
        cve_key = cve_id.upper()
        
        # Get KEV data
        kev_data = self._catalog.get(cve_key)
        
        if kev_data:
            logger.debug(f"Found KEV data for {cve_id}")
        else:
            logger.debug(f"No KEV data found for {cve_id}")
        
        return kev_data

    def _load_catalog(self) -> None:
        """Load KEV catalog from cache or download fresh copy.

        Raises:
            KEVCatalogError: If catalog cannot be loaded
        """
        logger.info("Loading CISA KEV catalog...")
        
        # Check if cache is valid
        if self._is_cache_valid():
            logger.info(f"Using cached KEV catalog from {self.cache_file}")
            self._catalog = self._parse_catalog_file()
        else:
            logger.info("Cache invalid or missing, downloading fresh KEV catalog")
            self._download_catalog()
            self._catalog = self._parse_catalog_file()
        
        logger.info(f"Loaded {len(self._catalog)} vulnerabilities from KEV catalog")

    def _is_cache_valid(self) -> bool:
        """Check if cached catalog file is valid.

        Cache is valid if:
        1. File exists
        2. File was modified after the most recent 07:00 UTC

        Returns:
            True if cache is valid
        """
        if not self.cache_file.exists():
            logger.debug("Cache file does not exist")
            return False
        
        try:
            # Get file modification time
            file_mtime = datetime.fromtimestamp(self.cache_file.stat().st_mtime)
            
            # Calculate most recent 07:00 UTC
            now_utc = datetime.utcnow()
            today_refresh = datetime.combine(now_utc.date(), time(7, 0, 0))
            
            # If current time is before today's 07:00 UTC, use yesterday's 07:00 UTC
            if now_utc < today_refresh:
                last_refresh_time = today_refresh - timedelta(days=1)
            else:
                last_refresh_time = today_refresh
            
            # Cache is valid if file is newer than last refresh time
            is_valid = file_mtime > last_refresh_time
            
            logger.debug(
                f"Cache validation: file_mtime={file_mtime}, "
                f"last_refresh={last_refresh_time}, valid={is_valid}"
            )
            
            return is_valid
            
        except Exception as e:
            logger.warning(f"Error checking cache validity: {e}")
            return False

    def _download_catalog(self) -> None:
        """Download KEV catalog from CISA.

        Raises:
            KEVCatalogError: If download fails
        """
        try:
            logger.info(f"Downloading KEV catalog from {self.CISA_KEV_URL}")
            
            # Download JSON
            response = requests.get(self.CISA_KEV_URL, timeout=30)
            response.raise_for_status()
            
            # Ensure cache directory exists
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            
            # Save to cache file
            with open(self.cache_file, "wb") as f:
                f.write(response.content)
            
            logger.info(f"KEV catalog downloaded and cached to {self.cache_file}")
            
        except requests.RequestException as e:
            logger.error(f"Failed to download KEV catalog: {e}")
            raise KEVCatalogError(f"Failed to download KEV catalog: {e}") from e
        except Exception as e:
            logger.error(f"Error saving KEV catalog: {e}")
            raise KEVCatalogError(f"Error saving KEV catalog: {e}") from e

    def _parse_catalog_file(self) -> dict[str, dict]:
        """Parse KEV catalog JSON file.

        Returns:
            Dictionary mapping CVE IDs to vulnerability data

        Raises:
            KEVCatalogError: If parsing fails
        """
        catalog: dict[str, dict] = {}
        
        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # Validate structure
            if "vulnerabilities" not in data:
                raise KEVCatalogError(
                    "Invalid KEV catalog format: 'vulnerabilities' key not found"
                )
            
            vulnerabilities = data.get("vulnerabilities", [])
            
            # Build lookup dictionary
            for vuln in vulnerabilities:
                cve_id = vuln.get("cveID", "").strip().upper()
                
                if cve_id:
                    catalog[cve_id] = vuln
                else:
                    logger.warning("Skipping vulnerability entry without cveID")
            
            return catalog
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse KEV catalog JSON: {e}")
            raise KEVCatalogError(f"Failed to parse KEV catalog JSON: {e}") from e
        except Exception as e:
            logger.error(f"Error reading KEV catalog: {e}")
            raise KEVCatalogError(f"Error reading KEV catalog: {e}") from e
