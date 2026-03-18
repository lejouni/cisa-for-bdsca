"""EUVD to CVE mapping service with caching.

Lazy-loads EUVD-CVE mapping from ENISA API with daily refresh at 07:00 UTC.
"""

import csv
import logging
from datetime import datetime, time, timedelta
from typing import Optional

import requests

from .config import Config

logger = logging.getLogger(__name__)


class EUVDMapperError(Exception):
    """Base exception for EUVD mapper errors."""
    pass


class EUVDMapper:
    """Manages EUVD to CVE mapping with caching.

    Lazy-loads mapping file from ENISA API only when first EUVD vulnerability is queried.
    Cache is refreshed daily at 07:00 UTC.
    """

    ENISA_API_URL = "https://euvdservices.enisa.europa.eu/api/dump/cve-euvd-mapping"
    CACHE_FILENAME = "euvd-cve-mapping.csv"

    def __init__(self, config: Config):
        """Initialize EUVD mapper.

        Args:
            config: Configuration object with cache directory setting
        """
        self.config = config
        self.cache_dir = config.euvd_cache_dir
        self.cache_file = self.cache_dir / self.CACHE_FILENAME
        
        # Lazy-loaded mapping dictionary: {euvd_id: [cve_id1, cve_id2, ...]}
        self._mapping: Optional[dict[str, list[str]]] = None
        
        logger.debug(f"EUVD mapper initialized with cache dir: {self.cache_dir}")

    def get_cves_for_euvd(self, euvd_id: str) -> list[str]:
        """Get related CVE IDs for given EUVD ID.

        Lazy-loads mapping on first call.

        Args:
            euvd_id: EUVD vulnerability ID (e.g., "EUVD-2024-1234")

        Returns:
            List of related CVE IDs (may be empty if no mapping found)

        Raises:
            EUVDMapperError: If mapping cannot be loaded
        """
        # Ensure mapping is loaded
        if self._mapping is None:
            self._load_mapping()
        
        # Normalize EUVD ID (case-insensitive lookup)
        euvd_key = euvd_id.upper()
        
        # Get related CVEs
        cves = self._mapping.get(euvd_key, [])
        
        if cves:
            logger.debug(f"Found {len(cves)} CVE(s) for {euvd_id}: {cves}")
        else:
            logger.debug(f"No CVE mapping found for {euvd_id}")
        
        return cves

    def _load_mapping(self) -> None:
        """Load EUVD-CVE mapping from cache or download fresh copy.

        Raises:
            EUVDMapperError: If mapping cannot be loaded
        """
        logger.info("Loading EUVD-CVE mapping...")
        
        # Check if cache is valid
        if self._is_cache_valid():
            logger.info(f"Using cached EUVD mapping from {self.cache_file}")
            self._mapping = self._parse_mapping_file()
        else:
            logger.info("Cache invalid or missing, downloading fresh EUVD mapping")
            self._download_mapping()
            self._mapping = self._parse_mapping_file()
        
        logger.info(f"Loaded {len(self._mapping)} EUVD-CVE mappings")

    def _is_cache_valid(self) -> bool:
        """Check if cached mapping file is valid.

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

    def _download_mapping(self) -> None:
        """Download EUVD-CVE mapping from ENISA API.

        Raises:
            EUVDMapperError: If download fails
        """
        try:
            logger.info(f"Downloading EUVD mapping from {self.ENISA_API_URL}")
            
            # Download CSV
            response = requests.get(self.ENISA_API_URL, timeout=30)
            response.raise_for_status()
            
            # Ensure cache directory exists
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            
            # Save to cache file
            with open(self.cache_file, "wb") as f:
                f.write(response.content)
            
            logger.info(f"EUVD mapping downloaded and cached to {self.cache_file}")
            
        except requests.RequestException as e:
            logger.error(f"Failed to download EUVD mapping: {e}")
            raise EUVDMapperError(f"Failed to download EUVD mapping: {e}") from e
        except Exception as e:
            logger.error(f"Error saving EUVD mapping: {e}")
            raise EUVDMapperError(f"Error saving EUVD mapping: {e}") from e

    def _parse_mapping_file(self) -> dict[str, list[str]]:
        """Parse EUVD-CVE mapping CSV file.

        Expected format: CSV with columns 'euvd_id' and 'cve_id'

        Returns:
            Dictionary mapping EUVD IDs to list of CVE IDs

        Raises:
            EUVDMapperError: If parsing fails
        """
        mapping: dict[str, list[str]] = {}
        
        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                
                # Validate headers
                if "euvd_id" not in reader.fieldnames or "cve_id" not in reader.fieldnames:
                    raise EUVDMapperError(
                        f"Invalid CSV format. Expected columns: euvd_id, cve_id. "
                        f"Found: {reader.fieldnames}"
                    )
                
                # Parse rows
                for row in reader:
                    euvd_id = row["euvd_id"].strip().upper()
                    cve_id = row["cve_id"].strip().upper()
                    
                    if euvd_id and cve_id:
                        # Support multiple CVEs per EUVD
                        if euvd_id not in mapping:
                            mapping[euvd_id] = []
                        mapping[euvd_id].append(cve_id)
            
            return mapping
            
        except FileNotFoundError:
            raise EUVDMapperError(f"Mapping file not found: {self.cache_file}")
        except Exception as e:
            logger.error(f"Error parsing EUVD mapping file: {e}")
            raise EUVDMapperError(f"Error parsing EUVD mapping: {e}") from e

    def clear_cache(self) -> None:
        """Clear cached mapping file."""
        if self.cache_file.exists():
            self.cache_file.unlink()
            logger.info("EUVD cache cleared")
        self._mapping = None
