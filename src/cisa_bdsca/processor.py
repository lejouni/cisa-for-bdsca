"""Vulnerability processing orchestration.

Main processing logic for collecting CISA data from multiple vulnerabilities.
"""

import logging
from typing import Optional

from .client import BlackDuckClient, BlackDuckAPIError
from .config import Config, load_config
from .euvd_mapper import EUVDMapper, EUVDMapperError
from .kev_catalog import KEVCatalog, KEVCatalogError
from .extractors import (
    determine_source_from_id,
    extract_vulnerability_info,
)
from .models import (
    CISAData,
    CollectionResult,
    MappingSource,
    RelatedCVE,
    VulnerabilityInfo,
    VulnerabilitySource,
)

logger = logging.getLogger(__name__)


def process_vulnerabilities(
    vuln_ids: list[str],
    config: Optional[Config] = None,
    use_kev_catalog: bool = False
) -> CollectionResult:
    """Process multiple vulnerabilities and collect CISA data.

    Main orchestration function that:
    1. Pre-scans for EUVD vulnerabilities (lazy loading optimization)
    2. Optionally initializes KEV catalog for enhanced CISA data
    3. Processes each vulnerability based on source type
    4. Collects CISA data and related CVE mappings
    5. Returns comprehensive results

    Args:
        vuln_ids: List of vulnerability IDs (CVE, EUVD, or BDSA)
        config: Optional configuration (loads from environment if None)
        use_kev_catalog: If True, use CISA KEV catalog for enhanced data

    Returns:
        CollectionResult with processed vulnerabilities and metadata
    """
    # Load configuration
    if config is None:
        config = load_config()
    
    # Initialize result
    result = CollectionResult(
        total_count=len(vuln_ids),
        success_count=0,
        error_count=0,
        vulnerabilities=[]
    )
    
    # Initialize Black Duck client
    try:
        bd_client = BlackDuckClient(config)
    except Exception as e:
        logger.error(f"Failed to initialize Black Duck client: {e}")
        for vuln_id in vuln_ids:
            result.add_error(vuln_id, f"Black Duck authentication failed: {e}")
        return result
    
    # Pre-scan for EUVD vulnerabilities (lazy loading optimization)
    has_euvd = any(vid.upper().startswith("EUVD-") for vid in vuln_ids)
    euvd_mapper: Optional[EUVDMapper] = None
    
    if has_euvd:
        logger.info("EUVD vulnerabilities detected, initializing EUVD mapper")
        try:
            euvd_mapper = EUVDMapper(config)
        except Exception as e:
            logger.error(f"Failed to initialize EUVD mapper: {e}")
            # Continue processing, but EUVD resolutions will fail
    else:
        logger.info("No EUVD vulnerabilities detected, skipping EUVD mapper initialization")
    
    # Initialize KEV catalog if requested
    kev_catalog: Optional[KEVCatalog] = None
    
    if use_kev_catalog:
        logger.info("KEV catalog mode enabled, initializing CISA KEV catalog")
        try:
            kev_catalog = KEVCatalog(config)
        except Exception as e:
            logger.error(f"Failed to initialize KEV catalog: {e}")
            # Continue processing, but will use Black Duck CISA data instead
    
    # Process each vulnerability
    for vuln_id in vuln_ids:
        try:
            logger.info(f"Processing {vuln_id}")
            
            # Determine source
            source = determine_source_from_id(vuln_id)
            
            # Update counts
            if source == VulnerabilitySource.NVD:
                result.cve_count += 1
            elif source == VulnerabilitySource.EUVD:
                result.euvd_count += 1
            elif source == VulnerabilitySource.BDSA:
                result.bdsa_count += 1
            
            # Process based on source
            if source == VulnerabilitySource.NVD:
                vuln_info = _process_cve(vuln_id, bd_client, kev_catalog)
            elif source == VulnerabilitySource.BDSA:
                vuln_info = _process_bdsa(vuln_id, bd_client, kev_catalog)
            elif source == VulnerabilitySource.EUVD:
                vuln_info = _process_euvd(vuln_id, bd_client, euvd_mapper, kev_catalog)
            else:
                vuln_info = VulnerabilityInfo(
                    id=vuln_id,
                    source=source,
                    error="Unknown vulnerability source"
                )
            
            # Add to results
            result.vulnerabilities.append(vuln_info)
            
            # Update statistics
            if vuln_info.error:
                result.add_error(vuln_id, vuln_info.error)
            else:
                result.success_count += 1
                
                # Check CISA data availability (top-level for direct CVE queries)
                has_cisa = False
                if vuln_info.cisa_data and vuln_info.cisa_data.has_data():
                    has_cisa = True
                    result.kev_count += 1  # If cisa_data exists, it's in KEV catalog
                
                # Check CISA data in related CVEs (for BDSA/EUVD)
                for related_cve in vuln_info.related_cves:
                    if related_cve.cisa_data and related_cve.cisa_data.has_data():
                        has_cisa = True
                        result.kev_count += 1  # If cisa_data exists, it's in KEV catalog
                
                if has_cisa:
                    result.cisa_available_count += 1
            
        except Exception as e:
            logger.error(f"Unexpected error processing {vuln_id}: {e}")
            result.add_error(vuln_id, f"Unexpected error: {e}")
            
            # Add minimal info to results
            result.vulnerabilities.append(
                VulnerabilityInfo(
                    id=vuln_id,
                    source=determine_source_from_id(vuln_id),
                    error=str(e)
                )
            )
    
    logger.info(
        f"Processing complete: {result.success_count} successful, "
        f"{result.error_count} errors, {result.cisa_available_count} with CISA data, "
        f"{result.kev_count} in KEV"
    )
    
    return result


def _process_cve(
    cve_id: str,
    bd_client: BlackDuckClient,
    kev_catalog: Optional[KEVCatalog] = None
) -> VulnerabilityInfo:
    """Process CVE vulnerability - direct CISA data extraction.

    Args:
        cve_id: CVE ID
        bd_client: Black Duck client
        kev_catalog: Optional KEV catalog for enhanced CISA data

    Returns:
        VulnerabilityInfo with CISA data
    """
    try:
        # Query Black Duck for CVE
        vuln_data = bd_client.get_vulnerability_by_id(cve_id)
        
        if not vuln_data:
            return VulnerabilityInfo(
                id=cve_id,
                source=VulnerabilitySource.NVD,
                error="Vulnerability not found in Black Duck"
            )
        
        # Extract vulnerability info and CISA data
        vuln_info = extract_vulnerability_info(
            cve_id,
            vuln_data,
            VulnerabilitySource.NVD
        )
        
        # If KEV catalog is enabled, override with KEV data
        if kev_catalog:
            kev_data = _get_kev_cisa_data(cve_id, kev_catalog)
            if kev_data:
                vuln_info.cisa_data = kev_data
                logger.debug(f"Enriched {cve_id} with KEV catalog data")
        
        return vuln_info
        
    except BlackDuckAPIError as e:
        logger.error(f"Black Duck API error for {cve_id}: {e}")
        return VulnerabilityInfo(
            id=cve_id,
            source=VulnerabilitySource.NVD,
            error=f"Black Duck API error: {e}"
        )


def _process_bdsa(
    bdsa_id: str,
    bd_client: BlackDuckClient,
    kev_catalog: Optional[KEVCatalog] = None
) -> VulnerabilityInfo:
    """Process BDSA vulnerability - extract related CVE and get CISA data.

    Args:
        bdsa_id: BDSA ID
        bd_client: Black Duck client
        kev_catalog: Optional KEV catalog for enhanced CISA data

    Returns:
        VulnerabilityInfo with related CVE and CISA data
    """
    try:
        # Query Black Duck for BDSA
        vuln_data = bd_client.get_vulnerability_by_id(bdsa_id)
        
        if not vuln_data:
            return VulnerabilityInfo(
                id=bdsa_id,
                source=VulnerabilitySource.BDSA,
                error="Vulnerability not found in Black Duck"
            )
        
        # Extract basic BDSA info
        vuln_info = extract_vulnerability_info(
            bdsa_id,
            vuln_data,
            VulnerabilitySource.BDSA
        )
        
        # Get related CVEs from BDSA metadata
        related_cve_ids = bd_client.get_multiple_related_cves_from_bdsa(vuln_data)
        
        if not related_cve_ids:
            vuln_info.error = "No related CVE found in Black Duck"
            logger.warning(f"No related CVE found for {bdsa_id}")
            return vuln_info
        
        vuln_info.mapping_source = MappingSource.BLACKDUCK
        
        # Fetch full CVE data for each related CVE
        related_cves = []
        for cve_id in related_cve_ids:
            logger.info(f"Fetching related CVE: {cve_id}")
            
            cve_data = bd_client.get_vulnerability_by_id(cve_id)
            if cve_data:
                # Extract CVE info
                cve_info = extract_vulnerability_info(
                    cve_id,
                    cve_data,
                    VulnerabilitySource.NVD
                )
                
                # If KEV catalog is enabled, override with KEV data
                if kev_catalog:
                    kev_data = _get_kev_cisa_data(cve_id, kev_catalog)
                    if kev_data:
                        cve_info.cisa_data = kev_data
                        logger.debug(f"Enriched related CVE {cve_id} with KEV catalog data")
                
                # Build RelatedCVE object
                related_cve = RelatedCVE(
                    id=cve_id,
                    description=cve_info.description,
                    published_date=cve_info.published_date,
                    updated_date=cve_info.updated_date,
                    severity=cve_info.severity,
                    base_score=cve_info.base_score,
                    cisa_data=cve_info.cisa_data
                )
                related_cves.append(related_cve)
                
                if cve_info.cisa_data:
                    logger.debug(f"CISA data found for {cve_id}")
            else:
                logger.warning(f"Could not fetch related CVE {cve_id}")
        
        vuln_info.related_cves = related_cves
        
        if not related_cves:
            vuln_info.error = "Could not fetch any related CVE data"
        
        return vuln_info
        
    except BlackDuckAPIError as e:
        logger.error(f"Black Duck API error for {bdsa_id}: {e}")
        return VulnerabilityInfo(
            id=bdsa_id,
            source=VulnerabilitySource.BDSA,
            error=f"Black Duck API error: {e}"
        )


def _process_euvd(
    euvd_id: str,
    bd_client: BlackDuckClient,
    euvd_mapper: Optional[EUVDMapper],
    kev_catalog: Optional[KEVCatalog] = None
) -> VulnerabilityInfo:
    """Process EUVD vulnerability - map to CVE via ENISA and get CISA data.

    Args:
        euvd_id: EUVD ID
        bd_client: Black Duck client
        euvd_mapper: EUVD mapper (may be None if initialization failed)
        kev_catalog: Optional KEV catalog for enhanced CISA data

    Returns:
        VulnerabilityInfo with related CVE and CISA data
    """
    # Initialize with basic info
    vuln_info = VulnerabilityInfo(
        id=euvd_id,
        source=VulnerabilitySource.EUVD
    )
    
    # Check if EUVD mapper is available
    if euvd_mapper is None:
        vuln_info.error = "EUVD mapper not available"
        logger.error(f"Cannot process {euvd_id}: EUVD mapper not initialized")
        return vuln_info
    
    try:
        # Get related CVE IDs from ENISA mapping
        related_cve_ids = euvd_mapper.get_cves_for_euvd(euvd_id)
        
        if not related_cve_ids:
            vuln_info.error = "No CVE mapping found in ENISA database"
            logger.warning(f"No CVE mapping found for {euvd_id}")
            return vuln_info
        
        vuln_info.mapping_source = MappingSource.ENISA
        
        # Fetch full CVE data for each related CVE
        related_cves = []
        for cve_id in related_cve_ids:
            logger.info(f"Fetching related CVE: {cve_id}")
            
            cve_data = bd_client.get_vulnerability_by_id(cve_id)
            if cve_data:
                # Extract CVE info
                cve_info = extract_vulnerability_info(
                    cve_id,
                    cve_data,
                    VulnerabilitySource.NVD
                )
                
                # If KEV catalog is enabled, override with KEV data
                if kev_catalog:
                    kev_data = _get_kev_cisa_data(cve_id, kev_catalog)
                    if kev_data:
                        cve_info.cisa_data = kev_data
                        logger.debug(f"Enriched related CVE {cve_id} with KEV catalog data")
                
                # Build RelatedCVE object
                related_cve = RelatedCVE(
                    id=cve_id,
                    description=cve_info.description,
                    published_date=cve_info.published_date,
                    updated_date=cve_info.updated_date,
                    severity=cve_info.severity,
                    base_score=cve_info.base_score,
                    cisa_data=cve_info.cisa_data
                )
                related_cves.append(related_cve)
                
                # Use first CVE's data to populate EUVD top-level fields
                if not vuln_info.description:
                    vuln_info.description = cve_info.description
                    vuln_info.published_date = cve_info.published_date
                    vuln_info.updated_date = cve_info.updated_date
                    vuln_info.severity = cve_info.severity
                    vuln_info.base_score = cve_info.base_score
                
                if cve_info.cisa_data:
                    logger.debug(f"CISA data found for {cve_id}")
            else:
                logger.warning(f"Could not fetch related CVE {cve_id} from Black Duck")
        
        vuln_info.related_cves = related_cves
        
        if not related_cves:
            vuln_info.error = "Could not fetch any related CVE data from Black Duck"
        
        return vuln_info
        
    except EUVDMapperError as e:
        logger.error(f"EUVD mapper error for {euvd_id}: {e}")
        vuln_info.error = f"EUVD mapping error: {e}"
        return vuln_info
    except BlackDuckAPIError as e:
        logger.error(f"Black Duck API error for {euvd_id}: {e}")
        vuln_info.error = f"Black Duck API error: {e}"
        return vuln_info


def _get_kev_cisa_data(cve_id: str, kev_catalog: KEVCatalog) -> Optional[CISAData]:
    """Extract CISA data from KEV catalog for given CVE.

    Args:
        cve_id: CVE ID
        kev_catalog: KEV catalog instance

    Returns:
        CISAData object with full KEV catalog fields, or None if not in catalog
    """
    try:
        kev_data = kev_catalog.get_kev_data(cve_id)
        
        if not kev_data:
            return None
        
        # Map KEV catalog fields to CISAData model
        cisa_data = CISAData(
            date_added=kev_data.get("dateAdded"),
            due_date=kev_data.get("dueDate"),
            required_action=kev_data.get("requiredAction"),
            notes=kev_data.get("notes"),
            vendor_project=kev_data.get("vendorProject"),
            product=kev_data.get("product"),
            vulnerability_name=kev_data.get("vulnerabilityName"),
            short_description=kev_data.get("shortDescription"),
            known_ransomware_campaign_use=kev_data.get("knownRansomwareCampaignUse"),
            cwes=kev_data.get("cwes")
        )
        
        return cisa_data
        
    except KEVCatalogError as e:
        logger.warning(f"Error fetching KEV data for {cve_id}: {e}")
        return None
    except Exception as e:
        logger.warning(f"Unexpected error fetching KEV data for {cve_id}: {e}")
        return None
