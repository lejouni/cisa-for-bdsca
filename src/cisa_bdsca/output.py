"""JSON output formatting for CISA data collection results.

Handles export of CollectionResult to JSON files with configurable formatting.
"""

import json
import logging
from pathlib import Path

from .models import CollectionResult

logger = logging.getLogger(__name__)


def export_to_json(
    result: CollectionResult,
    output_path: Path,
    compact: bool = False,
    sort_keys: bool = True
) -> None:
    """Export collection result to JSON file.

    Args:
        result: CollectionResult to export
        output_path: Path to output JSON file
        compact: If True, use compact formatting (no indentation)
        sort_keys: If True, sort dictionary keys in output

    Raises:
        IOError: If file cannot be written
    """
    try:
        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert to JSON
        if compact:
            json_str = result.model_dump_json(indent=None)
        else:
            json_str = result.model_dump_json(indent=2)
        
        # Optionally sort keys
        if sort_keys and not compact:
            # Re-parse and dump with sorted keys
            data = json.loads(json_str)
            json_str = json.dumps(data, indent=2, sort_keys=True)
        
        # Write to file
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_str)
        
        logger.info(f"Results exported to {output_path}")
        
    except Exception as e:
        logger.error(f"Failed to export results to {output_path}: {e}")
        raise IOError(f"Failed to write output file: {e}") from e


def format_summary(result: CollectionResult) -> str:
    """Format a human-readable summary of collection results.

    Args:
        result: CollectionResult to summarize

    Returns:
        Multi-line string with summary statistics
    """
    lines = [
        "=" * 60,
        "CISA Data Collection Summary",
        "=" * 60,
        "",
        f"Total Vulnerabilities: {result.total_count}",
        f"  - CVE (NVD):  {result.cve_count}",
        f"  - EUVD:       {result.euvd_count}",
        f"  - BDSA:       {result.bdsa_count}",
        "",
        "Processing Results:",
        f"  - Successful: {result.success_count}",
        f"  - Errors:     {result.error_count}",
        "",
        "CISA Data Availability:",
        f"  - With CISA data: {result.cisa_available_count}",
        f"  - In KEV catalog: {result.kev_count}",
        "",
    ]
    
    if result.errors:
        lines.append(f"Errors ({len(result.errors)}):")
        for error in result.errors[:5]:  # Show first 5 errors
            vuln_id = error.get("vulnerability_id", "Unknown")
            error_msg = error.get("error", "Unknown error")
            lines.append(f"  - {vuln_id}: {error_msg}")
        
        if len(result.errors) > 5:
            lines.append(f"  ... and {len(result.errors) - 5} more")
        lines.append("")
    
    lines.append("=" * 60)
    
    return "\n".join(lines)


def print_summary(result: CollectionResult) -> None:
    """Print summary to console.

    Args:
        result: CollectionResult to summarize
    """
    print(format_summary(result))


def export_vulnerabilities_only(
    result: CollectionResult,
    output_path: Path,
    compact: bool = False
) -> None:
    """Export only vulnerability data (without metadata) to JSON.

    Useful for importing into other tools.

    Args:
        result: CollectionResult containing vulnerabilities
        output_path: Path to output JSON file
        compact: If True, use compact formatting

    Raises:
        IOError: If file cannot be written
    """
    try:
        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert vulnerabilities to dict
        vulns_data = [v.model_dump(exclude_none=True) for v in result.vulnerabilities]
        
        # Write to file
        with open(output_path, "w", encoding="utf-8") as f:
            if compact:
                json.dump(vulns_data, f)
            else:
                json.dump(vulns_data, f, indent=2)
        
        logger.info(f"Vulnerabilities exported to {output_path}")
        
    except Exception as e:
        logger.error(f"Failed to export vulnerabilities to {output_path}: {e}")
        raise IOError(f"Failed to write output file: {e}") from e
