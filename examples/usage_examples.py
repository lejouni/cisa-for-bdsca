"""Sample usage examples for cisa_bdsca module."""

# Example 1: Simple CLI usage
"""
# Collect CISA data for specific vulnerabilities
python -m cisa_bdsca collect --ids "CVE-2021-44228,BDSA-2023-1234" --output results.json

# From file
python -m cisa_bdsca collect --ids-file vulnerabilities.txt --output results.json --verbose

# Check configuration
python -m cisa_bdsca config-check
"""

# Example 2: Python library usage
from cisa_bdsca import collect_cisa_data

def example_basic_usage():
    """Basic usage example."""
    vuln_ids = [
        "CVE-2021-44228",   # Log4Shell
        "BDSA-2023-1234",   # Black Duck advisory
        "EUVD-2024-5678"    # EU vulnerability
    ]
    
    # Collect data (uses environment variables for config)
    results = collect_cisa_data(vuln_ids)
    
    # Print summary
    print(f"Processed {results.total_count} vulnerabilities")
    print(f"Found CISA data for {results.cisa_available_count}")
    print(f"KEV vulnerabilities: {results.kev_count}")
    
    # Iterate through results
    for vuln in results.vulnerabilities:
        print(f"\n{vuln.id} ({vuln.source.value})")
        
        # For direct CVE queries, CISA data is at top level
        if vuln.cisa_data and vuln.cisa_data.has_data():
            print(f"  ⚠️ IN CISA KEV CATALOG")
            print(f"  Due date: {vuln.cisa_data.due_date}")
            print(f"  Action: {vuln.cisa_data.required_action}")
        
        # For BDSA/EUVD, check related CVEs (hierarchical structure)
        if vuln.related_cves:
            print(f"  Related CVEs: {len(vuln.related_cves)}")
            for related_cve in vuln.related_cves:
                print(f"    - {related_cve.id}")
                if related_cve.cisa_data and related_cve.cisa_data.has_data():
                    print(f"      ⚠️ IN CISA KEV CATALOG")
                    print(f"      Due date: {related_cve.cisa_data.due_date}")
                    print(f"      Action: {related_cve.cisa_data.required_action}")
        
        if vuln.error:
            print(f"  Error: {vuln.error}")



def example_with_custom_config():
    """Example with custom configuration."""
    from cisa_bdsca.config import Config
    from cisa_bdsca.processor import process_vulnerabilities
    
    # Create custom configuration
    config = Config(
        BLACKDUCK_URL="https://your-instance.blackduck.com",
        BLACKDUCK_API_TOKEN="your_token_here",
        BLACKDUCK_VERIFY_SSL=True,
        EUVD_CACHE_DIR="./cache"
    )
    
    # Process with custom config
    results = process_vulnerabilities(
        vuln_ids=["CVE-2021-44228"],
        config=config
    )
    
    return results


def example_export_results():
    """Example of exporting results to JSON."""
    from cisa_bdsca.output import export_to_json, print_summary
    from pathlib import Path
    
    # Collect data
    results = collect_cisa_data(["CVE-2021-44228"])
    
    # Print summary to console
    print_summary(results)
    
    # Export to JSON
    export_to_json(results, Path("output/results.json"))
    
    # Compact format
    export_to_json(results, Path("output/compact.json"), compact=True)


def example_filter_kev_only():
    """Example: Filter for KEV vulnerabilities only."""
    results = collect_cisa_data([
        "CVE-2021-44228",
        "CVE-2023-1234",
        "CVE-2024-5678"
    ])
    
    # Filter for KEV vulnerabilities (CISA data exists)
    kev_vulns = [
        v for v in results.vulnerabilities
        if v.cisa_data and v.cisa_data.has_data()
    ]
    
    print(f"Found {len(kev_vulns)} KEV vulnerabilities:")
    for vuln in kev_vulns:
        print(f"  {vuln.id}: Due {vuln.cisa_data.due_date}")


def example_batch_processing():
    """Example: Process vulnerabilities from a text file."""
    from pathlib import Path
    
    # Read vulnerability IDs from file
    vuln_file = Path("vulnerabilities.txt")
    
    with open(vuln_file, "r") as f:
        vuln_ids = [line.strip() for line in f if line.strip()]
    
    print(f"Processing {len(vuln_ids)} vulnerabilities...")
    
    # Process in batches
    batch_size = 50
    all_results = []
    
    for i in range(0, len(vuln_ids), batch_size):
        batch = vuln_ids[i:i + batch_size]
        print(f"Processing batch {i//batch_size + 1}...")
        
        results = collect_cisa_data(batch)
        all_results.append(results)
    
    # Combine results
    print(f"Processed {len(all_results)} batches")


def example_direct_client_usage():
    """Example: Direct Black Duck client usage."""
    from cisa_bdsca import BlackDuckClient
    from cisa_bdsca.config import load_config
    
    # Load configuration
    config = load_config()
    
    # Create client
    client = BlackDuckClient(config)
    
    # Get vulnerability details
    vuln_data = client.get_vulnerability_by_id("CVE-2021-44228")
    
    if vuln_data:
        print(f"Name: {vuln_data.get('name')}")
        print(f"Severity: {vuln_data.get('severity')}")
        
        # For BDSA, get related CVEs
        if "BDSA" in vuln_data.get('name', ''):
            related_cves = client.get_multiple_related_cves_from_bdsa(vuln_data)
            print(f"Related CVEs: {related_cves}")


def example_error_handling():
    """Example: Proper error handling."""
    from cisa_bdsca.client import BlackDuckAuthenticationError, BlackDuckAPIError
    from cisa_bdsca.euvd_mapper import EUVDMapperError
    
    try:
        results = collect_cisa_data(["CVE-2021-44228"])
        
        # Check for errors in results
        if results.error_count > 0:
            print(f"⚠️ {results.error_count} errors occurred:")
            for error in results.errors:
                print(f"  {error['vulnerability_id']}: {error['error']}")
        
    except BlackDuckAuthenticationError as e:
        print(f"Authentication failed: {e}")
        print("Check your BLACKDUCK_URL and BLACKDUCK_API_TOKEN")
        
    except BlackDuckAPIError as e:
        print(f"Black Duck API error: {e}")
        
    except EUVDMapperError as e:
        print(f"EUVD mapping error: {e}")
        print("Check internet connectivity to ENISA API")


if __name__ == "__main__":
    # Run basic example
    print("=" * 60)
    print("CISA Data Collection - Basic Example")
    print("=" * 60)
    
    # Note: This requires valid Black Duck configuration
    # Set environment variables or create .env file first
    
    try:
        example_basic_usage()
    except Exception as e:
        print(f"Error: {e}")
        print("\nMake sure to set up your .env file with Black Duck credentials")
        print("See .env.example for required configuration")
