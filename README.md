# CISA for BDSCA

A Python module to collect CISA (Cybersecurity and Infrastructure Security Agency) vulnerability information from Black Duck SCA. Supports CVE (NVD), EUVD, and BDSA vulnerability sources with automatic CVE resolution for EUVD and BDSA vulnerabilities.

## Features

- ✅ **Multi-source vulnerability support**: CVE, EUVD, and BDSA
- ✅ **CISA KEV integration**: Identifies Known Exploited Vulnerabilities
- ✅ **Dual CISA data sources**: 
  - Black Duck embedded CISA data (default)
  - CISA KEV catalog with enhanced fields (--use-kev-catalog)
- ✅ **Automatic CVE mapping**: 
  - BDSA → CVE via Black Duck `_meta.links`
  - EUVD → CVE via ENISA public API
- ✅ **Lazy loading**: EUVD mapping and KEV catalog only downloaded when needed
- ✅ **Daily cache refresh**: EUVD-CVE mapping and KEV catalog updated at 07:00 UTC
- ✅ **Dual interface**: Use as CLI tool or Python library
- ✅ **JSON export**: Structured output with comprehensive metadata
- ✅ **JSON Schema**: Validate output with included result_schema.json

## Installation

### Windows (Recommended)

Clone the repository and run the installation script:

```powershell
git clone <repository-url>
cd cisa-for-bdsca
.\install.ps1
```

The script will automatically:
- Check Python version (requires 3.10+)
- Create a virtual environment
- Install the package
- Set up .env configuration template
- Verify the installation

### Manual Installation

```bash
git clone <repository-url>
cd cisa-for-bdsca

# Create virtual environment (optional but recommended)
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\Activate.ps1  # Windows PowerShell

# Install package
pip install -e .
```

### Development Installation

```bash
pip install -e ".[dev]"
```

## Configuration

Create a `.env` file in your project directory (or use environment variables):

```bash
# Required: Black Duck Configuration
BLACKDUCK_URL=https://your-instance.blackduck.com
BLACKDUCK_API_TOKEN=your_api_token_here
BLACKDUCK_VERIFY_SSL=true

# Optional: Output Configuration
OUTPUT_PATH=./output
EUVD_CACHE_DIR=~/.cache/cisa-bdsca
KEV_CACHE_DIR=~/.cache/cisa-bdsca
LOG_LEVEL=INFO
```

**Cache Configuration:**
- `EUVD_CACHE_DIR`: Directory for caching EUVD-to-CVE mapping (default: `~/.cache/cisa-bdsca`)
- `KEV_CACHE_DIR`: Directory for caching CISA KEV catalog (default: `~/.cache/cisa-bdsca`)
- Both caches refresh daily at 07:00 UTC


### Getting Black Duck API Token

1. Log in to your Black Duck instance
2. Navigate to **User Settings** → **API Tokens**
3. Generate a new token with read permissions
4. Copy the token to your `.env` file

## Usage

### Command Line Interface

#### Collect CISA data for specific vulnerabilities

```bash
# Single or multiple IDs (comma-separated)
cisa-bdsca collect --ids "CVE-2021-44228,BDSA-2023-1234,EUVD-2024-5678" --output results.json

# From file (one ID per line)
cisa-bdsca collect --ids-file vulnerabilities.txt --output results.json

# Use CISA KEV catalog for enhanced CVE data (includes vendor, product, CWEs, etc.)
cisa-bdsca collect --ids "CVE-2025-47813" --use-kev-catalog --output results.json

# With verbose logging
cisa-bdsca collect --ids "CVE-2021-44228" --output results.json --verbose

# Compact JSON output
cisa-bdsca collect --ids "CVE-2021-44228" --output results.json --compact
```

#### CISA Data Sources

The tool supports two CISA data sources:

1. **Black Duck (default)**: Uses CISA data embedded in Black Duck vulnerability responses
   - Provides basic KEV fields: date_added, due_date, required_action, notes
   - Available for CVE vulnerabilities only

2. **CISA KEV Catalog (--use-kev-catalog)**: Downloads and uses official CISA KEV catalog
   - Provides comprehensive KEV data including:
     - All basic fields (date_added, due_date, required_action, notes)
     - vendor_project, product, vulnerability_name
     - short_description
     - known_ransomware_campaign_use
     - cwes (Common Weakness Enumeration codes)
   - Downloaded once daily and cached locally
   - Works for both direct CVE queries and related CVEs in BDSA/EUVD


#### Check configuration and connection

```bash
cisa-bdsca config-check
```

#### Clear EUVD cache

```bash
cisa-bdsca clear-cache
```

### Python Library

```python
from cisa_bdsca import collect_cisa_data

# Collect CISA data
vuln_ids = [
    "CVE-2021-44228",      # Log4Shell - direct CVE lookup
    "BDSA-2023-1234",      # Black Duck advisory - maps to CVE
    "EUVD-2024-5678"       # EU vulnerability - maps to CVE via ENISA
]

results = collect_cisa_data(vuln_ids)

# Access results
print(f"Total: {results.total_count}")
print(f"KEV count: {results.kev_count}")

for vuln in results.vulnerabilities:
    print(f"{vuln.id}: {vuln.source.value}")
    
    # For direct CVE queries, CISA data is at top level
    # If cisa_data exists, the vulnerability is in KEV catalog
    if vuln.cisa_data:
        print(f"  ⚠️ In CISA KEV catalog!")
        print(f"  Due date: {vuln.cisa_data.due_date}")
    
    # For BDSA/EUVD, CISA data is in related CVEs (hierarchical)
    for related_cve in vuln.related_cves:
        print(f"  Related: {related_cve.id}")
        if related_cve.cisa_data:
            print(f"    ⚠️ In CISA KEV catalog!")
            print(f"    Due date: {related_cve.cisa_data.due_date}")

# Export to JSON
from cisa_bdsca.output import export_to_json
from pathlib import Path

export_to_json(results, Path("output.json"))
```

### Advanced Usage

```python
from cisa_bdsca import BlackDuckClient
from cisa_bdsca.config import load_config
from cisa_bdsca.processor import process_vulnerabilities

# Custom configuration
config = load_config(env_file="/path/to/.env")

# Process with custom settings
results = process_vulnerabilities(
    vuln_ids=["CVE-2021-44228"],
    config=config
)

# Direct Black Duck client usage
client = BlackDuckClient(config)
vuln_data = client.get_vulnerability_by_id("CVE-2021-44228")
```

## How It Works

### Vulnerability Source Detection

The module automatically detects vulnerability source by ID prefix:

- **CVE-*** → NVD (National Vulnerability Database)
- **EUVD-*** → EUVD (EU Vulnerability Database)  
- **BDSA-*** → BDSA (Black Duck Security Advisory)

### CVE Resolution for EUVD/BDSA

#### BDSA → CVE (Black Duck Internal)

1. Query Black Duck for BDSA vulnerability
2. Parse `_meta.links` array for `rel="related-vulnerability"` with `label="NVD"`
3. Extract CVE ID from link `href`
4. Query Black Duck for CVE to get CISA data

#### EUVD → CVE (External ENISA API)

1. **Lazy loading**: Check if any EUVD IDs are in the input list
2. If yes, load EUVD-CVE mapping from cache or download from ENISA API
3. Map EUVD ID to CVE ID(s) using CSV data
4. Query Black Duck for CVE to get CISA data

**ENISA API:** `https://euvdservices.enisa.europa.eu/api/dump/cve-euvd-mapping`

**Cache strategy:**
- CSV file cached in `~/.cache/cisa-bdsca/` (configurable)
- Valid until next **07:00 UTC** (ENISA updates daily)
- Automatically refreshed on next query after 07:00 UTC
- **Only downloaded if EUVD vulnerabilities are in the input list**

### CISA Data Extraction

CISA data is only available for CVE vulnerabilities in Black Duck:

- **KEV Status**: Known Exploited Vulnerabilities catalog inclusion
- **Remediation**: Due dates and required actions

## Output Format

### JSON Structure

The output format is hierarchical: **CISA data for BDSA/EUVD vulnerabilities is nested within their related CVE objects**.

#### Basic Structure (Black Duck CISA Data)

```json
{
  "timestamp": "2026-03-18T10:30:00",
  "total_count": 3,
  "success_count": 3,
  "error_count": 0,
  "cve_count": 1,
  "euvd_count": 1,
  "bdsa_count": 1,
  "cisa_available_count": 2,
  "kev_count": 1,
  "vulnerabilities": [
    {
      "id": "CVE-2021-44228",
      "source": "NVD",
      "severity": "CRITICAL",
      "base_score": 10.0,
      "related_cves": [],
      "mapping_source": null,
      "cisa_data": {
        "date_added": "2021-12-10",
        "due_date": "2021-12-24",
        "required_action": "Apply updates per vendor instructions",
        "notes": "Log4j Remote Code Execution Vulnerability"
      }
    },
    {
      "id": "BDSA-2023-1234",
      "source": "BDSA",
      "severity": "HIGH",
      "base_score": 9.0,
      "cisa_data": null,
      "mapping_source": "Black Duck",
      "related_cves": [
        {
          "id": "CVE-2023-5678",
          "description": "Vulnerability description...",
          "severity": "HIGH",
          "base_score": 9.0,
          "published_date": "2023-01-15T10:00:00",
          "updated_date": "2023-02-01T12:00:00",
          "cisa_data": {
            "date_added": "2023-02-01",
            "due_date": "2023-02-22",
            "required_action": "Apply mitigations per vendor instructions",
            "notes": "Additional vulnerability information"
          }
        }
      ]
    },
    {
      "id": "EUVD-2024-5678",
      "source": "EUVD",
      "cisa_data": null,
      "mapping_source": "ENISA",
      "related_cves": [
        {
          "id": "CVE-2024-9999",
          "description": "Vulnerability description...",
          "cisa_data": null
        }
      ],
      "error": null
    }
  ],
  "errors": []
}
```

#### Enhanced Structure (--use-kev-catalog)

When using `--use-kev-catalog`, the CISA data includes additional fields from the official CISA KEV catalog:

```json
{
  "id": "CVE-2025-47813",
  "source": "NVD",
  "cisa_data": {
    "date_added": "2026-03-16",
    "due_date": "2026-03-30",
    "required_action": "Apply mitigations per vendor instructions...",
    "notes": "https://www.wftpserver.com/serverhistory.htm ; ...",
    "vendor_project": "Wing FTP Server",
    "product": "Wing FTP Server",
    "vulnerability_name": "Wing FTP Server Information Disclosure Vulnerability",
    "short_description": "Wing FTP Server contains a generation of error message...",
    "known_ransomware_campaign_use": "Unknown",
    "cwes": ["CWE-209"]
  }
}
```

**Additional KEV Catalog Fields:**
- `vendor_project`: Vendor or project name
- `product`: Affected product name
- `vulnerability_name`: Official vulnerability name
- `short_description`: Detailed vulnerability description
- `known_ransomware_campaign_use`: "Known" if used in ransomware, "Unknown" otherwise
- `cwes`: List of Common Weakness Enumeration codes

**Key Points:**
- **Direct CVE queries**: CISA data at top level, `related_cves` is empty
- **BDSA/EUVD queries**: CISA data nested inside `related_cves[].cisa_data`, top-level `cisa_data` is null
- **KEV Status**: If `cisa_data` exists (not null), the vulnerability is in the CISA Known Exploited Vulnerabilities catalog
- This hierarchical structure clearly shows which CVE provides the CISA/KEV information

### JSON Schema

A JSON Schema file ([result_schema.json](result_schema.json)) is provided to validate output files. The schema defines:

- Required fields and their types
- Valid values for enums (source, severity, mapping_source, etc.)
- Format constraints (dates, CVE ID patterns, CVSS scores)
- Hierarchical structure (vulnerabilities, related CVEs, CISA data)

**Validation with included script:**

```bash
# Validate single file
python validate_result.py results.json

# Validate multiple files
python validate_result.py result1.json result2.json result3.json
```

The validation script provides:
- ✅ Automatic schema loading
- ✅ Clear success/error messages
- ✅ Summary statistics
- ✅ Works with or without jsonschema package (basic validation without, full with)

**Manual validation:**

```bash
# Using Python jsonschema (install first: pip install jsonschema)
python -c "
import json
import jsonschema

with open('result_schema.json') as f:
    schema = json.load(f)

with open('results.json') as f:
    data = json.load(f)

jsonschema.validate(data, schema)
print('✓ JSON is valid')
"

# Using ajv-cli (Node.js - install: npm install -g ajv-cli)
ajv validate -s result_schema.json -d results.json
```

### Console Summary

```
============================================================
CISA Data Collection Summary
============================================================

Total Vulnerabilities: 3
  - CVE (NVD):  1
  - EUVD:       1
  - BDSA:       1

Processing Results:
  - Successful: 3
  - Errors:     0

CISA Data Availability:
  - With CISA data: 2
  - In KEV catalog: 1

============================================================
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   CLI / Library API                     │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                   Processor (Orchestration)              │
│  • Pre-scan for EUVD (lazy loading optimization)        │
│  • Route by vulnerability source                        │
└─────────────────────────────────────────────────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼
    ┌────────┐      ┌────────────┐    ┌────────────┐
    │  CVE   │      │    BDSA    │    │    EUVD    │
    │ Direct │      │  BD Links  │    │ ENISA API  │
    └────────┘      └────────────┘    └────────────┘
         │                 │                 │
         └─────────────────┼─────────────────┘
                           ▼
                ┌──────────────────────┐
                │  Black Duck Client   │
                │  • Get vulnerability │
                │  • Extract CISA data │
                └──────────────────────┘
                           ▼
                ┌──────────────────────┐
                │    JSON Output       │
                └──────────────────────┘
```

## Development

### Run tests

```bash
pytest tests/ -v
```

### Code formatting

```bash
black src/ tests/
flake8 src/
```

### Type checking

```bash
mypy src/
```

### Creating a Release

The project includes a PowerShell release script (`release.ps1`) that automates the release process:

**Basic release (bump patch version):**
```powershell
# Dry run to see what would happen
.\release.ps1 -DryRun

# Actual release to PyPI
.\release.ps1 -Part patch -Repository pypi
```

**Version bumping:**
```powershell
# Bump minor version (0.1.0 -> 0.2.0)
.\release.ps1 -Part minor

# Bump major version (0.1.0 -> 1.0.0)
.\release.ps1 -Part major

# Set explicit version
.\release.ps1 -NewVersion 1.2.3
```

**Advanced options:**
```powershell
# Publish to TestPyPI first
.\release.ps1 -Repository testpypi

# Skip install verification
.\release.ps1 -NoInstallTest

# Create GitHub release with tag
.\release.ps1 -CreateGitHubRelease -GitHubToken "ghp_..." -GitHubRepo "yourusername/cisa-for-bdsca"

# Build only, no upload (for testing)
.\release.ps1 -NoUpload

# Use local build artifacts
.\release.ps1 -SkipBuild -NoUpload
```

The script will:
1. Update version in `pyproject.toml` and `src/cisa_bdsca/__init__.py`
2. Build wheel and source distribution
3. Upload to PyPI or TestPyPI
4. Optionally create and push a git tag
5. Optionally create a GitHub release
6. Verify installation in a clean virtual environment

## Troubleshooting

### Authentication Failed

**Error:** `BlackDuckAuthenticationError: Failed to authenticate`

**Solution:**
- Verify `BLACKDUCK_URL` is correct (no trailing slash)
- Check `BLACKDUCK_API_TOKEN` is valid
- Ensure token has read permissions for vulnerabilities
- Test with `cisa-bdsca config-check`

### EUVD Mapping Failed

**Error:** `EUVDMapperError: Failed to download EUVD mapping`

**Solution:**
- Check internet connectivity
- Verify ENISA API is accessible: `curl https://euvdservices.enisa.europa.eu/api/dump/cve-euvd-mapping`
- Clear cache and retry: `cisa-bdsca clear-cache`

### No CISA Data Found

**Expected behavior:** CISA data is only available for CVE vulnerabilities in Black Duck.

For EUVD/BDSA:
1. Check if related CVE exists (see `related_cves` in output)
2. Related CVE may not have CISA data available
3. CISA KEV catalog is limited to actively exploited vulnerabilities

### Rate Limiting

If processing many vulnerabilities, Black Duck may rate-limit requests.

**Solution:** Process in smaller batches or add delays between requests (future enhancement).

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - See LICENSE file for details

## Acknowledgments

- **Black Duck** by Synopsys for vulnerability data
- **CISA** for KEV catalog
- **ENISA** for EUVD-CVE mapping API

## Support

For issues or questions:
- Open an issue on GitHub
- Check Black Duck API documentation: `https://your-instance.blackduck.com/api-doc/public.html`
- Review ENISA API documentation: https://euvdb.cert.europa.eu/

## Changelog

### v0.1.0 (2026-03-18)

- Initial release
- Support for CVE, EUVD, and BDSA vulnerabilities
- CISA KEV data extraction
- BDSA → CVE mapping via Black Duck
- EUVD → CVE mapping via ENISA API
- Lazy loading for EUVD mapper
- CLI and library interfaces
- JSON export with comprehensive metadata
