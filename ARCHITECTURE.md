# Project Structure

```
cisa-for-bdsca/
├── src/
│   └── cisa_bdsca/              # Main package
│       ├── __init__.py          # Package initialization and public API
│       ├── __main__.py          # CLI entry point (python -m cisa_bdsca)
│       ├── cli.py               # Typer CLI commands
│       ├── client.py            # Black Duck API client wrapper
│       ├── config.py            # Configuration management
│       ├── euvd_mapper.py       # EUVD-to-CVE mapping with caching
│       ├── extractors.py        # CISA data extraction logic
│       ├── kev_catalog.py       # CISA KEV Catalog integration (v0.1.1+)
│       ├── models.py            # Pydantic data models
│       ├── output.py            # JSON output formatting
│       └── processor.py         # Main orchestration logic
│
├── tests/                       # Test suite
│   ├── __init__.py
│   ├── conftest.py             # Pytest fixtures
│   ├── test_config.py          # Configuration tests
│   ├── test_extractors.py      # Extractor tests
│   └── test_models.py          # Model tests
│
├── examples/                    # Usage examples
│   ├── sample_vulnerabilities.txt
│   └── usage_examples.py
│
├── result_schema.json          # JSON Schema draft-07 for validation (v0.1.1+)
├── validate_result.py          # Standalone validation script (v0.1.1+)
├── release.ps1                 # Release automation script (v0.1.1+)
├── .env.example                # Configuration template
├── .gitignore                  # Git ignore rules
├── MANIFEST.in                 # Package data manifest
├── pyproject.toml             # Project metadata and dependencies (PEP 517/518)
├── requirements.txt           # Production dependencies
├── requirements-dev.txt       # Development dependencies
├── README.md                  # Full documentation
├── ARCHITECTURE.md            # Technical architecture (this file)
├── IMPLEMENTATION_SUMMARY.md  # Implementation summary
└── QUICKSTART.md             # Quick start guide
```

## Module Overview

### Core Modules

#### `config.py` - Configuration Management
- Loads settings from environment variables and .env file
- Validates Black Duck URL and API token
- Manages cache directory paths (EUVD and KEV)
- Pydantic-based settings with validation
- Uses SettingsConfigDict for Pydantic V2 compatibility (v0.1.2+)

#### `models.py` - Data Models
- `CISAData`: CISA vulnerability data from Black Duck or KEV Catalog
  - Core fields: `date_added`, `due_date`, `required_action`, `notes`
  - Enhanced KEV fields (v0.1.1+): `vendor_project`, `product`, `vulnerability_name`, `short_description`, `known_ransomware_campaign_use`, `cwes`
  - Pydantic model with field aliases for Black Duck API compatibility
  - Uses ConfigDict for Pydantic V2 compatibility (v0.1.2+)
  - `has_data()` method to check if any CISA data is present
- `RelatedCVE`: Full CVE information with nested CISA data
  - ID, description, dates, severity, base_score
  - Nested `cisa_data` field for hierarchical structure
  - Used in BDSA/EUVD vulnerabilities to show which CVE provides CISA data
- `VulnerabilityInfo`: Complete vulnerability information
  - ID, source, description, dates, severity, base_score
  - `related_cves`: List of `RelatedCVE` objects (for EUVD/BDSA) - **hierarchical structure**
  - `mapping_source`: Where CVE mapping came from (Black Duck or ENISA)
  - `cisa_data`: CISA data (only populated for direct CVE queries, null for BDSA/EUVD)
  - Errors, optional raw response
- `CollectionResult`: Processing results and statistics
  - Metadata: timestamp, counts (total, success, error, by source)
  - CISA statistics: available count, KEV count (checks both top-level and nested CISA data)
  - List of vulnerabilities and errors
- `VulnerabilitySource`: Enum for NVD/EUVD/BDSA
- `MappingSource`: Enum for Black Duck/ENISA

**Data Structure Hierarchy:**
- **Direct CVE query**: `VulnerabilityInfo.cisa_data` (top-level)
- **BDSA/EUVD query**: `VulnerabilityInfo.related_cves[].cisa_data` (nested in CVE objects)

#### `client.py` - Black Duck Client
- Wraps official Black Duck Python SDK
- Authentication with Bearer token
- `get_vulnerability_by_id()`: Query vulnerabilities
- `get_related_cve_from_bdsa()`: Extract CVE from BDSA metadata
- Error handling and retry logic

#### `euvd_mapper.py` - EUVD Mapping Service
- Lazy-loaded EUVD-to-CVE mapping
- Downloads CSV from ENISA API
- Cache managed with 07:00 UTC daily refresh
- Only initialized when EUVD vulnerabilities detected

#### `kev_catalog.py` - KEV Catalog Service (v0.1.1+)
- Alternative CISA data source (official CISA KEV catalog)
- Downloads JSON from https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- Lazy-loaded, only initialized when `--use-kev-catalog` flag is used
- Cache managed with 07:00 UTC daily refresh (same as EUVD)
- Provides enhanced metadata: vendor, product, CWEs, ransomware campaigns
- Enriches both CVE and BDSA vulnerabilities (via CVE mapping)

#### `extractors.py` - Data Extraction
- `extract_cisa_data()`: Parse CISA fields from Black Duck response
  - Handles nested `cisa` object structure from Black Duck
  - Maps: `addedDate` → `cisaDateAdded`, `dueDate` → `cisaDueDate`, etc.
- `extract_vulnerability_info()`: Extract vulnerability details
- `determine_source_from_id()`: Detect CVE/EUVD/BDSA from ID

**Black Duck CISA Response Format:**
```json
{
  "cisa": {
    "vulnId": "CVE-2013-0248",
    "addedDate": "2026-02-07T17:03:26.799Z",
    "dueDate": "2026-02-18T17:03:26.799Z",
    "requiredAction": "Required Action",
    "vulnerabilityName": "Name"
  }
}
```

#### `processor.py` - Orchestration
- `process_vulnerabilities()`: Main processing function
  - Accepts `use_kev_catalog` parameter for data source selection (v0.1.1+)
- Pre-scan optimization for lazy EUVD/KEV loading
- Routes by vulnerability source type
- Handles CVE/BDSA/EUVD processing logic
- KEV catalog enrichment for CVE and BDSA (v0.1.1+)
- Aggregates results and errors

#### `output.py` - Output Formatting
- `export_to_json()`: Export results to JSON file
- `format_summary()`: Human-readable summary
- `print_summary()`: Console output
- Compact and pretty-print modes

#### `cli.py` - Command-Line Interface
- Built with Typer for modern CLI
- Commands: `collect`, `config-check`, `clear-cache`
- Supports --ids and --ids-file input
- `--use-kev-catalog` flag for alternative CISA data source (v0.1.1+)
- Verbose logging option
- JSON output with --output

## Data Flow

### Standard Flow (Black Duck Data Source)

```
User Input (CLI/Library)
         ↓
    Processor
         ↓
   ┌────┴────┐
   │ Pre-scan │ → Check for EUVD IDs
   └────┬────┘
        ↓
   ┌─────────────────────────────────────────────────────────────────────┐
   │ For each vulnerability:                                             │
   │                                                                     │
   │  CVE  → Black Duck → Extract CISA data                             │
   │        → VulnerabilityInfo (CISA at top level)                     │
   │                                                                     │
   │  BDSA → Black Duck → Extract related CVE IDs from _meta.links      │
   │        → For each CVE: Black Duck → Extract full CVE data + CISA   │
   │        → VulnerabilityInfo (CISA nested in related_cves[])         │
   │                                                                     │
   │  EUVD → ENISA CSV → Extract related CVE IDs                        │
   │        → For each CVE: Black Duck → Extract full CVE data + CISA   │
   │        → VulnerabilityInfo (CISA nested in related_cves[])         │
   │                                                                     │
   └─────────────────────────────────────────────────────────────────────┘
         ↓
   CollectionResult
         ↓
    JSON Output (Hierarchical Structure)
```

### KEV Catalog Flow (v0.1.1+, --use-kev-catalog)

```
User Input (CLI/Library) + --use-kev-catalog flag
         ↓
    Processor
         ↓
   ┌────────────┐
   │ Initialize │ → Lazy-load KEV Catalog (cached, 07:00 UTC refresh)
   │ KEV Catalog│
   └─────┬──────┘
         ↓
   ┌─────────────────────────────────────────────────────────────────────┐
   │ For each vulnerability:                                             │
   │                                                                     │
   │  CVE  → KEV Catalog lookup → Enhanced CISA data (6 extra fields)   │
   │        → VulnerabilityInfo (enriched CISA at top level)            │
   │                                                                     │
   │  BDSA → Black Duck → Extract related CVE IDs from _meta.links      │
   │        → For each CVE: KEV Catalog → Enhanced CISA data            │
   │        → VulnerabilityInfo (enriched CISA nested in related_cves[])│
   │                                                                     │
   │  EUVD → ENISA CSV → Extract related CVE IDs                        │
   │        → For each CVE: KEV Catalog → Enhanced CISA data            │
   │        → VulnerabilityInfo (enriched CISA nested in related_cves[])│
   │                                                                     │
   └─────────────────────────────────────────────────────────────────────┘
         ↓
   CollectionResult
         ↓
    JSON Output → Validate with JSON Schema (optional)
```

**Output Structure:**
- **CVE**: CISA data at `vulnerabilities[].cisa_data`
- **BDSA/EUVD**: CISA data at `vulnerabilities[].related_cves[].cisa_data`

**KEV Catalog Enhanced Fields (v0.1.1+):**
- `vendor_project`: Vendor/project name
- `product`: Product name
- `vulnerability_name`: Descriptive vulnerability name
- `short_description`: Brief description
- `known_ransomware_campaign_use`: Ransomware usage indicator
- `cwes`: List of CWE IDs

## Key Features Implementation

### 1. Lazy Loading (EUVD Mapper & KEV Catalog)
- EUVD mapper only initialized if EUVD IDs detected in input
- KEV catalog only initialized if `--use-kev-catalog` flag is used (v0.1.1+)
- Saves unnecessary API calls and CSV/JSON parsing
- Cache loaded on first use

### 2. Cache Management
- EUVD-CVE mapping and KEV catalog cached locally
- Validated against 07:00 UTC refresh time
- Automatic download when stale
- Configurable cache directory for both EUVD and KEV

### 3. Dual CISA Data Sources (v0.1.1+)
- **Black Duck** (default): CISA data from Black Duck SCA
  - CVE: Direct CISA data extraction
  - BDSA: Resolved via Black Duck `_meta.links`
  - EUVD: Resolved via ENISA external API
- **KEV Catalog** (--use-kev-catalog): Official CISA catalog
  - Enhanced metadata (6 additional fields)
  - Direct CVE lookup
  - Enriches BDSA via CVE mapping
  - Same EUVD → CVE mapping as Black Duck

### 4. JSON Schema Validation (v0.1.1+)
- Complete JSON Schema draft-07 (`result_schema.json`)
- Standalone validation script (`validate_result.py`)
- Validates structure, enums, patterns, required fields
- Works with/without jsonschema package
- Supports CI/CD integration

### 5. Error Handling
- Per-vulnerability error collection
- Fails gracefully without stopping batch
- Detailed error messages
- Non-zero exit code on errors

### 6. Flexible Interface
- CLI for command-line usage
- Python library for integration
- Configurable via environment or .env file
- JSON export with metadata
- Validation support

### 7. Release Automation (v0.1.1+)
- Comprehensive PowerShell release script (`release.ps1`)
- Version bumping (major/minor/patch)
- Build and upload to PyPI/TestPyPI
- Git tagging and GitHub releases
- Post-upload verification

## Dependencies

### Production (v0.1.2)
- `blackduck>=1.1.3` - Official Black Duck SDK
- `pydantic>=2.12.0` - Data validation and settings
- `pydantic-settings>=2.13.0` - Settings management
- `python-dotenv>=1.2.0` - Environment variable loading
- `requests>=2.32.0` - HTTP client for ENISA and KEV APIs
- `typer>=0.24.0` - Modern CLI framework

### Development (v0.1.2)
- `pytest>=9.0.0` - Testing framework
- `pytest-cov>=7.0.0` - Coverage reporting
- `pytest-mock>=3.15.0` - Mocking support
- `black>=26.3.0` - Code formatting
- `flake8>=7.3.0` - Linting
- `mypy>=1.19.0` - Type checking
- `types-requests>=2.32.0` - Type stubs for requests

## Configuration

Required environment variables:
- `BLACKDUCK_URL`: Black Duck instance URL
- `BLACKDUCK_API_TOKEN`: API authentication token

Optional environment variables:
- `BLACKDUCK_VERIFY_SSL`: SSL verification (default: true)
- `OUTPUT_PATH`: Default output directory (default: ./output)
- `EUVD_CACHE_DIR`: EUVD cache location (default: ~/.cache/cisa-bdsca)
- `KEV_CACHE_DIR`: KEV catalog cache location (default: ~/.cache/cisa-bdsca) (v0.1.1+)
- `LOG_LEVEL`: Logging level (default: INFO)

## Testing Strategy

### Unit Tests
- Configuration validation
- Data model creation and validation
- Source detection from vulnerability IDs
- CISA data extraction
- Error handling

### Integration Tests (Future)
- Black Duck API mocking
- ENISA API mocking
- End-to-end processing
- Cache management

### Manual Testing
1. `config-check` - Verify Black Duck connection
2. Process known CVE with CISA data
3. Process BDSA with related CVE
4. Process EUVD with ENISA mapping
5. Process CVE with `--use-kev-catalog` for enhanced data (v0.1.1+)
6. Validate output with `validate_result.py` (v0.1.1+)
7. Verify cache refresh logic (07:00 UTC for both EUVD and KEV)
8. Test error scenarios

## Extension Points

### Adding New Vulnerability Sources
1. Add enum value to `VulnerabilitySource`
2. Implement detection in `determine_source_from_id()`
3. Add processing function in `processor.py`
4. Update documentation

### Adding New Output Formats
1. Implement formatter in `output.py`
2. Add CLI option in `cli.py`
3. Update JSON schema if structure changes (v0.1.1+)
4. Update documentation

### Custom CISA Fields
1. Update `CISAData` model in `models.py`
2. Update extractor in `extractors.py` or `kev_catalog.py`
3. Update JSON schema (`result_schema.json`) (v0.1.1+)
4. Test with your Black Duck instance or KEV catalog

### Adding Alternative Data Sources (v0.1.1+)
1. Create new module (e.g., `kev_catalog.py`)
2. Implement lazy loading and caching (07:00 UTC pattern)
3. Add CLI flag in `cli.py`
4. Update `processor.py` to use new source
5. Update `CISAData` model if new fields needed
6. Update JSON schema and documentation

## Performance Considerations

- Lazy EUVD mapper initialization saves ~2-5 seconds when not needed
- Lazy KEV catalog initialization (only with `--use-kev-catalog` flag) (v0.1.1+)
- CSV and JSON caching avoids repeated API calls (ENISA and KEV)
- Cache refresh at 07:00 UTC for both EUVD and KEV
- Batch processing supported (process all IDs in one run)
- No parallel API calls (sequential processing for reliability)
- ConfigDict migration reduces Pydantic overhead (v0.1.2+)

## Security Considerations

- API tokens loaded from environment variables
- SSL verification enabled by default
- No credentials logged or written to output
- Cache files have user-only permissions

## Version History

### v0.1.2 (2026-03-19) - Dependency Modernization
**Architectural Changes:**
- Migrated from class-based `Config` to `ConfigDict`/`SettingsConfigDict`
- Updated to Pydantic V2.12+ compatibility patterns
- Applied Black 26.3.0 formatting standards

**Dependency Upgrades:**
- Production: typer 0.24.0, requests 2.32.0, pydantic 2.12.0, pydantic-settings 2.13.0, python-dotenv 1.2.0
- Development: pytest 9.0.0, pytest-cov 7.0.0, black 26.3.0, flake8 7.3.0, mypy 1.19.0

**Impact:** Improved code quality, removed deprecation warnings, modernized codebase

### v0.1.1 (2026-03-18) - Major Feature Expansion
**New Modules:**
- `kev_catalog.py` - CISA KEV Catalog integration (220 lines)
- `result_schema.json` - JSON Schema draft-07 for validation (400 lines)
- `validate_result.py` - Standalone validation script (120 lines)
- `release.ps1` - Release automation (450 lines)

**Enhanced Data Model:**
- Added 6 KEV-specific fields to CISAData: vendor_project, product, vulnerability_name, short_description, known_ransomware_campaign_use, cwes
- Removed redundant fields: name, raw_data, kev_status, SSVC fields

**New Features:**
- Dual CISA data sources (Black Duck + KEV Catalog)
- `--use-kev-catalog` CLI flag
- JSON Schema validation workflow
- Complete release automation

**Impact:** Significant feature expansion, enhanced data richness, production-ready validation

### v0.1.0 (2026-03-18) - Initial Release
**Core Architecture:**
- 9 Python modules (~1,615 lines)
- Modular design: config, models, client, extractors, processor, output
- CLI and library interfaces

**Key Features:**
- Black Duck SCA integration
- Multi-source support (CVE, EUVD, BDSA)
- EUVD-CVE mapping via ENISA API
- Lazy loading optimization
- Cache management (07:00 UTC refresh)
- Error handling and logging

**Impact:** Production-ready initial release
