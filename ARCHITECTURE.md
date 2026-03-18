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
├── .env.example                # Configuration template
├── .gitignore                  # Git ignore rules
├── pyproject.toml             # Project metadata and dependencies (PEP 517/518)
├── requirements.txt           # Production dependencies
├── requirements-dev.txt       # Development dependencies
├── README.md                  # Full documentation
└── QUICKSTART.md             # Quick start guide
```

## Module Overview

### Core Modules

#### `config.py` - Configuration Management
- Loads settings from environment variables and .env file
- Validates Black Duck URL and API token
- Manages cache directory paths
- Pydantic-based settings with validation

#### `models.py` - Data Models
- `CISAData`: CISA vulnerability data extracted from Black Duck
  - KEV fields: `kev_status`, `date_added`, `due_date`, `required_action`, `notes`
  - Pydantic model with field aliases for Black Duck API compatibility
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
- Pre-scan optimization for lazy EUVD loading
- Routes by vulnerability source type
- Handles CVE/BDSA/EUVD processing logic
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
- Verbose logging option
- JSON output with --output

## Data Flow

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

**Output Structure:**
- **CVE**: CISA data at `vulnerabilities[].cisa_data`
- **BDSA/EUVD**: CISA data at `vulnerabilities[].related_cves[].cisa_data`

## Key Features Implementation

### 1. Lazy Loading (EUVD Mapper)
- EUVD mapper only initialized if EUVD IDs detected in input
- Saves unnecessary API calls and CSV parsing
- Cache loaded on first EUVD query

### 2. Cache Management
- EUVD-CVE mapping cached locally
- Validated against 07:00 UTC refresh time
- Automatic download when stale
- Configurable cache directory

### 3. Multi-Source Support
- CVE: Direct CISA data extraction
- BDSA: Resolved via Black Duck `_meta.links`
- EUVD: Resolved via ENISA external API

### 4. Error Handling
- Per-vulnerability error collection
- Fails gracefully without stopping batch
- Detailed error messages
- Non-zero exit code on errors

### 5. Flexible Interface
- CLI for command-line usage
- Python library for integration
- Configurable via environment or .env file
- JSON export with metadata

## Dependencies

### Production
- `blackduck>=1.1.3` - Official Black Duck SDK
- `pydantic>=2.0.0` - Data validation and settings
- `python-dotenv>=1.0.0` - Environment variable loading
- `requests>=2.31.0` - ENISA API calls
- `typer[all]>=0.9.0` - Modern CLI framework

### Development
- `pytest>=7.4.0` - Testing framework
- `pytest-cov>=4.1.0` - Coverage reporting
- `pytest-mock>=3.11.1` - Mocking support
- `black>=23.7.0` - Code formatting
- `flake8>=6.1.0` - Linting
- `mypy>=1.5.0` - Type checking

## Configuration

Required environment variables:
- `BLACKDUCK_URL`: Black Duck instance URL
- `BLACKDUCK_API_TOKEN`: API authentication token

Optional environment variables:
- `BLACKDUCK_VERIFY_SSL`: SSL verification (default: true)
- `OUTPUT_PATH`: Default output directory (default: ./output)
- `EUVD_CACHE_DIR`: EUVD cache location (default: ~/.cache/cisa-bdsca)
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
5. Verify cache refresh logic
6. Test error scenarios

## Extension Points

### Adding New Vulnerability Sources
1. Add enum value to `VulnerabilitySource`
2. Implement detection in `determine_source_from_id()`
3. Add processing function in `processor.py`
4. Update documentation

### Adding New Output Formats
1. Implement formatter in `output.py`
2. Add CLI option in `cli.py`
3. Update documentation

### Custom CISA Fields
1. Update `CISAData` model in `models.py`
2. Update extractor in `extractors.py`
3. Test with your Black Duck instance

## Performance Considerations

- Lazy EUVD mapper initialization saves ~2-5 seconds when not needed
- CSV caching avoids repeated ENISA API calls
- Batch processing supported (process all IDs in one run)
- No parallel API calls (sequential processing for reliability)

## Security Considerations

- API tokens loaded from environment variables
- SSL verification enabled by default
- No credentials logged or written to output
- Cache files have user-only permissions
