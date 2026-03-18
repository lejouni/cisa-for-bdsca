# Quick Start Guide

## 1. Install

### Automated Installation (Windows - Recommended)

Run the installation script:

```powershell
.\install.ps1
```

This handles everything: Python check, virtual environment, package installation, and .env setup.

### Manual Installation

```powershell
# Create virtual environment (optional but recommended)
python -m venv .venv
.venv\Scripts\Activate.ps1

# Install package
pip install -e .
```

For development (with testing tools):
```powershell
pip install -e ".[dev]"
```

## 2. Configure Black Duck Connection

If you used `install.ps1`, a `.env` file was created automatically. Otherwise, create it:

```powershell
Copy-Item .env.example .env
```

Edit `.env` with your Black Duck credentials:
```
BLACKDUCK_URL=https://your-instance.blackduck.com
BLACKDUCK_API_TOKEN=your_api_token_here
BLACKDUCK_VERIFY_SSL=true
```

## 3. Verify Configuration

```powershell
cisa-bdsca config-check
```

You should see:
```
✓ Configuration loaded successfully
✓ Successfully connected to Black Duck
✓ All checks passed!
```

## 4. Run Your First Query

### Using CLI with specific IDs

```powershell
python -m cisa_bdsca collect --ids "CVE-2021-44228" --output results.json
```

### Using CLI with file input

```powershell
python -m cisa_bdsca collect --ids-file examples\sample_vulnerabilities.txt --output results.json --verbose
```

### Using Python Library

Create a Python script:

```python
from cisa_bdsca import collect_cisa_data
from cisa_bdsca.output import export_to_json, print_summary
from pathlib import Path

# Collect data
results = collect_cisa_data([
    "CVE-2021-44228",  # Log4Shell
    "CVE-2023-23397",  # Outlook vulnerability
])

# Print summary
print_summary(results)

# Export to JSON
export_to_json(results, Path("my_results.json"))
```

Run it:
```powershell
python your_script.py
```

## 5. View Results

Open `results.json` to see the structured output with:
- Vulnerability details
- CISA KEV status
- Related CVE mappings (for EUVD/BDSA)
- Error information

## Common Commands

```powershell
# Check version
python -m cisa_bdsca --version

# Get help
python -m cisa_bdsca --help
python -m cisa_bdsca collect --help

# Enable verbose logging
python -m cisa_bdsca collect --ids "CVE-2021-44228" --verbose

# Clear EUVD cache (forces fresh download)
python -m cisa_bdsca clear-cache
```

## Run Tests

```powershell
# Install dev dependencies first
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src/cisa_bdsca --cov-report=html
```

## Troubleshooting

### Authentication Error

If you see `BlackDuckAuthenticationError`:
1. Verify your `BLACKDUCK_URL` is correct
2. Check your `BLACKDUCK_API_TOKEN` is valid
3. Ensure token has read permissions for vulnerabilities

### EUVD Download Error

If EUVD mapping fails:
1. Check internet connectivity
2. Verify ENISA API is accessible
3. Clear cache: `python -m cisa_bdsca clear-cache`

### No CISA Data Found

This is expected for:
- Vulnerabilities not in CISA KEV catalog
- EUVD/BDSA without related CVE mappings
- CVEs that don't have CISA data in Black Duck

## Next Steps

- Review [examples/usage_examples.py](examples/usage_examples.py) for more code samples
- Read the full [README.md](README.md) for comprehensive documentation
- Customize configuration in `.env` for your environment
