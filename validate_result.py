#!/usr/bin/env python3
"""Validate CISA BDSCA result files against the JSON schema.

Usage:
    python validate_result.py results.json
    python validate_result.py results1.json results2.json results3.json
"""

import json
import sys
from pathlib import Path


def validate_file(result_file: Path, schema_file: Path) -> bool:
    """Validate a result file against the schema.
    
    Args:
        result_file: Path to the result JSON file
        schema_file: Path to the schema JSON file
        
    Returns:
        True if valid, False otherwise
    """
    try:
        # Try to import jsonschema
        try:
            import jsonschema
            has_jsonschema = True
        except ImportError:
            has_jsonschema = False
            print("ℹ️  Note: Install 'jsonschema' package for full validation: pip install jsonschema")
        
        # Load files
        with open(schema_file, 'r', encoding='utf-8') as f:
            schema = json.load(f)
        
        with open(result_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Basic checks
        print(f"📄 Validating: {result_file}")
        print(f"   Total vulnerabilities: {data.get('total_count', 0)}")
        print(f"   Successful: {data.get('success_count', 0)}")
        print(f"   Errors: {data.get('error_count', 0)}")
        
        # Validate with jsonschema if available
        if has_jsonschema:
            try:
                jsonschema.validate(data, schema)
                print("✅ Valid: Structure matches schema")
                return True
            except jsonschema.ValidationError as e:
                print(f"❌ Invalid: {e.message}")
                print(f"   Path: {' -> '.join(str(p) for p in e.path)}")
                return False
        else:
            # Basic validation without jsonschema
            required_fields = ['timestamp', 'total_count', 'success_count', 'error_count', 
                             'vulnerabilities', 'errors']
            missing = [f for f in required_fields if f not in data]
            
            if missing:
                print(f"❌ Invalid: Missing required fields: {', '.join(missing)}")
                return False
            else:
                print("✅ Basic validation passed (install jsonschema for full validation)")
                return True
                
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON: {e}")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python validate_result.py <result_file.json> [<result_file2.json> ...]")
        print()
        print("Validates CISA BDSCA result files against the JSON schema.")
        print()
        print("Example:")
        print("  python validate_result.py results.json")
        print("  python validate_result.py result1.json result2.json result3.json")
        sys.exit(1)
    
    # Find schema file
    script_dir = Path(__file__).parent
    schema_file = script_dir / "result_schema.json"
    
    if not schema_file.exists():
        print(f"❌ Schema file not found: {schema_file}")
        print("   Make sure result_schema.json is in the same directory as this script.")
        sys.exit(1)
    
    # Validate each file
    results = []
    for result_path in sys.argv[1:]:
        result_file = Path(result_path)
        
        if not result_file.exists():
            print(f"❌ File not found: {result_file}")
            results.append(False)
            continue
        
        valid = validate_file(result_file, schema_file)
        results.append(valid)
        print()
    
    # Summary
    total = len(results)
    valid_count = sum(results)
    invalid_count = total - valid_count
    
    print("=" * 60)
    print(f"Validation Summary: {valid_count}/{total} files valid")
    
    if invalid_count > 0:
        print(f"❌ {invalid_count} file(s) failed validation")
        sys.exit(1)
    else:
        print("✅ All files passed validation")
        sys.exit(0)


if __name__ == "__main__":
    main()
