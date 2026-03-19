"""Command-line interface for cisa_bdsca.

Built with Typer for modern, type-safe CLI.
"""

import logging
from pathlib import Path
from typing import Optional

import typer
from typing_extensions import Annotated

from . import __version__
from .config import load_config
from .output import export_to_json, print_summary
from .processor import process_vulnerabilities

# Create Typer app
app = typer.Typer(
    name="cisa-bdsca",
    help="Collect CISA vulnerability information from Black Duck SCA",
    add_completion=False,
)


def setup_logging(verbose: bool = False) -> None:
    """Configure logging based on verbosity level."""
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Reduce noise from external libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        typer.echo(f"cisa-bdsca version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            "-v",
            callback=version_callback,
            is_eager=True,
            help="Show version and exit",
        ),
    ] = None,
) -> None:
    """CISA vulnerability data collector for Black Duck SCA."""
    pass


@app.command()
def collect(
    ids: Annotated[
        Optional[str],
        typer.Option("--ids", "-i", help="Comma-separated list of vulnerability IDs"),
    ] = None,
    ids_file: Annotated[
        Optional[Path],
        typer.Option("--ids-file", "-f", help="File containing vulnerability IDs (one per line)"),
    ] = None,
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Output JSON file path"),
    ] = None,
    compact: Annotated[
        bool,
        typer.Option("--compact", help="Use compact JSON formatting"),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", help="Enable verbose logging"),
    ] = False,
    use_kev_catalog: Annotated[
        bool,
        typer.Option(
            "--use-kev-catalog",
            help="Use CISA KEV catalog as CISA data source (includes full vulnerability details)",
        ),
    ] = False,
    env_file: Annotated[
        Optional[Path],
        typer.Option("--env-file", help="Path to .env file"),
    ] = None,
) -> None:
    """Collect CISA data for vulnerability IDs.

    Provide vulnerability IDs either via --ids or --ids-file.
    Supports CVE, EUVD, and BDSA format IDs.

    Examples:
        cisa-bdsca collect --ids "CVE-2021-44228,BDSA-2023-1234" -o results.json

        cisa-bdsca collect --ids-file vulns.txt --output results.json --verbose
    """
    # Setup logging
    setup_logging(verbose)
    logger = logging.getLogger(__name__)

    # Validate input
    if not ids and not ids_file:
        typer.echo("Error: Must provide either --ids or --ids-file", err=True)
        raise typer.Exit(1)

    if ids and ids_file:
        typer.echo("Error: Cannot use both --ids and --ids-file", err=True)
        raise typer.Exit(1)

    # Parse vulnerability IDs
    vuln_ids = []

    if ids:
        # Parse comma-separated IDs
        vuln_ids = [vid.strip() for vid in ids.split(",") if vid.strip()]
    elif ids_file:
        # Read from file
        try:
            with open(ids_file, "r", encoding="utf-8") as f:
                vuln_ids = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            typer.echo(f"Error: File not found: {ids_file}", err=True)
            raise typer.Exit(1)
        except Exception as e:
            typer.echo(f"Error reading file {ids_file}: {e}", err=True)
            raise typer.Exit(1)

    if not vuln_ids:
        typer.echo("Error: No vulnerability IDs provided", err=True)
        raise typer.Exit(1)

    logger.info(f"Processing {len(vuln_ids)} vulnerability IDs")

    # Load configuration
    try:
        config = load_config(str(env_file) if env_file else None)
    except Exception as e:
        typer.echo(f"Configuration error: {e}", err=True)
        raise typer.Exit(1)

    # Process vulnerabilities
    try:
        result = process_vulnerabilities(vuln_ids, config, use_kev_catalog=use_kev_catalog)
    except Exception as e:
        typer.echo(f"Processing failed: {e}", err=True)
        logger.exception("Processing failed")
        raise typer.Exit(1)

    # Print summary to console
    print_summary(result)

    # Export to file if requested
    if output:
        try:
            export_to_json(result, output, compact=compact)
            typer.echo(f"\nResults written to: {output}")
        except Exception as e:
            typer.echo(f"Error writing output file: {e}", err=True)
            raise typer.Exit(1)
    else:
        typer.echo("\nNo output file specified. Use --output to save results.")

    # Exit with error code if there were processing errors
    if result.error_count > 0:
        raise typer.Exit(1)


@app.command()
def config_check(
    env_file: Annotated[
        Optional[Path],
        typer.Option("--env-file", help="Path to .env file"),
    ] = None,
) -> None:
    """Check Black Duck configuration and connection.

    Validates configuration and tests connection to Black Duck.
    """
    setup_logging(verbose=True)

    typer.echo("Checking Black Duck configuration...")

    # Load configuration
    try:
        config = load_config(str(env_file) if env_file else None)
        typer.echo("✓ Configuration loaded successfully")
        typer.echo(f"  Black Duck URL: {config.blackduck_url}")
        typer.echo(f"  Verify SSL: {config.blackduck_verify_ssl}")
        typer.echo(f"  EUVD cache dir: {config.euvd_cache_dir}")
    except Exception as e:
        typer.echo(f"✗ Configuration error: {e}", err=True)
        raise typer.Exit(1)

    # Test connection
    try:
        from .client import BlackDuckClient

        typer.echo("\nTesting Black Duck connection...")
        client = BlackDuckClient(config)

        if client.check_connection():
            typer.echo("✓ Successfully connected to Black Duck")
        else:
            typer.echo("✗ Connection check failed", err=True)
            raise typer.Exit(1)

    except Exception as e:
        typer.echo(f"✗ Connection failed: {e}", err=True)
        raise typer.Exit(1)

    typer.echo("\n✓ All checks passed!")


@app.command()
def clear_cache(
    env_file: Annotated[
        Optional[Path],
        typer.Option("--env-file", help="Path to .env file"),
    ] = None,
) -> None:
    """Clear EUVD-CVE mapping cache.

    Forces fresh download on next EUVD query.
    """
    from .euvd_mapper import EUVDMapper

    try:
        config = load_config(str(env_file) if env_file else None)
        mapper = EUVDMapper(config)
        mapper.clear_cache()
        typer.echo("✓ EUVD cache cleared")
    except Exception as e:
        typer.echo(f"Error clearing cache: {e}", err=True)
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
