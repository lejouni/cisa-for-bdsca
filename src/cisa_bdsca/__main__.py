"""CLI entry point for cisa_bdsca module.

This allows the module to be invoked with:
    python -m cisa_bdsca <command> [options]
"""

from .cli import app

if __name__ == "__main__":
    app()
