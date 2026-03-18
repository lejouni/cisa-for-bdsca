"""Configuration management for cisa_bdsca.

Loads settings from environment variables and .env file.
"""

from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Config(BaseSettings):
    """Application configuration loaded from environment variables."""

    # Black Duck Configuration
    blackduck_url: str = Field(..., alias="BLACKDUCK_URL")
    blackduck_api_token: str = Field(..., alias="BLACKDUCK_API_TOKEN")
    blackduck_verify_ssl: bool = Field(default=True, alias="BLACKDUCK_VERIFY_SSL")

    # Output Configuration
    output_path: Path = Field(default=Path("./output"), alias="OUTPUT_PATH")

    # EUVD Cache Configuration
    euvd_cache_dir: Path = Field(
        default=Path.home() / ".cache" / "cisa-bdsca", alias="EUVD_CACHE_DIR"
    )
    
    # KEV Catalog Cache Configuration
    kev_cache_dir: Path = Field(
        default=Path.home() / ".cache" / "cisa-bdsca", alias="KEV_CACHE_DIR"
    )

    # Logging Configuration
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    @field_validator("blackduck_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Validate Black Duck URL format."""
        if not v:
            raise ValueError("BLACKDUCK_URL is required")
        if not v.startswith(("http://", "https://")):
            raise ValueError("BLACKDUCK_URL must start with http:// or https://")
        return v.rstrip("/")  # Remove trailing slash

    @field_validator("blackduck_api_token")
    @classmethod
    def validate_token(cls, v: str) -> str:
        """Validate API token is provided."""
        if not v:
            raise ValueError("BLACKDUCK_API_TOKEN is required")
        return v

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v_upper = v.upper()
        if v_upper not in valid_levels:
            raise ValueError(f"LOG_LEVEL must be one of {valid_levels}")
        return v_upper

    @field_validator("output_path", "euvd_cache_dir", "kev_cache_dir")
    @classmethod
    def validate_path(cls, v: Path) -> Path:
        """Expand user paths and ensure they're Path objects."""
        return Path(v).expanduser()

    class Config:
        """Pydantic configuration."""

        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


def load_config(env_file: Optional[str] = None) -> Config:
    """Load configuration from environment variables and .env file.

    Args:
        env_file: Optional path to .env file. If None, searches for .env in current directory.

    Returns:
        Config object with validated settings

    Raises:
        ValueError: If required configuration is missing or invalid
    """
    # Load .env file if it exists
    if env_file:
        load_dotenv(env_file)
    else:
        load_dotenv()  # Searches for .env in current directory

    try:
        config = Config()
    except Exception as e:
        raise ValueError(f"Configuration error: {e}") from e

    return config


def check_config(config: Optional[Config] = None) -> bool:
    """Check if configuration is valid.

    Args:
        config: Optional Config object. If None, loads from environment.

    Returns:
        True if configuration is valid

    Raises:
        ValueError: If configuration is invalid
    """
    if config is None:
        config = load_config()

    # All validation happens during Config initialization
    # If we got here, config is valid
    return True
