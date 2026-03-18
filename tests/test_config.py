"""Test configuration management."""

import os
import pytest
from pathlib import Path

from cisa_bdsca.config import Config, load_config


def test_config_validation():
    """Test configuration validation."""
    # Valid configuration
    config = Config(
        BLACKDUCK_URL="https://test.blackduck.com",
        BLACKDUCK_API_TOKEN="test_token_123"
    )
    
    assert config.blackduck_url == "https://test.blackduck.com"
    assert config.blackduck_api_token == "test_token_123"
    assert config.blackduck_verify_ssl is True
    

def test_config_url_validation():
    """Test URL validation."""
    # Missing protocol should raise error
    with pytest.raises(ValueError, match="must start with http"):
        Config(
            BLACKDUCK_URL="test.blackduck.com",
            BLACKDUCK_API_TOKEN="test_token"
        )
    
    # Trailing slash should be removed
    config = Config(
        BLACKDUCK_URL="https://test.blackduck.com/",
        BLACKDUCK_API_TOKEN="test_token"
    )
    assert config.blackduck_url == "https://test.blackduck.com"


def test_config_token_validation():
    """Test API token validation."""
    # Empty token should raise error
    with pytest.raises(ValueError, match="BLACKDUCK_API_TOKEN is required"):
        Config(
            BLACKDUCK_URL="https://test.blackduck.com",
            BLACKDUCK_API_TOKEN=""
        )


def test_config_log_level_validation():
    """Test log level validation."""
    # Valid log levels
    for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
        config = Config(
            BLACKDUCK_URL="https://test.blackduck.com",
            BLACKDUCK_API_TOKEN="test_token",
            LOG_LEVEL=level
        )
        assert config.log_level == level
    
    # Invalid log level
    with pytest.raises(ValueError, match="LOG_LEVEL must be one of"):
        Config(
            BLACKDUCK_URL="https://test.blackduck.com",
            BLACKDUCK_API_TOKEN="test_token",
            LOG_LEVEL="INVALID"
        )


def test_config_path_expansion():
    """Test path expansion."""
    config = Config(
        BLACKDUCK_URL="https://test.blackduck.com",
        BLACKDUCK_API_TOKEN="test_token",
        EUVD_CACHE_DIR="~/test_cache"
    )
    
    # Path should be expanded
    assert "~" not in str(config.euvd_cache_dir)
    assert "test_cache" in str(config.euvd_cache_dir)
