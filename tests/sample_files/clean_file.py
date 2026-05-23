# clean_file.py
# This file contains NO secrets and should produce zero findings.

import os
import logging

logger = logging.getLogger(__name__)


def get_api_key() -> str:
    """
    Retrieve the API key safely from environment variables.
    This is the correct pattern — never hardcode secrets.
    """
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        raise EnvironmentError("OPENAI_API_KEY is not set in environment variables.")
    return key


def connect_database() -> str:
    """
    Build a database URL from environment variables.
    """
    host = os.environ.get("DB_HOST", "localhost")
    port = os.environ.get("DB_PORT", "5432")
    user = os.environ.get("DB_USER", "")
    password = os.environ.get("DB_PASSWORD", "")
    name = os.environ.get("DB_NAME", "")

    return f"postgresql://{user}:{password}@{host}:{port}/{name}"


class Config:
    """Application configuration loaded from environment variables."""

    DEBUG: bool = os.environ.get("DEBUG", "false").lower() == "true"
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "")
    DATABASE_URL: str = os.environ.get("DATABASE_URL", "")
    REDIS_URL: str = os.environ.get("REDIS_URL", "redis://localhost:6379")


def main():
    config = Config()
    logger.info("Application starting...")
    logger.info("Debug mode: %s", config.DEBUG)
