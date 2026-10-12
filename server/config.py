"""
SPAZE Server - Configuration

Loads settings from environment variables / .env file.
"""

from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://spaze_user:spaze_pass@localhost:5432/spaze"
    DATABASE_URL_SYNC: str = "postgresql://spaze_user:spaze_pass@localhost:5432/spaze"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_KEY_TTL: int = 300  # Key cache TTL in seconds (5 min)

    # JWT
    JWT_SECRET: str = "spaze-dev-secret-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_MINUTES: int = 480  # 8 hours

    # Server
    SERVER_HOST: str = "0.0.0.0"
    SERVER_PORT: int = 8000
    DEBUG: bool = True

    # SPAZE
    APP_NAME: str = "SPAZE Server"
    APP_VERSION: str = "1.0.0"

    # Security mode: "baseline" (original design) or "pakl"
    # (presence-attested key leasing: signed agent requests,
    #  rolling badge tokens, short key leases)
    SECURITY_MODE: str = "baseline"
    MASTER_KEY: str = ""            # 64 hex chars; wraps FEKs at rest when set
    LEASE_TTL_S: float = 10.0       # key lease lifetime
    TOKEN_SLACK_S: float = 8.0      # tolerated presence-token lag
    TOKEN_MAX_REUSE_S: float = 5.0  # how long one token counter may be reused
    SIG_MAX_SKEW_S: float = 30.0    # agent request timestamp tolerance

    # PAKL-CR: server-issued challenges answered by the badge over a BLE
    # connection and timed + attested by the anchor (relay detection)
    CR_REQUIRED: bool = False
    CR_MAX_RTT_US: int = 50000      # calibrate from the legitimate RTT distribution
    CHALLENGE_TTL_S: float = 10.0

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
