"""Server settings from the environment.

Device credentials are not configured here — they come from the inventory's
``${ENV_VAR}`` references, so there is no silent global fallback to a default
account.
"""

import logging

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NETNERD_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    READ_ONLY: bool = Field(
        default=True,
        description=(
            "When True, write-class SSH commands are blocked at the driver level "
            "and no configuration can be pushed. Env: NETNERD_READ_ONLY."
        ),
    )
    LOG_LEVEL: str = Field(
        default="INFO",
        description="Python logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
    )
    AUDIT_DIR: str = Field(
        default="netnerd-audit",
        description="Directory the session transcript, JSONL log and report are written to.",
    )
    CONFIRM_TIMEOUT_MIN: int = Field(
        default=5,
        description="Minutes an applied change may stay unconfirmed before it is rolled back.",
    )
    TOKEN_TTL_MIN: int = Field(
        default=10,
        description="Minutes a change token from plan_change stays valid.",
    )
    IDLE_TIMEOUT_MIN: int = Field(
        default=10,
        description="Minutes a device session may sit idle before its SSH connection is closed.",
    )

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = value.upper()
        if upper not in valid:
            raise ValueError(f"LOG_LEVEL must be one of {valid}, got '{value}'")
        return upper

    def configure_logging(self) -> None:
        logging.basicConfig(
            level=getattr(logging, self.LOG_LEVEL, logging.INFO),
            format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )


settings = Settings()  # type: ignore[call-arg]
