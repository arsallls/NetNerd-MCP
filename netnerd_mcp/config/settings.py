"""Server settings from the environment.

Device credentials are not configured here — they come from the inventory's
``${ENV_VAR}`` references, so there is no silent global fallback to a default
account.
"""

import logging
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Everything the server keeps between runs lives here: the audit trail and the
# topology database. One directory under $HOME, so state does not depend on
# which directory the MCP client happened to launch the server from.
_STATE_HOME = Path.home() / ".netnerd"


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
    STATE_DIR: str = Field(
        default=str(_STATE_HOME),
        description=(
            "Directory for state kept between runs (the topology database). "
            "Env: NETNERD_STATE_DIR."
        ),
    )
    AUDIT_DIR: str = Field(
        default=str(_STATE_HOME / "audit"),
        description=(
            "Directory the session transcript, JSONL log and report are written to. "
            "Env: NETNERD_AUDIT_DIR."
        ),
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
    REQUIRE_TOPOLOGY_FOR_WRITES: bool = Field(
        default=False,
        description=(
            "When True, a change that takes an interface down is refused unless "
            "the topology graph can say what depends on it. Off by default: an "
            "undiscovered network would otherwise be unchangeable. "
            "Env: NETNERD_REQUIRE_TOPOLOGY_FOR_WRITES."
        ),
    )
    MAX_TELEMETRY_SEC: int = Field(
        default=30,
        description=(
            "Longest a telemetry subscription may sample for. A tool call that "
            "never returns wedges the client session, so the window is bounded "
            "here rather than trusted to the caller."
        ),
    )
    FLEET_TIMEOUT_MIN: int = Field(
        default=30,
        description=(
            "Minutes a staged fleet rollout may stay unconfirmed before every "
            "device reverts. Longer than CONFIRM_TIMEOUT_MIN because it has to "
            "outlast the whole rollout: the first stage's rollback must not fire "
            "while a later stage is still being applied. "
            "Env: NETNERD_FLEET_TIMEOUT_MIN."
        ),
    )
    FLEET_MAX_PARALLEL: int = Field(
        default=10,
        description=(
            "Devices pushed at once within a single stage. Each one holds an SSH "
            "session, so this is bounded by what the devices' sshd will accept "
            "rather than by this process. Env: NETNERD_FLEET_MAX_PARALLEL."
        ),
    )
    MAX_OUTPUT_LINES: int = Field(
        default=200,
        description=(
            "Line cap for unparsed command output returned to the model. Longer "
            "output comes back as a labelled excerpt, never as the full result."
        ),
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
