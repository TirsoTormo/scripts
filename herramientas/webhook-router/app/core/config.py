import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """
    Central Gateway configuration using Pydantic Settings.
    Loads variables from the environment or a local .env file.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Security token required to authenticate incoming requests
    GATEWAY_TOKEN: str = "my_super_secure_secret_token"
    
    # Session signing secret key
    SECRET_KEY: str = "supersecretkeyforjwtsigningsystem12345"
    
    # Mapped database/log directories and paths
    DATA_DIR: str = "data"
    DB_FILE: str = "data/gateway.db"
    LOG_FILE_INFRA: str = "data/infra_events.log"
    LOG_FILE_REMEDIATION: str = "data/remediation_history.log"

    # Telegram Bot configurations (Simulation mode if empty)
    TELEGRAM_BOT_TOKEN: Optional[str] = None
    TELEGRAM_CHAT_ID: Optional[str] = None

    # Discord Webhook Configuration (Simulation mode if empty)
    DISCORD_WEBHOOK_URL: Optional[str] = None

    # Slack Webhook Configuration (Simulation mode if empty)
    SLACK_WEBHOOK_URL: Optional[str] = None
    
    # Kubernetes Cluster configurations
    KUBECONFIG_PATH: Optional[str] = "~/.kube/config"
    KUBERNETES_NAMESPACE: str = "default"

    # Docker Host configurations
    DOCKER_HOST: Optional[str] = "unix:///var/run/docker.sock"
    
    # Default SSH target for auto-remediation (Simulation mode if empty)
    SSH_HOST: Optional[str] = None
    SSH_PORT: int = 22
    SSH_USERNAME: Optional[str] = None
    SSH_PASSWORD: Optional[str] = None
    SSH_PRIVATE_KEY_PATH: Optional[str] = None
    SSH_PRIVATE_KEY_PASSPHRASE: Optional[str] = None
    
    # Alert deduplication sliding window (in seconds)
    DEDUPLICATION_WINDOW_SECONDS: int = 300

    # Interval to dispatch low-priority alerts (INFO & WARNING) as a consolidated summary (in seconds)
    DIGEST_INTERVAL_SECONDS: int = 3600
    
    # Log rotation parameters (Set LOG_ROTATION_MAX_BYTES to 0 to disable rotation and retain logs infinitely)
    LOG_ROTATION_MAX_BYTES: int = 5242880  # Default: 5MB (5242880 bytes)
    LOG_ROTATION_BACKUP_COUNT: int = 5

    @property
    def is_telegram_configured(self) -> bool:
        """Checks if active Telegram Bot settings are provided."""
        return bool(self.TELEGRAM_BOT_TOKEN and self.TELEGRAM_CHAT_ID)

    @property
    def is_discord_configured(self) -> bool:
        """Checks if Discord webhook URL is configured."""
        return bool(self.DISCORD_WEBHOOK_URL and self.DISCORD_WEBHOOK_URL.startswith("http"))

    @property
    def is_slack_configured(self) -> bool:
        """Checks if Slack webhook URL is configured."""
        return bool(self.SLACK_WEBHOOK_URL and self.SLACK_WEBHOOK_URL.startswith("http"))

    @property
    def is_ssh_configured(self) -> bool:
        """Checks if sufficient target SSH configurations are present."""
        return bool(
            self.SSH_HOST and 
            self.SSH_USERNAME and 
            (self.SSH_PASSWORD or self.SSH_PRIVATE_KEY_PATH)
        )

# Initialize settings singleton
settings = Settings()
