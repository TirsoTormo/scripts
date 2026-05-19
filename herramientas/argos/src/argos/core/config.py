import json
from pathlib import Path

from pydantic import BaseModel, Field

CONFIG_FILE = Path.home() / ".argos_config.json"


class ArgosConfig(BaseModel):
    # Network Scanner
    default_timeout: int = Field(default=2)
    max_threads: int = Field(default=100)
    stealth_mode: bool = Field(default=False)

    # State tracking
    last_scan_file: str = Field(default=str(Path.home() / ".argos_last_scan.json"))
    auto_export_json: bool = Field(default=True)

    # UI
    theme_color: str = Field(default="bright_magenta")

    @classmethod
    def load(cls) -> "ArgosConfig":
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, encoding="utf-8") as f:
                    data = json.load(f)
                    return cls(**data)
            except Exception:
                pass
        return cls()

    def save(self):
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(self.model_dump(), f, indent=4)
        except Exception:
            pass


config = ArgosConfig.load()
