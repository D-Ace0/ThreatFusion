from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="THREATFUSION_", env_file=".env", extra="ignore")
    demo: bool = True
    db_path: Path = Path("data/threatfusion.sqlite3")
    cache_ttl: int = Field(default=3600, ge=0, le=604800)
    timeout: float = Field(default=10, gt=0, le=60)
    retries: int = Field(default=2, ge=0, le=5)
    retry_cap: float = Field(default=5, ge=0, le=60)
    vt_key: SecretStr = SecretStr("")
    abuse_key: SecretStr = SecretStr("")
    otx_key: SecretStr = SecretStr("")
    api_key: SecretStr = SecretStr("")
