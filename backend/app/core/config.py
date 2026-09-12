from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional
import os

class Settings(BaseSettings):
    PROJECT_NAME: str = "CiphR Backend"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    
    # Database Configuration
    DATABASE_URL: str = "sqlite+aiosqlite:///./test.db" # Default fallback
    SUPABASE_URL: Optional[str] = None
    SUPABASE_KEY: Optional[str] = None
    
    # LLM Keys
    GROQ_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None
    
    # Upload Settings
    UPLOAD_DIR: str = "./uploads"
    MAX_APK_SIZE_MB: int = 100
    MAX_APK_SIZE_BYTES: int = MAX_APK_SIZE_MB * 1024 * 1024
    
    # URL Ingestion Settings
    URL_FETCH_TIMEOUT: int = 15
    URL_MAX_REDIRECTS: int = 3

    # EMBER2024 Model (Phase 6D)
    EMBER_MODEL_PATH: str = "./scratch/ember2024_benchmark/EMBER2024_APK.model"
    
    # Evidence Fusion Shadow Mode (Phase 6F)
    FUSION_SHADOW_ENABLED: bool = False

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

settings = Settings()
