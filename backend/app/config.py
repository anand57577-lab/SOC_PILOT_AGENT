from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    PROJECT_NAME: str = "SOCPilot: Autonomous Security Alert Investigation Agent"
    VERSION: str = "1.0.0"
    DATABASE_URL: str = "sqlite:///./socpilot.db"
    MSSQL_URL: Optional[str] = None
    GOOGLE_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None
    DATASET_PATH: str = "socpilot/backend/data/GUIDE_Train.csv"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = True

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
