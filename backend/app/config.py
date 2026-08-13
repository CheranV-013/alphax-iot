from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    database_url: str = "sqlite:///./alphax.db"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173,https://alphax-iot.vercel.app"
    vibration_threshold: float = 0.5
    geofence_km: float = 1.5
    simulator_enabled: bool = True
    model_dir: str = "models"
    class Config:
        env_file = ".env"

settings = Settings()
