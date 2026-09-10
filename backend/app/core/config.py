from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict()

    app_name: str = "ECDAT"
    api_v1_prefix: str = "/api/v1"


settings = Settings()