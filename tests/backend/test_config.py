from app.core.config import settings


def test_settings_defaults() -> None:
    assert settings.app_name == "ECDAT"
    assert settings.api_v1_prefix == "/api/v1"