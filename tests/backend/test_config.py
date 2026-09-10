from backend.app.core.config import settings


def test_settings_defaults() -> None:
    assert settings.project_name == "Q-BITS-ECDAT"
    assert settings.port == 8000