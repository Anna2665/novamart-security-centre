"""Central configuration. Every secret comes from the environment (or .env); nothing sensitive is hard-coded."""
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=str(ROOT / ".env"), extra="ignore", case_sensitive=False)

    database_url: str = f"sqlite:///{ROOT / 'data' / 'cyberguard.db'}"
    data_dir: str = str(ROOT / "data")

    # secrets (generated into data/secrets.json on first start when not provided)
    jwt_secret: str | None = None
    cg_master_key: str | None = None  # base64, 32 bytes
    otp_pepper: str | None = None

    # demo accounts
    demo_email: str = "annamariya2605@gmail.com"
    brand_name: str = "NovaMart"
    cg_admin_password: str | None = None
    cg_analyst_password: str | None = None
    cg_viewer_password: str | None = None
    cg_shopper_password: str | None = None

    # SMTP (email OTP)
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    smtp_security: str = "starttls"  # starttls | ssl | none

    # E-mail over HTTPS (Resend). Use this where outgoing SMTP ports are blocked, e.g. free Render/Railway servers.
    # With a key set it is used instead of SMTP. With the default sender (onboarding@resend.dev) Resend only delivers to the address the Resend account was created with.
    resend_api_key: str | None = None
    resend_from: str = "NovaMart <onboarding@resend.dev>"

    # OTP / session policy
    otp_ttl_seconds: int = 60
    otp_max_attempts: int = 3
    otp_resend_cooldown: int = 15
    otp_dev_echo: bool = False  # explicit developer mode: show OTP on screen, email NOT sent
    session_minutes: int = 30
    max_failed_logins: int = 5
    lockout_minutes: int = 5

    telemetry_enabled: bool = True
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8000,http://127.0.0.1:8000"

    @property
    def smtp_configured(self) -> bool:
        return bool(self.smtp_host and self.smtp_user and self.smtp_password)

    @property
    def email_configured(self) -> bool:
        """True when some real delivery route exists: the HTTPS provider or SMTP."""
        return bool(self.resend_api_key) or self.smtp_configured


settings = Settings()
Path(settings.data_dir).mkdir(parents=True, exist_ok=True)
