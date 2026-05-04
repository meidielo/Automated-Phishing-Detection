from src.config import PipelineConfig


def test_public_demo_mode_defaults_to_false(monkeypatch):
    monkeypatch.delenv("PUBLIC_DEMO_MODE", raising=False)

    config = PipelineConfig._from_env_only()

    assert config.public_demo_mode is False


def test_public_demo_mode_reads_env_boolean(monkeypatch):
    monkeypatch.setenv("PUBLIC_DEMO_MODE", "yes")

    config = PipelineConfig._from_env_only()

    assert config.public_demo_mode is True


def test_public_demo_mode_reads_yaml_with_env_override(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "pipeline:\n"
        "  public_demo_mode: false\n"
        "  analyst_api_token: yaml-token\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PUBLIC_DEMO_MODE", "true")

    config = PipelineConfig.from_yaml(str(config_path))

    assert config.public_demo_mode is True


def test_smtp_password_reset_config_reads_env(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "smtp.zoho.com")
    monkeypatch.setenv("SMTP_PORT", "465")
    monkeypatch.setenv("SMTP_USERNAME", "alerts@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "app-password")
    monkeypatch.setenv("SMTP_FROM_EMAIL", "alerts@example.com")
    monkeypatch.setenv("SMTP_FROM_NAME", "PhishAnalyze Alerts")
    monkeypatch.setenv("SMTP_USE_SSL", "true")
    monkeypatch.setenv("SMTP_STARTTLS", "false")
    monkeypatch.setenv("PASSWORD_RESET_TOKEN_TTL_MINUTES", "45")

    config = PipelineConfig._from_env_only()

    assert config.smtp.host == "smtp.zoho.com"
    assert config.smtp.port == 465
    assert config.smtp.username == "alerts@example.com"
    assert config.smtp.password == "app-password"
    assert config.smtp.from_email == "alerts@example.com"
    assert config.smtp.from_name == "PhishAnalyze Alerts"
    assert config.smtp.use_ssl is True
    assert config.smtp.starttls is False
    assert config.password_reset_token_ttl_minutes == 45


def test_smtp_password_reset_config_reads_yaml_with_env_override(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "smtp:\n"
        "  host: smtp.yaml.test\n"
        "  port: 587\n"
        "  username: yaml@example.com\n"
        "  password: yaml-password\n"
        "  from_email: yaml@example.com\n"
        "  from_name: YAML Sender\n"
        "  use_ssl: false\n"
        "  starttls: true\n"
        "pipeline:\n"
        "  password_reset_token_ttl_minutes: 20\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SMTP_HOST", "smtp.env.test")
    monkeypatch.setenv("PASSWORD_RESET_TOKEN_TTL_MINUTES", "35")

    config = PipelineConfig.from_yaml(str(config_path))

    assert config.smtp.host == "smtp.env.test"
    assert config.smtp.port == 587
    assert config.smtp.username == "yaml@example.com"
    assert config.smtp.from_name == "YAML Sender"
    assert config.password_reset_token_ttl_minutes == 35


def test_zoho_password_reset_config_reads_env(monkeypatch):
    monkeypatch.setenv("ZOHO_CLIENT_ID", "client-id")
    monkeypatch.setenv("ZOHO_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("ZOHO_REFRESH_TOKEN", "refresh-token")
    monkeypatch.setenv("ZOHO_ACCOUNTS_BASE", "https://accounts.zoho.com.au")
    monkeypatch.setenv("ZOHO_ACCOUNT_ID", "123456789")
    monkeypatch.setenv("ZOHO_FROM", "alerts@example.com")
    monkeypatch.setenv("ZOHO_API_BASE", "https://mail.zoho.com.au")
    monkeypatch.setenv("ZOHO_ENABLE_DIRECT_SEND", "true")

    config = PipelineConfig._from_env_only()

    assert config.zoho_mail.client_id == "client-id"
    assert config.zoho_mail.client_secret == "client-secret"
    assert config.zoho_mail.refresh_token == "refresh-token"
    assert config.zoho_mail.accounts_base == "https://accounts.zoho.com.au"
    assert config.zoho_mail.account_id == "123456789"
    assert config.zoho_mail.from_email == "alerts@example.com"
    assert config.zoho_mail.api_base == "https://mail.zoho.com.au"
    assert config.zoho_mail.enable_direct_send is True


def test_zoho_password_reset_config_reads_yaml_with_legacy_env_override(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "zoho_mail:\n"
        "  client_id: yaml-client\n"
        "  client_secret: yaml-secret\n"
        "  refresh_token: yaml-refresh\n"
        "  accounts_base: https://accounts.zoho.com.au\n"
        "  account_id: 700123\n"
        "  from_email: yaml@example.com\n"
        "  api_base: https://mail.zoho.com.au\n"
        "  enable_direct_send: false\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ZOHO_CLIENT_ID", "env-client")
    monkeypatch.delenv("ZOHO_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("ZOHO_REFRESH_TOKEN", raising=False)
    monkeypatch.delenv("ZOHO_ACCOUNTS_BASE", raising=False)
    monkeypatch.delenv("ZOHO_ACCOUNT_ID", raising=False)
    monkeypatch.delenv("ZOHO_FROM", raising=False)
    monkeypatch.delenv("ZOHO_API_BASE", raising=False)
    monkeypatch.delenv("ZOHO_ENABLE_DIRECT_SEND", raising=False)
    monkeypatch.setenv("ENABLE_DIRECT_SEND", "yes")

    config = PipelineConfig.from_yaml(str(config_path))

    assert config.zoho_mail.client_id == "env-client"
    assert config.zoho_mail.client_secret == "yaml-secret"
    assert config.zoho_mail.from_email == "yaml@example.com"
    assert config.zoho_mail.enable_direct_send is True


def test_gemini_api_key_reads_env(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-env-key")

    config = PipelineConfig._from_env_only()

    assert config.api.gemini_key == "gemini-env-key"


def test_gemini_api_key_reads_yaml_with_env_override(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "api:\n"
        "  gemini_key: yaml-gemini-key\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("GEMINI_API_KEY", "env-gemini-key")

    config = PipelineConfig.from_yaml(str(config_path))

    assert config.api.gemini_key == "env-gemini-key"
