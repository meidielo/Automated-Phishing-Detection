"""
Pipeline configuration loaded from environment variables or YAML.
"""
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


def _coerce_bool(value, default: bool = False) -> bool:
    """Coerce env/YAML values such as true/false, yes/no, 1/0."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return default


@dataclass
class APIConfig:
    virustotal_key: str = ""
    urlscan_key: str = ""
    abuseipdb_key: str = ""
    google_safebrowsing_key: str = ""
    sandbox_provider: str = "hybrid_analysis"
    hybrid_analysis_key: str = ""
    anyrun_key: str = ""
    joesandbox_key: str = ""
    llm_provider: str = "anthropic"
    llm_api_key: str = ""
    llm_api_base: str = ""
    llm_model: str = ""
    anthropic_key: str = ""
    openai_key: str = ""
    deepseek_key: str = ""
    moonshot_key: str = ""


@dataclass
class IMAPConfig:
    host: str = "imap.example.com"
    port: int = 993
    user: str = ""
    password: str = ""
    folder: str = "INBOX"
    quarantine_folder: str = "Quarantine"
    poll_interval_seconds: int = 60


@dataclass
class SMTPConfig:
    host: str = ""
    port: int = 587
    username: str = ""
    password: str = ""
    from_email: str = ""
    from_name: str = "PhishAnalyze"
    use_ssl: bool = False
    starttls: bool = True


@dataclass
class ScoringConfig:
    weights: dict[str, float] = field(default_factory=lambda: {
        "header_analysis": 0.10,
        "url_reputation": 0.15,
        "domain_intelligence": 0.10,
        "url_detonation": 0.15,
        "brand_impersonation": 0.10,
        "attachment_analysis": 0.15,
        "nlp_intent": 0.15,
        "sender_profiling": 0.00,
        "payment_fraud": 0.10,
    })
    thresholds: dict[str, tuple[float, float]] = field(default_factory=lambda: {
        "CLEAN": (0.0, 0.3),
        "SUSPICIOUS": (0.3, 0.6),
        "LIKELY_PHISHING": (0.6, 0.8),
        "CONFIRMED_PHISHING": (0.8, 1.0),
    })


@dataclass
class PipelineConfig:
    api: APIConfig = field(default_factory=APIConfig)
    imap: IMAPConfig = field(default_factory=IMAPConfig)
    smtp: SMTPConfig = field(default_factory=SMTPConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    max_concurrent_analyzers: int = 10
    url_detonation_timeout: int = 30
    pipeline_timeout: int = 120
    feedback_db_path: str = "data/feedback.db"
    log_level: str = "INFO"
    dashboard_port: int = 8000
    analyst_api_token: str = ""
    public_demo_mode: bool = False
    saas_db_path: str = "data/saas.db"
    saas_session_secret: str = ""
    saas_public_signup_enabled: bool = False
    password_reset_token_ttl_minutes: int = 30
    max_concurrent_browser: int = 3
    # Privacy / data retention. Stored email metadata in
    # data/results.jsonl is regulated PII under Australian Privacy Act
    # and EU GDPR. Default 30 days; set to 0 to disable purging entirely.
    # See `python main.py purge` and src/automation/retention.py.
    data_retention_days: int = 30

    @classmethod
    def from_env(cls) -> "PipelineConfig":
        """
        Load configuration. If ``config.yaml`` exists in the process CWD
        (or at the path named by ``CONFIG_YAML_PATH``), delegate to
        :meth:`from_yaml`, which applies env-var overrides on top of the
        YAML values. Otherwise, load purely from environment variables.

        This is the single runtime entrypoint — callers do not need to
        know whether a YAML file is present. Previously ``from_yaml``
        existed but had no callsites, which meant ``config.yaml`` was
        effectively dead config (audit finding, cycle 14.5).
        """
        yaml_path = os.getenv("CONFIG_YAML_PATH", "config.yaml")
        if Path(yaml_path).exists():
            return cls.from_yaml(yaml_path)
        return cls._from_env_only()

    @classmethod
    def _from_env_only(cls) -> "PipelineConfig":
        """Load configuration purely from environment variables (no YAML)."""
        api = APIConfig(
            virustotal_key=os.getenv("VIRUSTOTAL_API_KEY", ""),
            urlscan_key=os.getenv("URLSCAN_API_KEY", ""),
            abuseipdb_key=os.getenv("ABUSEIPDB_API_KEY", ""),
            google_safebrowsing_key=os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", ""),
            sandbox_provider=os.getenv("SANDBOX_PROVIDER", "hybrid_analysis"),
            hybrid_analysis_key=os.getenv("HYBRID_ANALYSIS_API_KEY", ""),
            anyrun_key=os.getenv("ANYRUN_API_KEY", ""),
            joesandbox_key=os.getenv("JOESANDBOX_API_KEY", ""),
            llm_provider=os.getenv("LLM_PROVIDER", "anthropic"),
            llm_api_key=os.getenv("LLM_API_KEY", ""),
            llm_api_base=os.getenv("LLM_API_BASE", ""),
            llm_model=os.getenv("LLM_MODEL", ""),
            anthropic_key=os.getenv("ANTHROPIC_API_KEY", ""),
            openai_key=os.getenv("OPENAI_API_KEY", ""),
            deepseek_key=os.getenv("DEEPSEEK_API_KEY", ""),
            moonshot_key=os.getenv("MOONSHOT_API_KEY", ""),
        )
        imap = IMAPConfig(
            host=os.getenv("IMAP_HOST", "imap.example.com"),
            port=int(os.getenv("IMAP_PORT", "993")),
            user=os.getenv("IMAP_USER", ""),
            password=os.getenv("IMAP_PASSWORD", ""),
            folder=os.getenv("IMAP_FOLDER", "INBOX"),
            quarantine_folder=os.getenv("IMAP_QUARANTINE_FOLDER", "Quarantine"),
        )
        smtp = SMTPConfig(
            host=os.getenv("SMTP_HOST", ""),
            port=int(os.getenv("SMTP_PORT", "587")),
            username=os.getenv("SMTP_USERNAME", ""),
            password=os.getenv("SMTP_PASSWORD", ""),
            from_email=os.getenv("SMTP_FROM_EMAIL", ""),
            from_name=os.getenv("SMTP_FROM_NAME", "PhishAnalyze"),
            use_ssl=_coerce_bool(os.getenv("SMTP_USE_SSL"), False),
            starttls=_coerce_bool(os.getenv("SMTP_STARTTLS"), True),
        )
        return cls(
            api=api,
            imap=imap,
            smtp=smtp,
            max_concurrent_analyzers=int(os.getenv("MAX_CONCURRENT_ANALYZERS", "10")),
            url_detonation_timeout=int(os.getenv("URL_DETONATION_TIMEOUT_SECONDS", "30")),
            pipeline_timeout=int(os.getenv("ANALYSIS_PIPELINE_TIMEOUT_SECONDS", "120")),
            feedback_db_path=os.getenv("FEEDBACK_DB_PATH", "data/feedback.db"),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            dashboard_port=int(os.getenv("DASHBOARD_PORT", "8000")),
            analyst_api_token=os.getenv("ANALYST_API_TOKEN", ""),
            public_demo_mode=_coerce_bool(os.getenv("PUBLIC_DEMO_MODE"), False),
            saas_db_path=os.getenv("SAAS_DB_PATH", "data/saas.db"),
            saas_session_secret=os.getenv("SAAS_SESSION_SECRET", ""),
            saas_public_signup_enabled=_coerce_bool(
                os.getenv("SAAS_PUBLIC_SIGNUP_ENABLED"),
                False,
            ),
            password_reset_token_ttl_minutes=int(os.getenv("PASSWORD_RESET_TOKEN_TTL_MINUTES", "30")),
            max_concurrent_browser=3,
            data_retention_days=int(os.getenv("DATA_RETENTION_DAYS", "30")),
        )

    @classmethod
    def from_yaml(cls, path: str = "config.yaml") -> "PipelineConfig":
        """
        Load configuration from a YAML file with env var overrides.

        YAML values are used as defaults; environment variables override
        any value present in the YAML file.
        """
        try:
            import yaml
        except ImportError:
            raise ImportError("PyYAML is required for YAML config: pip install pyyaml")

        yaml_path = Path(path)
        if not yaml_path.exists():
            # Avoid recursion: from_env() delegates to from_yaml() when
            # a YAML file exists, so fall through to the env-only loader.
            return cls._from_env_only()

        # Explicit UTF-8: Python's default open() uses the locale encoding
        # (cp1252 on many Windows installs), which blows up on any non-ASCII
        # byte in the YAML file. UTF-8 is what YAML 1.2 mandates anyway.
        with open(yaml_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        def _get(section: dict, key: str, env_var: str, default=""):
            """Get value: env var > yaml > default."""
            env_val = os.getenv(env_var)
            if env_val is not None:
                return env_val
            return section.get(key, default)

        api_data = data.get("api", {})
        api = APIConfig(
            virustotal_key=_get(api_data, "virustotal_key", "VIRUSTOTAL_API_KEY"),
            urlscan_key=_get(api_data, "urlscan_key", "URLSCAN_API_KEY"),
            abuseipdb_key=_get(api_data, "abuseipdb_key", "ABUSEIPDB_API_KEY"),
            google_safebrowsing_key=_get(api_data, "google_safebrowsing_key", "GOOGLE_SAFE_BROWSING_API_KEY"),
            sandbox_provider=_get(api_data, "sandbox_provider", "SANDBOX_PROVIDER", "hybrid_analysis"),
            hybrid_analysis_key=_get(api_data, "hybrid_analysis_key", "HYBRID_ANALYSIS_API_KEY"),
            anyrun_key=_get(api_data, "anyrun_key", "ANYRUN_API_KEY"),
            joesandbox_key=_get(api_data, "joesandbox_key", "JOESANDBOX_API_KEY"),
            llm_provider=_get(api_data, "llm_provider", "LLM_PROVIDER", "anthropic"),
            llm_api_key=_get(api_data, "llm_api_key", "LLM_API_KEY"),
            llm_api_base=_get(api_data, "llm_api_base", "LLM_API_BASE"),
            llm_model=_get(api_data, "llm_model", "LLM_MODEL"),
            anthropic_key=_get(api_data, "anthropic_key", "ANTHROPIC_API_KEY"),
            openai_key=_get(api_data, "openai_key", "OPENAI_API_KEY"),
            deepseek_key=_get(api_data, "deepseek_key", "DEEPSEEK_API_KEY"),
            moonshot_key=_get(api_data, "moonshot_key", "MOONSHOT_API_KEY"),
        )

        imap_data = data.get("imap", {})
        imap = IMAPConfig(
            host=_get(imap_data, "host", "IMAP_HOST", "imap.example.com"),
            port=int(_get(imap_data, "port", "IMAP_PORT", 993)),
            user=_get(imap_data, "user", "IMAP_USER"),
            password=_get(imap_data, "password", "IMAP_PASSWORD"),
            folder=_get(imap_data, "folder", "IMAP_FOLDER", "INBOX"),
            quarantine_folder=_get(imap_data, "quarantine_folder", "IMAP_QUARANTINE_FOLDER", "Quarantine"),
            poll_interval_seconds=int(imap_data.get("poll_interval_seconds", 60)),
        )

        smtp_data = data.get("smtp", {})
        smtp = SMTPConfig(
            host=_get(smtp_data, "host", "SMTP_HOST", ""),
            port=int(_get(smtp_data, "port", "SMTP_PORT", 587)),
            username=_get(smtp_data, "username", "SMTP_USERNAME", ""),
            password=_get(smtp_data, "password", "SMTP_PASSWORD", ""),
            from_email=_get(smtp_data, "from_email", "SMTP_FROM_EMAIL", ""),
            from_name=_get(smtp_data, "from_name", "SMTP_FROM_NAME", "PhishAnalyze"),
            use_ssl=_coerce_bool(_get(smtp_data, "use_ssl", "SMTP_USE_SSL", False)),
            starttls=_coerce_bool(_get(smtp_data, "starttls", "SMTP_STARTTLS", True)),
        )

        scoring_data = data.get("scoring", {})
        scoring_cfg = ScoringConfig()
        if "weights" in scoring_data:
            scoring_cfg.weights = scoring_data["weights"]
        if "thresholds" in scoring_data:
            scoring_cfg.thresholds = {
                k: tuple(v) for k, v in scoring_data["thresholds"].items()
            }

        pipeline_data = data.get("pipeline", {})
        return cls(
            api=api,
            imap=imap,
            smtp=smtp,
            scoring=scoring_cfg,
            max_concurrent_analyzers=int(_get(pipeline_data, "max_concurrent_analyzers", "MAX_CONCURRENT_ANALYZERS", 10)),
            url_detonation_timeout=int(_get(pipeline_data, "url_detonation_timeout", "URL_DETONATION_TIMEOUT_SECONDS", 30)),
            pipeline_timeout=int(_get(pipeline_data, "pipeline_timeout", "ANALYSIS_PIPELINE_TIMEOUT_SECONDS", 120)),
            feedback_db_path=_get(pipeline_data, "feedback_db_path", "FEEDBACK_DB_PATH", "data/feedback.db"),
            log_level=_get(pipeline_data, "log_level", "LOG_LEVEL", "INFO"),
            dashboard_port=int(_get(pipeline_data, "dashboard_port", "DASHBOARD_PORT", 8000)),
            analyst_api_token=_get(pipeline_data, "analyst_api_token", "ANALYST_API_TOKEN"),
            public_demo_mode=_coerce_bool(_get(pipeline_data, "public_demo_mode", "PUBLIC_DEMO_MODE", False)),
            saas_db_path=_get(pipeline_data, "saas_db_path", "SAAS_DB_PATH", "data/saas.db"),
            saas_session_secret=_get(pipeline_data, "saas_session_secret", "SAAS_SESSION_SECRET", ""),
            saas_public_signup_enabled=_coerce_bool(_get(
                pipeline_data,
                "saas_public_signup_enabled",
                "SAAS_PUBLIC_SIGNUP_ENABLED",
                False,
            )),
            password_reset_token_ttl_minutes=int(_get(
                pipeline_data,
                "password_reset_token_ttl_minutes",
                "PASSWORD_RESET_TOKEN_TTL_MINUTES",
                30,
            )),
            max_concurrent_browser=int(pipeline_data.get("max_concurrent_browser", 3)),
            data_retention_days=int(_get(pipeline_data, "data_retention_days", "DATA_RETENTION_DAYS", 30)),
        )
