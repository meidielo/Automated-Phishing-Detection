"""
Pipeline configuration loaded from environment variables or YAML.
"""
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


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
    anthropic_key: str = ""
    openai_key: str = ""


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
class ScoringConfig:
    weights: dict[str, float] = field(default_factory=lambda: {
        "header_analysis": 0.10,
        "url_reputation": 0.15,
        "domain_intelligence": 0.10,
        "url_detonation": 0.15,
        "brand_impersonation": 0.10,
        "attachment_analysis": 0.15,
        "nlp_intent": 0.15,
        "sender_profiling": 0.10,
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
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    max_concurrent_analyzers: int = 10
    url_detonation_timeout: int = 30
    pipeline_timeout: int = 120
    feedback_db_path: str = "data/feedback.db"
    log_level: str = "INFO"
    dashboard_port: int = 8000
    analyst_api_token: str = ""
    max_concurrent_browser: int = 3

    @classmethod
    def from_env(cls) -> "PipelineConfig":
        """Load configuration from environment variables."""
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
            anthropic_key=os.getenv("ANTHROPIC_API_KEY", ""),
            openai_key=os.getenv("OPENAI_API_KEY", ""),
        )
        imap = IMAPConfig(
            host=os.getenv("IMAP_HOST", "imap.example.com"),
            port=int(os.getenv("IMAP_PORT", "993")),
            user=os.getenv("IMAP_USER", ""),
            password=os.getenv("IMAP_PASSWORD", ""),
            folder=os.getenv("IMAP_FOLDER", "INBOX"),
            quarantine_folder=os.getenv("IMAP_QUARANTINE_FOLDER", "Quarantine"),
        )
        return cls(
            api=api,
            imap=imap,
            max_concurrent_analyzers=int(os.getenv("MAX_CONCURRENT_ANALYZERS", "10")),
            url_detonation_timeout=int(os.getenv("URL_DETONATION_TIMEOUT_SECONDS", "30")),
            pipeline_timeout=int(os.getenv("ANALYSIS_PIPELINE_TIMEOUT_SECONDS", "120")),
            feedback_db_path=os.getenv("FEEDBACK_DB_PATH", "data/feedback.db"),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            dashboard_port=int(os.getenv("DASHBOARD_PORT", "8000")),
            analyst_api_token=os.getenv("ANALYST_API_TOKEN", ""),
            max_concurrent_browser=3,
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
            return cls.from_env()

        with open(yaml_path) as f:
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
            anthropic_key=_get(api_data, "anthropic_key", "ANTHROPIC_API_KEY"),
            openai_key=_get(api_data, "openai_key", "OPENAI_API_KEY"),
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
            scoring=scoring_cfg,
            max_concurrent_analyzers=int(_get(pipeline_data, "max_concurrent_analyzers", "MAX_CONCURRENT_ANALYZERS", 10)),
            url_detonation_timeout=int(_get(pipeline_data, "url_detonation_timeout", "URL_DETONATION_TIMEOUT_SECONDS", 30)),
            pipeline_timeout=int(_get(pipeline_data, "pipeline_timeout", "ANALYSIS_PIPELINE_TIMEOUT_SECONDS", 120)),
            feedback_db_path=_get(pipeline_data, "feedback_db_path", "FEEDBACK_DB_PATH", "data/feedback.db"),
            log_level=_get(pipeline_data, "log_level", "LOG_LEVEL", "INFO"),
            dashboard_port=int(_get(pipeline_data, "dashboard_port", "DASHBOARD_PORT", 8000)),
            analyst_api_token=_get(pipeline_data, "analyst_api_token", "ANALYST_API_TOKEN"),
            max_concurrent_browser=int(pipeline_data.get("max_concurrent_browser", 3)),
        )
