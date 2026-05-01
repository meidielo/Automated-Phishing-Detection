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
