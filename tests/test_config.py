from __future__ import annotations

from aws_security_auditor.config import load_config_file


def test_load_config_file(tmp_path) -> None:
    config = tmp_path / "auditor.toml"
    config.write_text(
        """
required_tags = ["Owner", "Service"]

[critical_resource_tags]
Environment = ["prod", "prd"]
Criticality = ["tier1"]
""".strip(),
        encoding="utf-8",
    )

    required_tags, critical_tags = load_config_file(config)

    assert required_tags == ("Owner", "Service")
    assert critical_tags == {
        "Environment": ("prod", "prd"),
        "Criticality": ("tier1",),
    }
