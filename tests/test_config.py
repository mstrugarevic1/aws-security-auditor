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

    file_config = load_config_file(config)
    required_tags, critical_tags = file_config

    assert required_tags == ("Owner", "Service")
    assert critical_tags == {
        "Environment": ("prod", "prd"),
        "Criticality": ("tier1",),
    }
    assert file_config.suppressions == ()


def test_load_config_file_suppressions(tmp_path) -> None:
    config = tmp_path / "auditor.toml"
    config.write_text(
        """
[[suppressions]]
check_id = "EC2_SG_OPEN_SSH"
resource_id = "sg-1"
region = "us-east-1"
account_id = "123"
reason = "Temporary vendor access"
expires = "2099-01-01"
""".strip(),
        encoding="utf-8",
    )

    suppression = load_config_file(config).suppressions[0]

    assert suppression.check_id == "EC2_SG_OPEN_SSH"
    assert suppression.resource_id == "sg-1"
    assert suppression.region == "us-east-1"
    assert suppression.account_id == "123"


def test_load_config_file_invalid_suppression(tmp_path) -> None:
    config = tmp_path / "auditor.toml"
    config.write_text(
        """
[[suppressions]]
check_id = "X"
resource_id = "r"
reason = ""
expires = "bad"
""".strip(),
        encoding="utf-8",
    )

    try:
        load_config_file(config)
    except ValueError as exc:
        assert "reason" in str(exc)
    else:
        raise AssertionError("expected ValueError")
