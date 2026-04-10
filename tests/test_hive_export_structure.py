"""Static checks for Hive export structure."""

import json
from pathlib import Path


def test_hive_export_files_exist():
    root = Path("hive_exports/gcp_iam_enterprise_triage")
    required = [
        "__init__.py",
        "__main__.py",
        "agent.py",
        "agent.json",
        "config.py",
        "flowchart.json",
        "mcp_servers.json",
        "README.md",
        "nodes/__init__.py",
    ]
    for rel in required:
        path = root / rel
        assert path.exists(), f"Missing required Hive export file: {path}"


def test_hive_export_json_shapes():
    root = Path("hive_exports/gcp_iam_enterprise_triage")
    agent_json = json.loads((root / "agent.json").read_text(encoding="utf-8"))
    flowchart_json = json.loads((root / "flowchart.json").read_text(encoding="utf-8"))

    assert agent_json["agent"]["id"] == "gcp_iam_enterprise_triage"
    assert agent_json["graph"]["entry_node"] == "governance-intake"
    assert len(agent_json["graph"]["nodes"]) >= 5

    assert "levels" in flowchart_json
    assert flowchart_json["entry_node"] == "governance-intake"
    assert flowchart_json["policy"]["default_threshold"] == 0.80
