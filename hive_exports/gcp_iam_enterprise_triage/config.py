"""Runtime configuration for the Hive enterprise triage export."""

from dataclasses import dataclass

from framework.config import RuntimeConfig

default_config = RuntimeConfig()


@dataclass
class AgentMetadata:
    name: str = "GCP IAM Enterprise Multi-Level Triage"
    version: str = "1.0.0"
    description: str = (
        "Enterprise security triage graph for GCP IAM threat detection. "
        "Implements governance intake, specialist analysis lanes, "
        "risk committee decisioning, and executive reporting."
    )
    intro_message: str = (
        "Enterprise triage initialized. Scanner artifacts received. "
        "Running governance, specialist lanes, correlation, and committee gate."
    )


metadata = AgentMetadata()
