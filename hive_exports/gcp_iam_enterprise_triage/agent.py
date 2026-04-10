"""Agent graph construction for GCP IAM enterprise multi-level triage."""

from pathlib import Path

from framework.graph import EdgeCondition, EdgeSpec, Goal, SuccessCriterion, Constraint
from framework.graph.checkpoint_config import CheckpointConfig
from framework.graph.edge import GraphSpec
from framework.graph.executor import ExecutionResult
from framework.llm import LiteLLMProvider
from framework.runner.tool_registry import ToolRegistry
from framework.runtime.agent_runtime import AgentRuntime, create_agent_runtime
from framework.runtime.execution_stream import EntryPointSpec

from .config import default_config, metadata
from .nodes import (
    governance_intake_node,
    iam_specialist_node,
    secret_specialist_node,
    correlation_committee_node,
    risk_committee_node,
    executive_reporting_node,
)

goal = Goal(
    id="gcp-iam-enterprise-triage",
    name="GCP IAM Enterprise Multi-Level Security Triage",
    description=(
        "Convert scanner evidence into governance-aligned decisions using "
        "multi-level specialist lanes for IAM and secret risk, followed by "
        "committee correlation and merge gate decisioning."
    ),
    success_criteria=[
        SuccessCriterion(
            id="normalized-output",
            description="Every finding follows the required normalized schema",
            metric="schema_compliance",
            target="100%",
            weight=0.20,
        ),
        SuccessCriterion(
            id="specialist-coverage",
            description="Both IAM and secret specialist lanes execute and contribute",
            metric="lane_coverage",
            target=">=2",
            weight=0.20,
        ),
        SuccessCriterion(
            id="policy-aligned-gate",
            description="Merge gate decision strictly follows critical+threshold policy",
            metric="policy_alignment",
            target="true",
            weight=0.30,
        ),
        SuccessCriterion(
            id="actionable-remediation",
            description="All high-priority findings include concrete remediation",
            metric="remediation_coverage",
            target="100%",
            weight=0.30,
        ),
    ],
    constraints=[
        Constraint(
            id="evidence-only",
            description="Do not invent findings beyond provided scanner evidence.",
            constraint_type="hard",
            category="accuracy",
        ),
        Constraint(
            id="policy-immutability",
            description="Do not alter gate policy semantics during execution.",
            constraint_type="hard",
            category="governance",
        ),
    ],
)

nodes = [
    governance_intake_node,
    iam_specialist_node,
    secret_specialist_node,
    correlation_committee_node,
    risk_committee_node,
    executive_reporting_node,
]

edges = [
    EdgeSpec(
        id="governance-to-iam",
        source="governance-intake",
        target="iam-specialist",
        condition=EdgeCondition.ON_SUCCESS,
        priority=1,
    ),
    EdgeSpec(
        id="iam-to-secret",
        source="iam-specialist",
        target="secret-specialist",
        condition=EdgeCondition.ON_SUCCESS,
        priority=1,
    ),
    EdgeSpec(
        id="secret-to-correlation",
        source="secret-specialist",
        target="correlation-committee",
        condition=EdgeCondition.ON_SUCCESS,
        priority=1,
    ),
    EdgeSpec(
        id="correlation-to-risk",
        source="correlation-committee",
        target="risk-committee",
        condition=EdgeCondition.ON_SUCCESS,
        priority=1,
    ),
    EdgeSpec(
        id="risk-to-executive",
        source="risk-committee",
        target="executive-reporting",
        condition=EdgeCondition.ON_SUCCESS,
        priority=1,
    ),
]

entry_node = "governance-intake"
entry_points = {"start": "governance-intake"}
pause_nodes = []
terminal_nodes = ["executive-reporting"]


class GCPIAMEnterpriseTriageAgent:
    """Enterprise triage graph backed by Hive runtime primitives."""

    def __init__(self, config=None):
        self.config = config or default_config
        self.goal = goal
        self.nodes = nodes
        self.edges = edges
        self.entry_node = entry_node
        self.entry_points = entry_points
        self.pause_nodes = pause_nodes
        self.terminal_nodes = terminal_nodes
        self._graph: GraphSpec | None = None
        self._agent_runtime: AgentRuntime | None = None
        self._tool_registry: ToolRegistry | None = None
        self._storage_path: Path | None = None

    def _build_graph(self) -> GraphSpec:
        return GraphSpec(
            id="gcp-iam-enterprise-triage-graph",
            goal_id=self.goal.id,
            version="1.0.0",
            entry_node=self.entry_node,
            entry_points=self.entry_points,
            terminal_nodes=self.terminal_nodes,
            pause_nodes=self.pause_nodes,
            nodes=self.nodes,
            edges=self.edges,
            default_model=self.config.model,
            max_tokens=self.config.max_tokens,
            loop_config={
                "max_iterations": 80,
                "max_tool_calls_per_turn": 10,
                "max_history_tokens": 32000,
            },
            conversation_mode="continuous",
            identity_prompt=(
                "You are an enterprise SOC triage system with governance, specialist, "
                "and committee lanes for GCP IAM risk analysis."
            ),
        )

    def _setup(self, mock_mode: bool = False) -> None:
        self._storage_path = Path.home() / ".hive" / "agents" / "gcp_iam_enterprise_triage"
        self._storage_path.mkdir(parents=True, exist_ok=True)

        self._tool_registry = ToolRegistry()
        mcp_config_path = Path(__file__).parent / "mcp_servers.json"
        if mcp_config_path.exists():
            self._tool_registry.load_mcp_config(mcp_config_path)

        llm = None
        if not mock_mode:
            llm = LiteLLMProvider(
                model=self.config.model,
                api_key=self.config.api_key,
                api_base=self.config.api_base,
            )

        self._graph = self._build_graph()

        checkpoint_config = CheckpointConfig(
            enabled=True,
            checkpoint_on_node_start=False,
            checkpoint_on_node_complete=True,
            checkpoint_max_age_days=7,
            async_checkpoint=True,
        )

        entry_specs = [
            EntryPointSpec(
                id="default",
                name="Enterprise Triage",
                entry_node=self.entry_node,
                trigger_type="manual",
                isolation_level="shared",
            )
        ]

        self._agent_runtime = create_agent_runtime(
            graph=self._graph,
            goal=self.goal,
            storage_path=self._storage_path,
            entry_points=entry_specs,
            llm=llm,
            tools=list(self._tool_registry.get_tools().values()),
            tool_executor=self._tool_registry.get_executor(),
            checkpoint_config=checkpoint_config,
        )

    async def start(self, mock_mode: bool = False) -> None:
        if self._agent_runtime is None:
            self._setup(mock_mode=mock_mode)
        if not self._agent_runtime.is_running:
            await self._agent_runtime.start()

    async def stop(self) -> None:
        if self._agent_runtime and self._agent_runtime.is_running:
            await self._agent_runtime.stop()
        self._agent_runtime = None

    async def trigger_and_wait(
        self,
        input_data: dict | None = None,
        session_state: dict | None = None,
    ) -> ExecutionResult | None:
        if self._agent_runtime is None:
            raise RuntimeError("Agent not started. Call start() first.")

        return await self._agent_runtime.trigger_and_wait(
            entry_point_id="default",
            input_data=input_data or {},
            session_state=session_state,
        )

    async def run(self, context: dict, mock_mode: bool = False, session_state=None) -> ExecutionResult:
        await self.start(mock_mode=mock_mode)
        try:
            result = await self.trigger_and_wait(context, session_state=session_state)
            return result or ExecutionResult(success=False, error="Execution timeout")
        finally:
            await self.stop()

    def info(self) -> dict:
        return {
            "name": metadata.name,
            "version": metadata.version,
            "description": metadata.description,
            "goal": {
                "name": self.goal.name,
                "description": self.goal.description,
            },
            "nodes": [n.id for n in self.nodes],
            "edges": [e.id for e in self.edges],
            "entry_node": self.entry_node,
            "terminal_nodes": self.terminal_nodes,
            "client_facing_nodes": [n.id for n in self.nodes if n.client_facing],
        }

    def validate(self) -> dict:
        errors: list[str] = []
        node_ids = {node.id for node in self.nodes}

        for edge in self.edges:
            if edge.source not in node_ids:
                errors.append(f"Edge {edge.id}: source '{edge.source}' not found")
            if edge.target not in node_ids:
                errors.append(f"Edge {edge.id}: target '{edge.target}' not found")

        if self.entry_node not in node_ids:
            errors.append(f"Entry node '{self.entry_node}' not found")

        for terminal in self.terminal_nodes:
            if terminal not in node_ids:
                errors.append(f"Terminal node '{terminal}' not found")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": [],
        }


default_agent = GCPIAMEnterpriseTriageAgent()
