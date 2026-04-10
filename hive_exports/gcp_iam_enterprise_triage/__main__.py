"""CLI entrypoint for GCP IAM Enterprise Multi-Level Triage Hive export."""

import asyncio
import json
import logging
import sys

import click

from .agent import GCPIAMEnterpriseTriageAgent, default_agent


def setup_logging(verbose: bool = False, debug: bool = False) -> None:
    """Configure logging for execution visibility."""
    if debug:
        level, fmt = logging.DEBUG, "%(asctime)s %(name)s: %(message)s"
    elif verbose:
        level, fmt = logging.INFO, "%(message)s"
    else:
        level, fmt = logging.WARNING, "%(levelname)s: %(message)s"
    logging.basicConfig(level=level, format=fmt, stream=sys.stderr)
    logging.getLogger("framework").setLevel(level)


@click.group()
@click.version_option(version="1.0.0")
def cli() -> None:
    """Enterprise multi-level triage powered by Hive graph runtime."""


@cli.command()
@click.option("--input-json", type=click.Path(exists=True), help="Path to context JSON file.")
@click.option("--mock", is_flag=True, help="Run in mock mode.")
@click.option("--quiet", "quiet", is_flag=True, help="Output JSON only.")
@click.option("--verbose", "verbose", is_flag=True, help="Show execution details.")
@click.option("--debug", is_flag=True, help="Show debug logging.")
def run(input_json, mock, quiet, verbose, debug) -> None:
    """Run enterprise triage with input context."""
    if not quiet:
        setup_logging(verbose=verbose, debug=debug)

    context = {}
    if input_json:
        with open(input_json, "r", encoding="utf-8") as handle:
            context = json.load(handle)

    result = asyncio.run(default_agent.run(context, mock_mode=mock))

    output_data = {
        "success": result.success,
        "steps_executed": result.steps_executed,
        "output": result.output,
    }
    if result.error:
        output_data["error"] = result.error

    click.echo(json.dumps(output_data, indent=2, default=str))
    sys.exit(0 if result.success else 1)


@cli.command()
@click.option("--json", "output_json", is_flag=True)
def info(output_json: bool) -> None:
    """Show agent information."""
    info_data = default_agent.info()
    if output_json:
        click.echo(json.dumps(info_data, indent=2))
        return

    click.echo(f"Agent: {info_data['name']}")
    click.echo(f"Version: {info_data['version']}")
    click.echo(f"Description: {info_data['description']}")
    click.echo(f"Nodes: {', '.join(info_data['nodes'])}")
    click.echo(f"Entry: {info_data['entry_node']}")


@cli.command()
def validate() -> None:
    """Validate graph structure."""
    validation = default_agent.validate()
    if validation["valid"]:
        click.echo("Agent is valid")
    else:
        click.echo("Agent has errors:")
        for error in validation["errors"]:
            click.echo(f"  ERROR: {error}")
    sys.exit(0 if validation["valid"] else 1)


@cli.command()
@click.option("--verbose", "verbose", is_flag=True)
def shell(verbose: bool) -> None:
    """Interactive shell for quick manual testing."""
    asyncio.run(_interactive_shell(verbose))


async def _interactive_shell(verbose: bool = False) -> None:
    setup_logging(verbose=verbose)

    click.echo("=== GCP IAM Enterprise Multi-Level Triage ===")
    click.echo("Paste scanner findings JSON and press Enter. Type 'quit' to exit.\n")

    agent = GCPIAMEnterpriseTriageAgent()
    await agent.start()

    try:
        while True:
            raw = await asyncio.get_event_loop().run_in_executor(None, input, "scanner_findings_json> ")
            if raw.lower() in {"quit", "exit", "q"}:
                click.echo("Goodbye!")
                break

            context = {
                "scanner_findings_json": raw,
                "confidence_threshold": "0.80",
                "architecture_context": "",
            }
            result = await agent.trigger_and_wait(context)
            if result is None:
                click.echo("[Execution timed out]")
                continue

            if result.success:
                click.echo(json.dumps(result.output, indent=2, default=str))
            else:
                click.echo(f"Execution failed: {result.error}", err=True)
    finally:
        await agent.stop()


if __name__ == "__main__":
    cli()
