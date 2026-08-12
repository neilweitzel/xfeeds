from collections import defaultdict
from pathlib import Path
from typing import Annotated

import typer
import yaml
from pydantic import ValidationError

from xfeeds.config import get_active_voting_classes, load_registry
from xfeeds.log import configure_logging
from xfeeds.models import Registry, SourceConfig

app = typer.Typer(
    help="xfeeds: A self-updating, open threat intelligence feed.", no_args_is_help=True
)

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = REPO_ROOT / "sources.yaml"


def _load_or_exit(config_file: Path | None) -> Registry:
    """Load the registry or exit with a readable message.

    The default resolves against the repository root, not the current working
    directory, so the CLI works from anywhere.
    """
    path = config_file or DEFAULT_CONFIG
    try:
        return load_registry(path)
    except FileNotFoundError:
        typer.secho(f"Error: configuration file '{path}' not found.", fg=typer.colors.RED)
        raise typer.Exit(code=1) from None
    except ValidationError as e:
        typer.secho("Validation error in sources.yaml:", fg=typer.colors.RED)
        print(e)
        raise typer.Exit(code=1) from None
    except (yaml.YAMLError, OSError) as e:
        typer.secho(f"Error loading configuration: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from None


@app.callback()
def callback() -> None:
    pass


@app.command()
def validate(
    config_file: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="Path to sources.yaml",
        ),
    ] = None,
) -> None:
    """Load and validate the sources configuration."""
    configure_logging()
    registry = _load_or_exit(config_file)

    # Group sources by independence_class
    grouped_sources: dict[str, list[SourceConfig]] = defaultdict(list)
    for source in registry.sources:
        grouped_sources[source.independence_class].append(source)

    typer.secho(f"Successfully loaded {len(registry.sources)} sources.", fg=typer.colors.GREEN)
    print()
    print(f"{'Class':<20} | {'Source Name':<20} | {'Enabled':<7} | {'Vote':<5} | {'Redist':<6}")
    print("-" * 70)

    for ind_class, sources in sorted(grouped_sources.items()):
        for i, source in enumerate(sources):
            # Only print the class name for the first source in the group
            class_display = ind_class if i == 0 else ""
            enabled_str = "Yes" if source.enabled else "No"
            vote_str = "Yes" if source.vote else "No"
            redist_str = "Yes" if source.redistribute else "No"

            print(
                f"{class_display:<20} | {source.name:<20} | {enabled_str:<7} | {vote_str:<5} | {redist_str:<6}"
            )

    active_classes = get_active_voting_classes(registry)
    print()
    typer.secho(f"Active voting classes: {len(active_classes)}", fg=typer.colors.CYAN)


@app.command()
def run(
    config_file: Annotated[
        Path, typer.Option("--config", "-c", help="Path to sources.yaml")
    ] = DEFAULT_CONFIG,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Compute everything, write nothing")
    ] = False,
    force: Annotated[bool, typer.Option("--force", help="Bypass the churn guard")] = False,
    only: Annotated[
        str | None, typer.Option("--only", help="Fetch a single source by name")
    ] = None,
) -> None:
    """Fetch every source, score, filter, and write the feeds."""
    configure_logging()
    registry = _load_or_exit(config_file)
    from xfeeds.pipeline import ChurnGuardTripped
    from xfeeds.pipeline import run as run_pipeline

    try:
        report = run_pipeline(registry, dry_run=dry_run, force=force, only=only)
    except ChurnGuardTripped as e:
        typer.secho(f"Churn guard tripped: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=2) from e
    except Exception as e:
        typer.secho(f"Run failed: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from e

    print(report.summary())
    if dry_run:
        typer.secho("Dry run - no files written.", fg=typer.colors.YELLOW)


@app.command()
def explain(
    indicator: Annotated[str, typer.Argument(help="IP address to explain")],
    config_file: Annotated[
        Path, typer.Option("--config", "-c", help="Path to sources.yaml")
    ] = DEFAULT_CONFIG,
) -> None:
    """Explain why an address is or is not in the feed."""
    registry = _load_or_exit(config_file)
    from xfeeds.pipeline import explain as explain_indicator

    print(explain_indicator(registry, indicator))


if __name__ == "__main__":
    app()
