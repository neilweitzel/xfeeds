from collections import defaultdict
from pathlib import Path

import typer
from pydantic import ValidationError

from xfeeds.config import get_active_voting_classes, load_registry
from xfeeds.models import SourceConfig

app = typer.Typer(help="xfeeds: A self-updating, open threat intelligence feed.", no_args_is_help=True)


@app.command()
def validate(
    config_file: Path = typer.Option(
        Path("sources.yaml"), "--config", "-c", help="Path to sources.yaml"
    ),
) -> None:
    """Load and validate the sources configuration."""
    try:
        registry = load_registry(config_file)
    except FileNotFoundError:
        typer.secho(f"Error: configuration file '{config_file}' not found.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    except ValidationError as e:
        typer.secho("Validation Error in sources.yaml:", fg=typer.colors.RED)
        print(e)
        raise typer.Exit(code=1)
    except Exception as e:
        typer.secho(f"Error loading configuration: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

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


if __name__ == "__main__":
    app()
@app.command()
def run():
    """Dummy command to make typer create a subcommand group."""
    pass
