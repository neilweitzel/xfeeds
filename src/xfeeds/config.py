from pathlib import Path

import yaml

from xfeeds.models import Registry


def load_registry(yaml_path: Path) -> Registry:
    """Load and validate sources.yaml, applying defaults to each source."""
    with open(yaml_path, "r", encoding="utf-8") as f:
        raw_data = yaml.safe_load(f)

    # We manually merge the defaults block into each source since Pydantic v2
    # doesn't automatically do deep dict merging for lists of nested objects
    # based on sibling fields without custom pre-validators.
    defaults = raw_data.get("defaults", {})
    if "sources" in raw_data and isinstance(raw_data["sources"], list):
        for i, source in enumerate(raw_data["sources"]):
            if isinstance(source, dict):
                # Apply defaults for keys that are not present in the source
                for k, v in defaults.items():
                    if k not in source:
                        source[k] = v

    registry = Registry.model_validate(raw_data)
    return registry


def get_active_voting_classes(registry: Registry) -> set[str]:
    """Return the set of independence_class for ACTIVE voting sources.
    An active voting source is one where enabled == True and vote == True.
    """
    classes = set()
    for source in registry.sources:
        if source.enabled and source.vote:
            classes.add(source.independence_class)
    return classes
