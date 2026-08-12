from pathlib import Path

import pytest
from pydantic import ValidationError

from xfeeds.config import get_active_voting_classes, load_registry


def test_load_real_sources_yaml() -> None:
    """Load the real sources.yaml and verify its content."""
    yaml_path = Path("sources.yaml")
    registry = load_registry(yaml_path)

    active_classes = get_active_voting_classes(registry)

    # Assert exactly 7 voting classes are active on a fresh clone.
    assert len(active_classes) == 7

    # Verify no API keys are present (enabled should be False for abuseipdb/threatfox)
    abuseipdb = next((s for s in registry.sources if s.name == "abuseipdb_blacklist"), None)
    threatfox = next((s for s in registry.sources if s.name == "threatfox"), None)

    if abuseipdb:
        assert abuseipdb.enabled is False
    if threatfox:
        assert threatfox.enabled is False


def test_duplicate_source_name() -> None:
    with pytest.raises(ValidationError, match="Duplicate source name found: dup"):
        from xfeeds.models import Registry

        Registry.model_validate(
            {
                "version": 1,
                "defaults": {},
                "sources": [
                    {
                        "name": "dup",
                        "url": "a",
                        "parser": "plain_text",
                        "independence_class": "a",
                        "weight": 1.0,
                    },
                    {
                        "name": "dup",
                        "url": "b",
                        "parser": "plain_text",
                        "independence_class": "b",
                        "weight": 1.0,
                    },
                ],
                "allowlist_sources": [],
            }
        )


def test_invalid_weight() -> None:
    with pytest.raises(ValidationError, match="Weight must be between 0.0 and 1.0"):
        from xfeeds.models import Registry

        Registry.model_validate(
            {
                "version": 1,
                "defaults": {},
                "sources": [
                    {
                        "name": "valid1",
                        "url": "a",
                        "parser": "plain_text",
                        "independence_class": "a",
                        "weight": 1.5,
                    },
                ],
                "allowlist_sources": [],
            }
        )


def test_invalid_parser() -> None:
    with pytest.raises(ValidationError, match="Unknown parser"):
        from xfeeds.models import Registry

        Registry.model_validate(
            {
                "version": 1,
                "defaults": {},
                "sources": [
                    {
                        "name": "valid1",
                        "url": "a",
                        "parser": "magic_parser",
                        "independence_class": "a",
                        "weight": 1.0,
                    },
                ],
                "allowlist_sources": [],
            }
        )


def test_voting_source_weight_zero() -> None:
    with pytest.raises(ValidationError, match="voting source but has weight 0.0"):
        from xfeeds.models import Registry

        Registry.model_validate(
            {
                "version": 1,
                "defaults": {},
                "sources": [
                    {
                        "name": "valid1",
                        "url": "a",
                        "parser": "plain_text",
                        "independence_class": "a",
                        "weight": 0.0,
                        "vote": True,
                    },
                ],
                "allowlist_sources": [],
            }
        )
