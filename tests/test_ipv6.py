"""IPv6 dual-track behaviour.

Two of these guard defects that were live in production rather than hypothetical
regressions: `iptables.ipset` silently dropped every IPv6 record while the
dashboard published the combined count against it, and the address lookup skipped
IPv6 entirely, so the page reported prefixes the feed was actively blocking as not
listed.

The rest guard the property the whole feature exists for: a single-stack consumer
must be able to fetch a file and receive nothing it cannot parse.
"""

import ipaddress
import json
from datetime import UTC, datetime
from pathlib import Path

from xfeeds.collectors.parsers import spamhaus_json
from xfeeds.dashboard import build_lookup_index
from xfeeds.emit import emit_all, family_stats, of_family, write_ipset, write_text_feed
from xfeeds.insights import (
    MAX_ENTRY_WEIGHT,
    MIN_CELL,
    _addresses_of,
    build_family_analysis,
)
from xfeeds.models import (
    Band,
    DefaultsConfig,
    Registry,
    ScoredIndicator,
    SourceConfig,
)

NOW = datetime(2026, 8, 12, tzinfo=UTC)


def src(name: str, cls: str, **kw: object) -> SourceConfig:
    return SourceConfig(
        name=name,
        url=f"https://example.com/{name}",
        parser="plain_text",
        independence_class=cls,
        weight=1.0,
        **kw,  # type: ignore[arg-type]
    )


def registry_of(*sources: SourceConfig) -> Registry:
    return Registry(
        version=1, defaults=DefaultsConfig(), sources=list(sources), allowlist_sources=[]
    )


def rec(
    ip: str,
    band: Band = Band.HIGH,
    classes: list[str] | None = None,
    sources: list[str] | None = None,
    score: float = 90.0,
    **kw: object,
) -> ScoredIndicator:
    return ScoredIndicator(
        ip_or_cidr=ipaddress.ip_network(ip, strict=False)
        if "/" in ip
        else ipaddress.ip_address(ip),
        score=score,
        band=band,
        independence_classes=classes or ["spamhaus"],
        sources=sources or ["spamhaus_drop_v6"],
        categories=["criminal-hosting"],
        first_seen=NOW,
        last_seen=NOW,
        **kw,  # type: ignore[arg-type]
    )


MIXED = [
    rec("45.33.32.156", classes=["alpha"], sources=["a1"]),
    rec("198.51.100.0/24", classes=["alpha"], sources=["a1"]),
    rec("2001:678:254::/48"),
    rec("2a00:1450::/32"),
    rec("2606:4700::/44", band=Band.MEDIUM, score=60.0),
]


# --------------------------------------------------------------------------
# The property the feature exists for
# --------------------------------------------------------------------------


def test_v4_feed_contains_no_ipv6(tmp_path: Path) -> None:
    """The whole point. A single-stack IPv4 consumer must get nothing it cannot parse."""
    registry = registry_of(src("a1", "alpha"), src("spamhaus_drop_v6", "spamhaus"))
    path = tmp_path / "high-confidence-v4.txt"
    write_text_feed(path, "high confidence (IPv4)", MIXED, registry, NOW, family=4)

    body = [ln for ln in path.read_text().splitlines() if ln and not ln.startswith("#")]
    assert body, "the v4 feed should not be empty for this fixture"
    for line in body:
        assert ipaddress.ip_network(line, strict=False).version == 4


def test_v6_feed_contains_no_ipv4(tmp_path: Path) -> None:
    registry = registry_of(src("a1", "alpha"), src("spamhaus_drop_v6", "spamhaus"))
    path = tmp_path / "high-confidence-v6.txt"
    write_text_feed(path, "high confidence (IPv6)", MIXED, registry, NOW, family=6)

    body = [ln for ln in path.read_text().splitlines() if ln and not ln.startswith("#")]
    assert body
    for line in body:
        assert ipaddress.ip_network(line, strict=False).version == 6


def test_family_split_is_lossless(tmp_path: Path) -> None:
    """No record may vanish in the split, and none may be duplicated across files."""
    registry = registry_of(src("a1", "alpha"), src("spamhaus_drop_v6", "spamhaus"))
    combined = tmp_path / "all.txt"
    v4 = tmp_path / "v4.txt"
    v6 = tmp_path / "v6.txt"
    write_text_feed(combined, "combined", MIXED, registry, NOW)
    write_text_feed(v4, "v4", MIXED, registry, NOW, family=4)
    write_text_feed(v6, "v6", MIXED, registry, NOW, family=6)

    def entries(path: Path) -> set[str]:
        return {ln for ln in path.read_text().splitlines() if ln and not ln.startswith("#")}

    assert entries(v4) | entries(v6) == entries(combined)
    assert not entries(v4) & entries(v6)


# --------------------------------------------------------------------------
# Regression guards for defects that were live
# --------------------------------------------------------------------------


def test_ipset_v6_records_are_not_silently_dropped(tmp_path: Path) -> None:
    """`write_ipset` used to filter version == 4 with no comment and no count.

    An ipset holds one address family, so the v6 records have to go somewhere.
    Previously they went nowhere and nothing said so.
    """
    v4_path = tmp_path / "iptables.ipset"
    v6_path = tmp_path / "iptables6.ipset"
    high = [r for r in MIXED if r.band is Band.HIGH]
    write_ipset(v4_path, high, NOW, 4, "iptables6.ipset")
    write_ipset(v6_path, high, NOW, 6, "iptables.ipset")

    v4_text = v4_path.read_text()
    v6_text = v6_path.read_text()

    assert "family inet\n" in v4_text or "family inet " in v4_text
    assert "family inet6" in v6_text
    assert "xfeeds6" in v6_text

    added_v4 = {ln.split()[-1] for ln in v4_text.splitlines() if ln.startswith("add ")}
    added_v6 = {ln.split()[-1] for ln in v6_text.splitlines() if ln.startswith("add ")}
    assert added_v4 | added_v6 == {str(r.ip_or_cidr) for r in high}

    # And the exclusion must be stated, not silent.
    assert "NOT in this file" in v4_text
    assert "iptables6.ipset" in v4_text


def test_lookup_index_finds_ipv6_record() -> None:
    """The dashboard reported blocked v6 prefixes as not listed.

    128-bit bounds cannot survive JSON's number type, so they are carried as
    decimal strings for the client to parse with BigInt. Verify the bounds are
    exact rather than rounded through a float.
    """
    index = build_lookup_index(MIXED)
    assert index["v"] == 2
    assert index["r"], "IPv4 rows must still be present"
    assert index["r6"], "IPv6 rows must be present - this is the regression"

    net = ipaddress.ip_network("2001:678:254::/48")
    row = next(r for r in index["r6"] if r[5] == str(net))
    assert isinstance(row[0], str) and isinstance(row[1], str)
    assert int(row[0]) == int(net.network_address)
    assert int(row[1]) == int(net.broadcast_address)

    probe = int(ipaddress.ip_address("2001:678:254::dead:beef"))
    assert int(row[0]) <= probe <= int(row[1])


def test_lookup_index_v6_bounds_exceed_js_safe_integer() -> None:
    """Guards the reason the bounds are strings.

    If someone 'simplifies' these back to JSON numbers, the client silently loses
    precision and matches the wrong ranges. Assert the values genuinely exceed the
    range a JS number can hold exactly.
    """
    index = build_lookup_index(MIXED)
    js_max_safe = 2**53 - 1
    assert any(int(row[1]) > js_max_safe for row in index["r6"])


# --------------------------------------------------------------------------
# Aggregation honesty
# --------------------------------------------------------------------------


def test_addresses_of_caps_ipv6_weight() -> None:
    """One /29 must not dominate every aggregate it touches.

    An IPv6 /29 holds 2**99 addresses. Summed raw against IPv4 counts it is not a
    large contribution, it is the only contribution.
    """
    wide_v6 = ipaddress.ip_network("2a00::/29")
    assert wide_v6.num_addresses > MAX_ENTRY_WEIGHT
    assert _addresses_of(wide_v6) == MAX_ENTRY_WEIGHT

    # IPv4 behaviour must be unchanged: the width cap admits nothing near 2**24.
    assert _addresses_of(ipaddress.ip_network("198.51.100.0/24")) == 256


def test_min_cell_folding_applied_to_v6_aggregations() -> None:
    """v6 cells are held to the threshold the project already uses for ASN cells."""
    records = [rec(f"2a00:{i:x}::/32") for i in range(MIN_CELL + 2)]
    records += [rec("2606:4700::/44")]  # a lone cell, below MIN_CELL
    analysis = build_family_analysis(records)["v6"]

    named = {row["key"] for row in analysis["prefix_lengths"]}
    assert "/32" in named
    assert "/44" not in named, "a cell below MIN_CELL must fold"
    assert analysis["prefix_lengths_folded_entries"] == 1


def test_blast_radius_reported_and_exact() -> None:
    """Scope, not entry count. A /48 is 65,536 /64s; a /32 is 4,294,967,296."""
    analysis = build_family_analysis([rec("2001:678:254::/48"), rec("2a00:1450::/32")])["v6"]
    assert analysis["blast_radius_64_total"] == 65_536 + 4_294_967_296
    assert analysis["sites_48_total"] == 1 + 65_536


def test_contiguous_runs_reported_but_not_collapsed() -> None:
    """Adjacency is a finding. Merging it would diverge from what upstream published."""
    records = [rec("2a11:f080::/32"), rec("2a11:f081::/32")]
    analysis = build_family_analysis(records)["v6"]
    runs = analysis["contiguous_runs"]
    assert len(runs) == 1
    assert runs[0]["aggregate"] == "2a11:f080::/31"
    assert set(runs[0]["members"]) == {"2a11:f080::/32", "2a11:f081::/32"}
    # The records themselves are untouched.
    assert analysis["entries"] == 2


def test_suppressed_analyses_are_data_driven() -> None:
    """A degenerate family says so; a varied one stops saying so."""
    degenerate = build_family_analysis([rec("2001:678:254::/48"), rec("2a00:1450::/32")])["v6"]
    named = {s["analysis"] for s in degenerate["suppressed"]}
    assert "Corroboration histogram" in named
    assert "Score distribution" in named

    varied = build_family_analysis(
        [
            rec("2001:678:254::/48", classes=["spamhaus"], sources=["s1"], score=90.0),
            rec(
                "2a00:1450::/32",
                band=Band.MEDIUM,
                classes=["alpha", "beta"],
                sources=["a1", "b1"],
                score=61.0,
            ),
        ]
    )["v6"]
    named_varied = {s["analysis"] for s in varied["suppressed"]}
    assert "Corroboration histogram" not in named_varied
    assert "Score distribution" not in named_varied
    # The ASN limit is structural and stays regardless of variance.
    assert "Network and ASN persistence" in named_varied


# --------------------------------------------------------------------------
# Upstream references
# --------------------------------------------------------------------------


def test_spamhaus_sblid_and_rir_are_parsed() -> None:
    """The DROP payload carries both and the parser used to discard them."""
    payload = (
        b'{"cidr":"2001:678:254::/48","sblid":"SBL697648","rir":"ripencc"}\n'
        b'{"cidr":"2a00:1450::/32","sblid":"SBL123456","rir":"arin"}\n'
    )
    config = src("spamhaus_drop_v6", "spamhaus", categories=["criminal-hosting"])
    records = list(spamhaus_json(payload, config, NOW))
    assert len(records) == 2
    assert records[0].source_reference == "SBL697648"
    assert records[0].source_registry == "ripencc"
    assert records[1].source_reference == "SBL123456"


def test_source_reference_never_reaches_a_text_feed(tmp_path: Path) -> None:
    """Firewalls parse those files. A ticket id on a line would break them."""
    registry = registry_of(src("spamhaus_drop_v6", "spamhaus"))
    records = [rec("2001:678:254::/48", source_reference="SBL697648")]
    path = tmp_path / "high-confidence-v6.txt"
    write_text_feed(path, "high confidence (IPv6)", records, registry, NOW, family=6)
    body = [ln for ln in path.read_text().splitlines() if ln and not ln.startswith("#")]
    assert body == ["2001:678:254::/48"]


def test_source_reference_reaches_the_lookup_index() -> None:
    index = build_lookup_index([rec("2001:678:254::/48", source_reference="SBL697648")])
    assert index["r6"][0][8] == "SBL697648"


# --------------------------------------------------------------------------
# Disclosure and manifest
# --------------------------------------------------------------------------


def test_concentration_notice_only_when_single_class(tmp_path: Path) -> None:
    """Computed from the data, so it disappears when a second class arrives."""
    registry = registry_of(src("spamhaus_drop_v6", "spamhaus"), src("b1", "beta"))

    single = tmp_path / "single.txt"
    write_text_feed(single, "v6", [rec("2001:678:254::/48")], registry, NOW, family=6)
    assert "CONCENTRATION NOTICE" in single.read_text()

    corroborated = tmp_path / "corroborated.txt"
    write_text_feed(
        corroborated,
        "v6",
        [
            rec(
                "2001:678:254::/48",
                classes=["spamhaus", "beta"],
                sources=["spamhaus_drop_v6", "b1"],
            )
        ],
        registry,
        NOW,
        family=6,
    )
    assert "CONCENTRATION NOTICE" not in corroborated.read_text()


def test_manifest_family_counts_match_emitted_files(tmp_path: Path) -> None:
    """The dashboard prints these numbers. They must equal the file contents.

    The previous bug was exactly this: the downloads table reported the combined
    high count against a file that held only the IPv4 subset.
    """
    registry = registry_of(src("a1", "alpha"), src("spamhaus_drop_v6", "spamhaus"))
    emit_all(MIXED, registry, {"generated_at": NOW.isoformat()}, NOW, feeds_dir=tmp_path)

    manifest = json.loads((tmp_path / "manifest.json").read_text())
    families = manifest["families"]

    for family, path in ((4, "iptables.ipset"), (6, "iptables6.ipset")):
        added = [ln for ln in (tmp_path / path).read_text().splitlines() if ln.startswith("add ")]
        assert len(added) == families[f"v{family}"]["high"]

    for family in (4, 6):
        text = (tmp_path / f"high-confidence-v{family}.txt").read_text()
        body = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
        assert len(body) == families[f"v{family}"]["high"]


def test_family_stats_counts_independence_classes() -> None:
    """This field is what makes the concentration notice testable over time."""
    stats = family_stats(MIXED)
    assert stats["v6"]["independence_classes"] == 1
    assert stats["v6"]["published"] == 3
    assert stats["v4"]["published"] == 2
    assert stats["v6"]["blast_radius_64"] > 0


def test_emit_all_writes_both_families(tmp_path: Path) -> None:
    registry = registry_of(src("a1", "alpha"), src("spamhaus_drop_v6", "spamhaus"))
    emit_all(MIXED, registry, {"generated_at": NOW.isoformat()}, NOW, feeds_dir=tmp_path)
    for name in (
        "high-confidence-v4.txt",
        "high-confidence-v6.txt",
        "medium-confidence-v4.txt",
        "medium-confidence-v6.txt",
        "iptables.ipset",
        "iptables6.ipset",
    ):
        assert (tmp_path / name).exists(), name
    # The combined files must be untouched in meaning - firewalls point at them.
    combined = (tmp_path / "high-confidence.txt").read_text()
    assert "2001:678:254::/48" in combined
    assert "45.33.32.156" in combined


def test_determinism_with_mixed_families(tmp_path: Path) -> None:
    """AGENTS.md rule 4. Two runs, byte-identical output, or every run commits noise."""
    registry = registry_of(src("a1", "alpha"), src("spamhaus_drop_v6", "spamhaus"))
    first = tmp_path / "first"
    second = tmp_path / "second"
    for out in (first, second):
        emit_all(MIXED, registry, {"generated_at": NOW.isoformat()}, NOW, feeds_dir=out)

    for path in sorted(first.iterdir()):
        assert path.read_bytes() == (second / path.name).read_bytes(), path.name


def test_csv_carries_address_family_and_reference(tmp_path: Path) -> None:
    registry = registry_of(src("a1", "alpha"), src("spamhaus_drop_v6", "spamhaus"))
    records = [*MIXED, rec("2a01:4f8::/32", source_reference="SBL999999")]
    emit_all(records, registry, {"generated_at": NOW.isoformat()}, NOW, feeds_dir=tmp_path)
    rows = (tmp_path / "all.csv").read_text().splitlines()
    header = rows[0].split(",")
    assert "address_family" in header
    assert "source_reference" in header
    assert any(row.endswith("SBL999999") for row in rows[1:])
    assert any(",v6," in row for row in rows[1:])


def test_of_family_helper() -> None:
    assert len(of_family(MIXED, 4)) == 2
    assert len(of_family(MIXED, 6)) == 3
