# IPv6 dual-track — feature specification

Status: proposed
Date: 2026-08-15
Affects: `emit.py`, `insights.py`, `dashboard.py`, `enrich.py`, `README.md`, `docs/DECISIONS.md`

---

## 1. What is actually true today

Before designing anything, the measured state of the current run (`feeds/all.json`,
generated 2026-08-15T06:58Z):

| Fact | Value |
|---|---|
| Published indicators | 4,821 |
| IPv4 | 4,730 (98.1%) |
| IPv6 | 91 (1.9%) |
| IPv6 contributing sources | **1** — `spamhaus_drop_v6` |
| IPv6 independence classes | **1** — `spamhaus` |
| IPv6 bands | 100% `high` (score 90.0, all `promoted_by: spamhaus_drop_v6`) |
| IPv6 prefix lengths | /29 (18), /32 (27), /36 (4), /38 (1), /39 (3), /40 (3), /44 (2), /48 (32) |
| IPv6 single addresses (/128) | 0 |

Two conclusions follow, and they drive the whole design.

**IPv6 is not a future problem — it already ships.** The pipeline has handled v6
end to end since `spamhaus_drop_v6` was enabled. `models.py`, `filters.py`
(`MAX_IPV6_PREFIXLEN = 48`), `allowlist.py` (separate `_v6` span index) and
`emit.write_nftables` (`set blocklist6`) all treat it as first class. Ninety-two
v6 lines are in `high-confidence.txt` right now, mixed inline with the v4 lines,
and `all.csv` / `all.json` / `stix-bundle.json` carry them too. Any consumer
pointing v4-only tooling at `high-confidence.txt` is already receiving lines it
cannot parse. This is a live defect, not a roadmap item.

**IPv6 has no corroboration and cannot have any.** Every v6 record comes from one
source in one independence class. The project's core claim — a score means
*independent* agreement — is structurally unavailable for v6 with the current
source set. `high-confidence.txt` opens with "corroborated by multiple INDEPENDENT
sources, or comes from a source whose precision justifies it alone"; v6 rides
entirely on the second clause. That is defensible for Spamhaus DROP specifically,
but it must be stated, not left for a reader to infer from a `sources` array.

## 2. Goals

1. A v4-only consumer can fetch a URL and receive **zero** v6 lines.
2. A v6-capable consumer can fetch v6 without parsing and filtering the combined file.
3. No existing URL changes meaning in a way that silently breaks a working deployment.
4. The dashboard stops pretending the corpus is IPv4-only.
5. The confidence semantics of the v6 track are stated on the page and in the file header.

## 3. Non-goals

- Adding IPv6 sources. `sources.yaml` is frozen per AGENTS.md; a v6 source addition
  needs its own ADR and measurement.
- IPv6 ASN/geo enrichment. `iptoasn.com` v6 tables exist but pulling one is a new
  dataset with its own cache, licence check and memory profile. Deferred — see §8.
- Any change to scoring weights, the churn guard, or band thresholds.

## 4. Output layout

Family-suffixed files alongside the existing combined files. Nothing is removed.

```
feeds/
  high-confidence.txt          # UNCHANGED — combined, both families
  high-confidence-v4.txt       # new
  high-confidence-v6.txt       # new
  medium-confidence.txt        # UNCHANGED — combined
  medium-confidence-v4.txt     # new
  medium-confidence-v6.txt     # new
  iptables.ipset               # CHANGED semantics — see below
  iptables6.ipset              # new
  nftables.conf                # UNCHANGED — already emits blocklist4 + blocklist6
  all.csv / all.json           # UNCHANGED — gain an address_family column/field
```

Same three files land in `feeds/noncommercial/` and `feeds/clean/` via the existing
`emit_all` tier loop, at zero extra cost.

### Why suffix rather than split

Splitting `high-confidence.txt` into v4-only would be the cleaner end state, and it
is wrong here. Thousands of pfSense/OPNsense URL-table entries and cron `curl`s point
at that filename. Silently changing what it returns is exactly the kind of
undiscussable breakage AGENTS.md rule 4 exists to prevent. Suffixed files are additive:
existing consumers keep working, new consumers get a correct URL, and the README can
recommend the suffixed form as the default going forward.

### `iptables.ipset` is the one real bug

`emit.write_ipset` declares `create xfeeds hash:net family inet` and then filters
`if r.ip_or_cidr.version == 4`. It silently drops all 91 v6 records with no comment,
no count, and no warning. Worse, the dashboard's "All downloads" table reports its
entry count as `counts["high"]` — 3,902 — when the file actually contains 3,811.
The published number is wrong today.

Fix:

- `write_ipset` gains a `family: int = 4` parameter, emits
  `family inet` / `family inet6` and set name `xfeeds` / `xfeeds6` accordingly, and
  writes a header line stating how many records of the *other* family were excluded.
- `emit_all` calls it twice, producing `iptables.ipset` and `iptables6.ipset`.
- The dashboard downloads table reports per-family counts from the manifest rather
  than reusing the combined high count.

## 5. Header and manifest changes

Every text feed header gains two lines:

```
# Address family: IPv6 only
# Entries:   91
# NOTE: IPv6 coverage in this project comes from a single source family
#       (Spamhaus DROPv6) and therefore carries no independent corroboration.
#       It is published because that source's precision justifies it alone,
#       not because multiple sources agree. See README "IPv6 coverage".
```

The corroboration caveat is emitted **conditionally**, computed from the data:
if the v6 records span fewer than two independence classes, print it. It disappears
automatically the day a second v6 source is enabled. Hard-coding the Spamhaus
sentence would go stale silently, which is the failure mode this project keeps
running into with documentation.

`manifest.json` gains a `families` block so the dashboard and downstream monitoring
do not have to recompute it:

```json
"families": {
  "v4": {"high": 3811, "medium": 828, "published": 4639, "independence_classes": 7},
  "v6": {"high": 91,   "medium": 0,   "published": 91,   "independence_classes": 1}
}
```

`independence_classes` per family is the field that makes the caveat testable and
makes "did v6 corroboration ever improve" a chartable question.

## 6. Dashboard and visualizations

Five changes, in priority order.

### 6.1 The address lookup silently fails on IPv6 — fix first

`dashboard.build_lookup_index` contains:

```python
if item.version != 4:
    continue
```

So the "Check an address" box cannot find any of the 91 v6 entries that are in the
feed. A user pastes a v6 address that xfeeds *is currently blocking* and the page
tells them it is not listed. That is the worst possible failure for the one
interactive feature on the page — it produces confident, wrong answers during
false-positive triage.

`lookup.json` is a `{"v": ..., "r": [...]}` structure of integer `[lo, hi]` ranges.
IPv6 integers exceed JavaScript's `Number.MAX_SAFE_INTEGER`, which is presumably why
it was skipped. Two workable options:

- **Preferred:** add a parallel `r6` array storing bounds as decimal **strings**, and
  have the client-side lookup use `BigInt` for the v6 path. `BigInt` is baseline in
  every browser the dashboard already targets, needs no dependency, and keeps the
  existing v4 fast path on plain numbers.
- Fallback: store v6 bounds as `[hi64, lo64]` integer pairs and compare
  lexicographically. Avoids `BigInt` but is harder to read and to test.

Size impact is negligible: 91 rows against ~4,700.

### 6.2 Add an IPv6 spectrum strip beside the IPv4 one

The existing strip cuts IPv4 into 512 slices of 8.4M addresses. The same idea does
not transfer directly — IPv6 is 2^128, and a linear strip would render 91 entries as
an invisible smear at the far left of an empty bar. That is technically honest and
communicates nothing.

Render the **allocated** space instead: restrict the axis to `2000::/3`, the block
IANA actually issues global unicast from, and slice it into 256 buckets on a log
scale. Label it explicitly as global unicast space, not "the IPv6 internet", and
shade the unallocated remainder the same way the v4 strip shades multicast and
reserved space. Reuse `_spectrum_svg` with a parameterised domain rather than
writing a second renderer.

The honest caption matters more than the chart: *"91 prefixes across N of 256 slices
of global unicast space, from one source. The v4 strip below is drawn from twelve."*
Placing them side by side makes the coverage asymmetry the visual takeaway, which is
the actual finding.

### 6.3 Prefix-size distribution — the chart that carries real information

For IPv6, prefix *width* is the substantive fact and there is currently nowhere to
see it. The corpus is 18 × /29 and 27 × /32 alongside 32 × /48. A /29 is 2^99
addresses. Counting a /29 and a /48 as "two entries" is meaningless, and
`insights._addresses_of` returning `num_addresses` for v6 networks will produce
absurd magnitudes if it is ever summed into an aggregate.

Add a horizontal bar chart of entry count by prefix length, v4 and v6 as two rows of
the same figure. It answers "what am I actually blocking" in a way the entry count
cannot, and it is the chart an operator uses to decide whether a /29 belongs in their
ruleset at all.

Guard `_addresses_of` for v6 at the same time: cap the returned weight, or return the
prefix length and let callers decide, so no aggregate can ever be dominated by a
single /29.

### 6.4 Say what "unenriched" means

`insights.build_insights` increments `unenriched` for every v6 observation and merges
it with genuine ASN-lookup misses. Two different things in one number. Split it into
`unenriched_ipv6` and `unenriched_no_asn`, and have the dashboard render the v6 figure
as an explicit line — "91 IPv6 prefixes are excluded from network analysis; the ASN
table we use is IPv4-only" — rather than folding it into an unexplained residual.

### 6.5 Downloads table

Add the suffixed files with correct per-family counts from the new manifest block,
and add an "Address family" column. Fix the `iptables.ipset` count noted in §4.

## 7. README changes

Four edits.

**7.1 — `## Using the feeds` table.** Add an "Address family" column. List the
suffixed files. Mark the combined files as "both — use the suffixed file if your
tooling is single-stack".

**7.2 — New `### IPv6 coverage` subsection** under "Using the feeds":

> xfeeds publishes IPv6 as a separate track. It is small and it is structurally
> different from the IPv4 feed: 91 prefixes from a single source family, Spamhaus
> DROPv6, so nothing in it is independently corroborated. It ships because that
> source's precision justifies it alone. Prefixes are wide by design — /29 to /48 —
> because IPv6 abuse rotates freely within an allocation and blocking a /128 achieves
> nothing.
>
> If you run single-stack IPv4, use `high-confidence-v4.txt` and `iptables.ipset`.
> If you run dual-stack, take both, or use `nftables.conf`, which has always carried
> both families in separate sets.

**7.3 — Fix the ipset recipe.** The current snippet is presented as *the* firewall
recipe and quietly covers only v4. Extend it:

```bash
curl -sS https://neilweitzel.github.io/xfeeds/iptables.ipset  | sudo ipset restore -!
curl -sS https://neilweitzel.github.io/xfeeds/iptables6.ipset | sudo ipset restore -!
sudo iptables  -I INPUT -m set --match-set xfeeds  src -j DROP
sudo ip6tables -I INPUT -m set --match-set xfeeds6 src -j DROP
```

**7.4 — `## What the dashboard shows`.** The section currently opens with "The IPv4
space as one strip" and reads as though the corpus is IPv4-only. Add the v6 strip and
the prefix-size chart, and state that ASN analysis is IPv4-only because the
enrichment table is.

Also worth adding to `## Safety rails`: the `/48` v6 cap is listed but its rationale
is not. A /48 cap on a source that legitimately publishes /29s means the cap is being
carried by the Spamhaus exemption — that is load-bearing and currently undocumented.

## 8. Follow-on, explicitly deferred

- **IPv6 ASN enrichment.** `iptoasn.com` publishes a v6 table under the same PDDL
  licence. Same bisect approach, but 128-bit keys, a much larger table and a new
  cache entry. Worth doing only if a second v6 source lands and the corpus grows
  enough to make the analysis meaningful. 91 prefixes from one source does not
  justify it.
- **A second IPv6 source.** The single highest-value change available, and the only
  one that would let v6 participate in independence scoring at all. Needs a survey of
  which public feeds publish v6 with usable licences, then an ADR and an overlap
  measurement against Spamhaus DROPv6, following the ADR-033 method.
- **Aggregation policy.** No /128s appear today because the only source publishes
  allocations. If a source that publishes individual v6 addresses is ever enabled,
  a /64 rollup rule is needed before it ships — a /128 blocklist is close to useless
  and a naive one would explode the entry count.

## 9. Testing

Per AGENTS.md, new risk-bearing behaviour needs a failure-mode test.

| Test | Asserts |
|---|---|
| `test_v4_feed_contains_no_ipv6` | Every line of `*-v4.txt` parses as v4. The whole point of the feature. |
| `test_v6_feed_contains_no_ipv4` | Mirror. |
| `test_family_split_is_lossless` | v4 + v6 line counts equal the combined file exactly. No record vanishes in the split. |
| `test_ipset_v6_records_not_silently_dropped` | `iptables6.ipset` contains the v6 records `iptables.ipset` excludes. |
| `test_lookup_index_finds_ipv6_record` | A known v6 prefix from the fixture set resolves through the lookup index. Regression guard for §6.1. |
| `test_manifest_family_counts_match_emitted_files` | The numbers the dashboard prints equal the file contents. Prevents the current ipset miscount recurring. |
| `test_corroboration_caveat_appears_only_when_single_class` | Caveat is data-driven and disappears when a second class exists. |
| `test_determinism_with_mixed_families` | Two runs produce byte-identical suffixed files. AGENTS.md rule 4. |

Fixtures already exist: `tests/fixtures/sources/spamhaus_drop_v6.json`.

## 10. Sequencing

Ordered by consumer impact, not by code locality.

| Wave | Work | Rationale |
|---|---|---|
| 1 | `iptables6.ipset` + `write_ipset` family parameter + manifest `families` block | Fixes a live silent drop and a wrong published count |
| 1 | `build_lookup_index` IPv6 support | Fixes confidently-wrong answers during FP triage |
| 2 | Suffixed text feeds + conditional header caveat + tests | The dual-track deliverable |
| 2 | README §7.1–7.4 | Must land with the files, not after |
| 3 | IPv6 spectrum strip + prefix-size chart + unenriched split | Visualization |
| 3 | ADR entry in `docs/DECISIONS.md` | Records why suffixing beat splitting, and the single-class caveat |

Waves 1 and 2 touch `emit.py` and are best kept sequential. Wave 3 is
`dashboard.py`/`insights.py` and can run in parallel with the wave 2 README work.

## 11. ADR text to record

> **Dual-track IPv6 output.** IPv6 has shipped inside the combined feeds since
> `spamhaus_drop_v6` was enabled, which means single-stack IPv4 consumers have been
> receiving unparseable lines. Rather than change what `high-confidence.txt` returns —
> thousands of firewall URL tables point at it — family-suffixed files are added
> alongside it and documented as the recommended form. `iptables.ipset` was found to
> drop v6 silently while the dashboard reported the combined count; both are fixed.
> The v6 track carries a data-driven header caveat because all 91 records come from a
> single independence class, so the project's corroboration claim does not hold for
> it. IPv6 ASN enrichment and any second v6 source are deferred to their own ADRs.
