# IPv6 dual-track — feature specification

Status: proposed
Date: 2026-08-15
Affects: `emit.py`, `insights.py`, `dashboard.py`, `collectors/parsers.py`, `models.py`, `README.md`, `docs/DECISIONS.md`

---

## 1. Measured state

All figures from the `2026-08-15T06:58Z` run (`feeds/all.json`).

| | |
|---|---|
| Published indicators | 4,821 |
| IPv4 | 4,730 (98.1%) |
| IPv6 | 91 (1.9%) |
| IPv6 sources | 1 — `spamhaus_drop_v6` |
| IPv6 independence classes | 1 — `spamhaus` |
| IPv6 bands | 100% `high`, all score 90.0, all `promoted_by: spamhaus_drop_v6` |
| IPv6 single addresses (/128) | 0 |
| IPv6 prefix lengths | /29 (18), /30 (1), /32 (27), /36 (4), /38 (1), /39 (3), /40 (3), /44 (2), /48 (32) |
| Nested (redundant) prefixes | 0 |
| Adjacent prefixes that would collapse | 91 → 85 |

IPv6 has shipped inside the combined feeds since `spamhaus_drop_v6` was enabled.
`models.py`, `filters.py` (`MAX_IPV6_PREFIXLEN = 48`), `allowlist.py` and
`write_nftables` all treat it as first class. Ninety-two v6 lines sit in
`high-confidence.txt` today, inline with v4. **Single-stack IPv4 consumers are
already receiving lines they cannot parse.** That is a live defect, not a roadmap
item.

## 2. Is 91 entries statistically relevant?

The question has two different answers depending on the dimension, and conflating
them is what makes IPv6 feel unusable.

### 2.1 On scoring dimensions: no, and not because of sample size

The v6 set has **zero variance** on every dimension the existing dashboard charts:

| Dimension | Distinct values across 91 records |
|---|---|
| Score | 1 (90.0) |
| Band | 1 (high) |
| Source | 1 |
| Independence class | 1 |
| Categories | 1 pair (`criminal-hosting`, `hijacked-netblock`) |
| `first_seen` | 1 (2026-08-12 — when the source was enabled) |
| Tags | 0 |

This is not a small sample. It is a **degenerate** one. The corroboration
histogram, score distribution, band split and category breakdown would each render
exactly one bar. Building v6 versions of those charts produces the appearance of
analysis with none of the substance, which is worse than omitting them.

### 2.2 On structural dimensions: yes, by the project's own existing threshold

`insights.MIN_CELL = 5` already defines the smallest count this project is willing
to report against a named cell. Applying that same gate to v6 structural
aggregations:

| Aggregation | Cells passing MIN_CELL | Entries covered |
|---|---|---|
| Prefix length | 3 of 9 — /29 (18), /32 (27), /48 (32) | 77 of 91 (85%) |
| RIR /12 block | 5 of 6 — `2a00::/12` (31), `2a10::/12` (27), `2000::/12` (18), `2400::/12` (6), `2600::/12` (6) | 85 of 91 (93%) |

Both clear the bar the codebase already enforces and tests elsewhere. The residual
cells fold into an unnamed bucket exactly as they do for ASN rollups. No new
statistical standard is invented; the existing one is applied to a new axis.

**So: publish the structural aggregations, suppress the scoring ones, and state
which is which.** That is the whole answer, and it is defensible because it comes
from a rule already in the code.

### 2.3 The dimension that actually matters is blast radius, not entry count

Entry count is a meaningless denominator for IPv6. Measured:

| Prefix | Entries | /64 subnets each | /64 subnets total |
|---|---:|---:|---:|
| /29 | 18 | 34,359,738,368 | 618,475,290,624 |
| /30 | 1 | 17,179,869,184 | 17,179,869,184 |
| /32 | 27 | 4,294,967,296 | 115,964,116,992 |
| /36 | 4 | 268,435,456 | 1,073,741,824 |
| /38 | 1 | 67,108,864 | 67,108,864 |
| /39 | 3 | 33,554,432 | 100,663,296 |
| /40 | 3 | 16,777,216 | 50,331,648 |
| /44 | 2 | 1,048,576 | 2,097,152 |
| /48 | 32 | 65,536 | 2,097,152 |
| **Total** | **91** | | **752,915,316,736** |

Equivalently **11,488,576 /48 sites**.

Two facts an analyst needs and cannot currently get:

- **The 18 /29 entries — 20% of the list — carry 82% of the total blast radius.**
- **The 32 /48 entries — 35% of the list — carry 0.0003% of it.**

A feed that reports "91 IPv6 entries" and stops has told the operator nothing about
what applying it does to their network. This is the single most valuable v6
aggregation available, it needs no new data, and it is statistically solid because
it is arithmetic rather than inference.

### 2.4 Contiguity is a finding, not just a compression opportunity

Four runs of adjacent prefixes exist:

```
2a11:f080::/30  <-  2a11:f080::/32, 2a11:f081::/32, 2a11:f082::/32, 2a11:f083::/32
2a05:f680::/31  <-  2a05:f680::/32, 2a05:f681::/32
2a14:7c2::/31   <-  2a14:7c2::/32, 2a14:7c3::/32
2a05:b0c6:a000::/38 <- 2a05:b0c6:a000::/39, 2a05:b0c6:a200::/39
```

Four consecutive /32s under single control is an operator holding contiguous
RIR-scale allocations — a materially different signal from four unrelated listings.
There is also concentration at the allocation level: 70 distinct /32s across 91
entries, with `2001:678::/32` accounting for 14.

**Report adjacency; do not collapse it in the feed.** Collapsing changes what is
published relative to what Spamhaus said and destroys the per-entry SBL mapping
(§3.1). Surface it as an insight instead.

## 3. What analysts actually need — and what we are throwing away

### 3.1 The SBL ID is in the payload and the parser discards it

The DROPv6 records look like this:

```json
{"cidr":"2001:678:254::/48","sblid":"SBL697648","rir":"ripencc"}
```

`parsers.spamhaus_json` reads `data["cidr"]` and ignores `sblid` and `rir`
entirely. Spamhaus's own documented text conversion emits `(.cidr) + " ; " +
(.sblid)`, and listing details are looked up by IP, IP range, or SBL ticket number
at [check.spamhaus.org](https://check.spamhaus.org/) ([Spamhaus Blocklist
documentation](https://www.spamhaus.org/blocklists/spamhaus-blocklist/)).

**This is the highest-value analyst affordance available in this feature and it
costs nothing — the data is already being fetched and parsed.** The first question
on any false-positive report is "why is this listed", and the SBL ID answers it
with an authoritative upstream citation instead of "a source we trust said so".

Proposal:

- Add `source_reference: str | None` to `IndicatorRecord` and `ScoredIndicator` —
  a generic upstream ticket/reference field, not a Spamhaus-specific one, so other
  sources can populate it later.
- `spamhaus_json` populates it from `sblid` for both the v4 and v6 sources. The v4
  feed gains this too: 1,681 v4 records are promoted by `spamhaus_drop_v4` and are
  equally unciteable today.
- Emit it in `all.json` and as a column in `all.csv`. Render it in the dashboard
  lookup result and link to the Spamhaus checker.
- Keep it out of the plain-text feeds — those are parsed by firewalls, and the
  header already carries attribution.

Confirm the exact deep-link URL form against the checker at implementation time
rather than constructing one; only the lookup entry point is documented.

### 3.2 The `rir` field, with an honest caveat

`rir` states which registry allocated the block. It is genuinely useful for abuse
reporting — it tells you which registry's abuse contact path applies.

It is also one inference step away from the geography this project deliberately
refuses to publish. The existing objection is specific and correct: an ASN's
registration country is not where traffic originates. The RIR is coarser still.

Recommendation: carry `rir` in `all.json` for routing abuse reports, use the
derived /12 block for the distribution chart (which is address-space structure, not
geography), and **do not** render a country or region label anywhere. If that feels
too close to the line, drop `rir` and keep the /12 aggregation, which is computed
from the address itself and carries no registry claim at all.

### 3.3 Wide prefixes are the semantic of DROP, and this must be explained

General IPv6 operational guidance is consistent: `/128` is never the right unit
because privacy extensions rotate addresses, `/64` is the floor and the default
scope for one actor, and `/32` is typically an entire ISP that should
"almost never" be treated as a single actor ([geoiphub prefix
guidance](https://geoiphub.com/blog/rate-limit-and-block-ipv6-by-prefix), consistent
with RFC 6177 / BCP 157 allocation practice and [RIPE-690](https://www.ripe.net/publications/docs/ripe-690/)).

Forty-five of our 91 entries (49%) are at /32 or wider.

An analyst applying the normal heuristic would look at a /29 and conclude the feed
is recklessly aggregated. They would be wrong, and the reason is specific: DROP is
a "do not route or peer" list of netblocks **leased or stolen outright by criminal
operations**, published for firewall and backbone use ([Spamhaus
DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)). The whole
allocation is the finding. That is precisely the documented exception to the
"never block a /32" rule.

If the page does not say this, the wide prefixes read as a defect. Saying it is the
difference between a feed an analyst trusts and one they discard. This belongs on
the dashboard next to the prefix chart, not buried in the README.

### 3.4 ipset cannot mix address families

`hash:net family inet6` is a separate set from `hash:net family inet` — this is a
hard constraint of ipset, not a stylistic choice ([firewalld ipset
documentation](https://firewalld.org/2015/12/ipset-support)). A second file is
mandatory, and the v4/v6 `iptables`/`ip6tables` rules are separate commands.

## 4. Two live defects

### 4.1 `write_ipset` silently drops IPv6 and the dashboard publishes a wrong count

`emit.write_ipset` declares `create xfeeds hash:net family inet` then filters
`if r.ip_or_cidr.version == 4` — no comment, no count, no warning. The dashboard's
downloads table reports its entry count as `counts["high"]` (3,902) for a file
containing 3,811.

Fix: `write_ipset` gains `family: int = 4`, emitting `family inet` / `family inet6`
and set name `xfeeds` / `xfeeds6`, plus a header line stating how many records of
the other family were excluded and where to get them. `emit_all` calls it twice.
Counts come from the manifest, per family.

### 4.2 `build_lookup_index` skips IPv6, producing confidently wrong answers

`dashboard.build_lookup_index` contains a bare `if item.version != 4: continue`.
The "Check an address" box therefore reports v6 prefixes the feed is **actively
blocking** as not listed — the worst failure mode for the one interactive feature
on the page, during exactly the triage task it exists to serve.

`lookup.json` stores integer `[lo, hi]` bounds; v6 integers exceed
`Number.MAX_SAFE_INTEGER`, which is presumably why it was skipped. Add a parallel
`r6` array with decimal-string bounds and a `BigInt` client path, leaving the v4
fast path on plain numbers. `BigInt` is baseline in every browser the dashboard
targets and adds no dependency. Cost: 91 rows against ~4,700.

## 5. Output layout

Family-suffixed files **alongside** the existing combined files. Nothing is removed.

```
feeds/
  high-confidence.txt          # UNCHANGED - combined, both families
  high-confidence-v4.txt       # new
  high-confidence-v6.txt       # new
  medium-confidence.txt        # UNCHANGED - combined
  medium-confidence-v4.txt     # new
  medium-confidence-v6.txt     # new
  iptables.ipset               # v4, now states what it excludes
  iptables6.ipset              # new
  nftables.conf                # UNCHANGED - already carries both families
  all.csv / all.json           # gain address_family + source_reference
```

The same files land in `noncommercial/` and `clean/` through the existing
`emit_all` tier loop at no extra cost.

**Why suffix rather than split.** Splitting `high-confidence.txt` into v4-only is
the cleaner end state and the wrong move here: thousands of pfSense/OPNsense URL
tables and cron `curl`s point at that filename, and silently changing what it
returns is what AGENTS.md rule 4 exists to prevent. Suffixed files are additive,
and the README recommends them as the default going forward.

## 6. Header and manifest

Text feed headers gain an address-family line, an entry count, and — for v6 while
it remains single-source — a concentration notice:

```
# Address family: IPv6 only
# Entries:   91
# Blast radius: 11,488,576 /48 sites across 70 distinct /32 allocations
#
# IPv6 coverage in this feed comes from a single source family (Spamhaus
# DROPv6). Those records are promoted on that source's precision alone,
# which is the same basis as 44% of the IPv4 high-confidence feed. The
# limitation is concentration, not quality: if this one source degrades
# there is no second opinion to fall back on. See README "IPv6 coverage".
```

The notice is **computed**, printed only when the family spans fewer than two
independence classes, so it disappears the day a second v6 source is enabled.
Hard-coding the Spamhaus sentence would go stale silently — a failure mode this
repo keeps hitting with documentation.

`manifest.json` gains a `families` block:

```json
"families": {
  "v4": {"high": 3811, "medium": 828, "published": 4639,
         "independence_classes": 7, "sources": 12},
  "v6": {"high": 91, "medium": 0, "published": 91,
         "independence_classes": 1, "sources": 1,
         "blast_radius_48": 11488576, "distinct_allocations_32": 70}
}
```

Per-family `independence_classes` is what makes the notice testable and makes "did
v6 corroboration ever improve" a chartable question.

## 7. Visualizations

Driven by §2: publish what the data supports, suppress what it does not, and label
the suppression.

### 7.1 Prefix length and blast radius — the primary v6 chart

A horizontal bar chart of entries by prefix length, with a second encoding for
blast radius, v4 and v6 in one figure. Cells below `MIN_CELL` fold into an unnamed
bucket, consistent with existing ASN rollups.

This is the chart that answers "what does applying this feed actually do", and it
is the one an operator uses to decide whether a /29 belongs in their ruleset. Pair
it with the §3.3 explanation of why DROP prefixes are wide, or it will be
misread.

Guard `insights._addresses_of` at the same time: it returns `num_addresses` for v6
networks, so a single /29 contributes 2^99 and will dominate any aggregate it
touches. Cap the weight or return prefix length and let callers decide.

### 7.2 RIR /12 block distribution

Five named cells clear `MIN_CELL`, covering 93% of entries. Address-space
structure, no geography. Small, honest, and genuinely informative — it shows the
listings concentrate in `2a00::/12` and `2a10::/12`.

### 7.3 Allocation concentration

70 distinct /32s across 91 entries, top allocation holding 14, plus the four
contiguous runs from §2.4. Rendered as a short table rather than a chart — it is a
handful of rows and a chart would be decoration.

### 7.4 An IPv6 spectrum strip — recommended against

A linear 2^128 axis renders 91 prefixes as an invisible smear. Restricting to
`2000::/3` and log-scaling into 256 buckets makes it visible, but it would show 70
scattered marks and say nothing the RIR chart does not say better and more
honestly. The v4 strip earns its place by answering "how much of the internet do we
see activity in at all" over 4,730 entries; the v6 equivalent over 91 single-source
entries answers nothing.

Recommendation: **do not build it.** Revisit if a second v6 source lands.

### 7.5 Explicitly suppressed, with stated reasons

Rendered as a short panel listing what is unavailable and why, rather than as
missing charts a reader has to notice:

| Analysis | Why unavailable for IPv6 |
|---|---|
| Corroboration histogram | 1 independence class — one bar |
| Score distribution | All 91 records score 90.0 |
| Added/removed churn | Single source; the whole family moves as a block |
| ASN persistence | Enrichment table (`iptoasn.com`) is IPv4-only |
| Category breakdown | All records carry the same two categories |

This is the user-facing form of §2.1, and it is more useful than the charts would
have been.

### 7.6 Split the `unenriched` counter

`insights.build_insights` merges v6 observations and genuine ASN-lookup misses into
one `unenriched` number. Split into `unenriched_ipv6` and `unenriched_no_asn`, and
render the v6 figure explicitly — "91 IPv6 prefixes are excluded from network
analysis; the ASN table is IPv4-only" — rather than as an unexplained residual.

### 7.7 Downloads table

Add suffixed files, an address-family column, and correct per-family counts from
the manifest. Fixes the §4.1 miscount.

## 8. README changes

**8.1 `## Using the feeds`** — address-family column; list suffixed files; mark the
combined files "both — use the suffixed file if your tooling is single-stack".

**8.2 New `### IPv6 coverage`** subsection:

> xfeeds publishes IPv6 as a separate track. It is small and structurally different
> from the IPv4 feed: 91 prefixes from a single source family, Spamhaus DROPv6.
>
> **What the limitation actually is.** Those records are promoted on that source's
> precision alone. So are 1,681 IPv4 records — 44% of the IPv4 high-confidence feed
> rests on the same basis. The problem with IPv6 is not that the data is weaker; it
> is that there is no second source, so nothing corroborates it and nothing covers
> for it if that source degrades. Treat it as a concentration risk.
>
> **The prefixes are wide on purpose.** /29 to /48, no individual addresses. General
> IPv6 practice is to work at /64 and to treat a /32 as an entire ISP that should
> almost never be blocked wholesale. DROP is the documented exception: it lists
> netblocks leased or stolen outright by criminal operations, where the whole
> allocation is the finding. Applying this feed blocks 11,488,576 /48 sites, and 18
> entries account for 82% of that. Review the wide entries before deploying.
>
> **Which file.** Single-stack IPv4: `high-confidence-v4.txt` and `iptables.ipset`.
> Dual-stack: both, or `nftables.conf`, which has always carried both families in
> separate sets.

**8.3 Fix the ipset recipe** — currently presented as *the* firewall recipe while
covering only v4:

```bash
curl -sS https://neilweitzel.github.io/xfeeds/iptables.ipset  | sudo ipset restore -!
curl -sS https://neilweitzel.github.io/xfeeds/iptables6.ipset | sudo ipset restore -!
sudo iptables  -I INPUT -m set --match-set xfeeds  src -j DROP
sudo ip6tables -I INPUT -m set --match-set xfeeds6 src -j DROP
```

**8.4 `## What the dashboard shows`** — opens with "The IPv4 space as one strip" and
reads as though the corpus were IPv4-only. Add the prefix/blast-radius chart, the
RIR distribution, the suppressed-analysis panel, and state that ASN analysis is
IPv4-only because the enrichment table is.

**8.5 `## Safety rails`** — the `/48` v6 cap is listed without rationale. Since
Spamhaus legitimately publishes /29s, that cap rests entirely on the DROP
exemption. Load-bearing and undocumented.

**8.6 `### Why an address is or is not listed`** — document `source_reference` in
the `explain` output once §3.1 lands. That command is the false-positive triage
tool and an upstream ticket ID is the strongest thing it can print.

## 9. Deferred

- **IPv6 ASN enrichment.** `iptoasn.com` publishes a v6 table under the same PDDL
  licence, but it means 128-bit keys, a much larger table and a new cache entry.
  Ninety-one prefixes from one source does not justify it.
- **A second IPv6 source.** The highest-value change available and the only one that
  makes v6 corroboration possible. Needs a survey of public feeds publishing v6
  under usable licences, then an ADR and an ADR-033-style overlap measurement
  against DROPv6. Everything conditional in this spec keys off it.
- **/64 aggregation policy.** No /128s appear today because the only source
  publishes allocations. Any future source publishing individual v6 addresses needs
  a /64 rollup rule before it ships — a /128 blocklist is close to useless against
  privacy-extension rotation, and a naive one would explode the entry count.

## 10. Decided: IPv6 is not capped below `high`

Considered and rejected: capping v6 to medium until a second source corroborates it.

**44.2% of the IPv4 high-confidence feed is single-class** — 1,686 of 3,811
records, of which 1,681 are promoted by `spamhaus_drop_v4`, the direct IPv4 sibling
of `spamhaus_drop_v6`. Same source family, same promotion mechanism, same trust
basis.

Capping v6 on corroboration grounds would require capping those 1,681 v4 records on
identical grounds. The `promotes` path in `score.py` exists precisely to encode
"this source's word alone is enough", and DROP is the canonical case for it.

The honest disclosure is therefore about **concentration**, not quality — which is
what §6 and §8.2 say.

## 11. Testing

| Test | Asserts |
|---|---|
| `test_v4_feed_contains_no_ipv6` | Every line of `*-v4.txt` parses as IPv4 |
| `test_v6_feed_contains_no_ipv4` | Mirror |
| `test_family_split_is_lossless` | v4 + v6 counts equal the combined file exactly |
| `test_ipset_v6_records_not_silently_dropped` | `iptables6.ipset` holds what `iptables.ipset` excludes |
| `test_lookup_index_finds_ipv6_record` | A known v6 prefix resolves through the index — regression guard for §4.2 |
| `test_manifest_family_counts_match_emitted_files` | Published numbers equal file contents — prevents the §4.1 miscount recurring |
| `test_concentration_notice_only_when_single_class` | Notice is data-driven and vanishes with a second class |
| `test_sbl_id_parsed_and_never_in_text_feeds` | `source_reference` populated from `sblid`; absent from `*.txt` |
| `test_addresses_of_caps_ipv6_weight` | A /29 cannot dominate an aggregate |
| `test_min_cell_folding_applied_to_v6_aggregations` | Cells under 5 fold, consistent with ASN rollups |
| `test_determinism_with_mixed_families` | Two runs produce byte-identical suffixed files — AGENTS.md rule 4 |

Fixtures exist: `tests/fixtures/sources/spamhaus_drop_v6.json`, which already
contains `sblid` and `rir`.

## 12. Sequencing

| Wave | Work | Rationale |
|---|---|---|
| 1 | `write_ipset` family parameter + `iptables6.ipset` + manifest `families` | Live silent drop and a wrong published count |
| 1 | `build_lookup_index` IPv6 support | Confidently wrong answers during triage |
| 2 | `source_reference` / SBL passthrough (v4 and v6) | Highest analyst value; unblocks dashboard and `explain` |
| 2 | Suffixed text feeds + computed concentration notice + tests | The dual-track deliverable |
| 2 | README §8.1–8.3 | Must land with the files |
| 3 | Prefix/blast-radius chart, RIR distribution, allocation table, suppressed panel, `unenriched` split, `_addresses_of` guard | Visualization |
| 3 | README §8.4–8.6 + ADR entry | Documentation catches up |

Waves 1 and 2 both touch `emit.py` and stay sequential. Wave 3 is
`dashboard.py`/`insights.py` and can run parallel to the wave 2 README work.

## 13. ADR text

> **Dual-track IPv6 output, and what its aggregations may claim.** IPv6 has shipped
> inside the combined feeds since `spamhaus_drop_v6` was enabled, so single-stack
> IPv4 consumers were already receiving unparseable lines. Family-suffixed files are
> added alongside the combined ones rather than changing what `high-confidence.txt`
> returns, because firewall URL tables point at that filename. `write_ipset` was
> found to drop v6 silently while the dashboard published the combined count, and
> `build_lookup_index` skipped v6 so the address lookup reported blocked prefixes as
> unlisted; both are fixed.
>
> The 91 v6 records have zero variance on every scored dimension, so corroboration,
> score, churn and category charts are suppressed with stated reasons rather than
> rendered as single bars. Structural aggregations — prefix length, blast radius and
> RIR /12 block — are published because their cells clear the existing `MIN_CELL`
> threshold, applying a rule the codebase already enforces rather than inventing a
> new standard. Blast radius is reported alongside entry count because 20% of
> entries carry 82% of the address space affected.
>
> IPv6 is **not** capped below `high`. 44% of the IPv4 high-confidence feed is
> likewise single-class and promoted by the same Spamhaus source family, so capping
> v6 on corroboration grounds would require capping 1,681 v4 records identically.
> The disclosure is about concentration risk, and it is computed from the
> independence-class count so it disappears when a second v6 source lands.
>
> The DROPv6 payload carries `sblid` and `rir`, both previously discarded. A generic
> `source_reference` field now carries the upstream ticket into `all.json`, `all.csv`
> and `explain`, giving false-positive triage an authoritative citation. It is kept
> out of the plain-text feeds, which firewalls parse.
