# Reading the xfeeds dashboard

A guide to every panel and metric on <https://neilweitzel.github.io/xfeeds/>.

The dashboard itself is deliberately terse: numbers, tables, and short captions.
The reasoning behind how each metric is built lives here, so the page stays
data-driven without leaving anything unexplained. Per-source admit and reject
decisions live in [DECISIONS.md](DECISIONS.md); this document explains how to read
the page.

---

## Who this page is for

Two audiences, in this order.

**You need to block bad IPs today.** The first four sections are yours: the headline
numbers, the address lookup, the downloads table, and the copy-paste firewall
configuration. You can stop reading at "Set it up" and have a working blocklist.

**You are deciding whether to trust the feed, or studying the corpus.** Keep going.
"Feed health" and "Sources and provenance" answer whether the feed is alive and how
much evidence backs a record. "Threat landscape" is aggregate analysis of everything
the pipeline sees, including sources whose data is never republished.

---

## The headline numbers

Five cards, computed from the current run's `manifest.json`.

| Card | What it counts |
|---|---|
| safe to block | High-confidence entries. Corroborated across independent source families, or promoted by a single high-precision source. |
| worth challenging | Medium-confidence entries. Two independent sources. Challenge or rate-limit rather than drop. |
| rejected as uncorroborated | Share of everything seen this run that was withheld from publication. A high number is the filter working, not a fault. |
| sources healthy | Sources that returned usable data this run, over sources configured and not skipped. Skipped means "needs an API key we do not have". |
| changed this run | Addresses added and removed versus the previous run. |

What the cards deliberately do **not** count: anything withheld for licence reasons,
anything on the allowlist, and anything from a scoring-only source that no
redistributable source also reported. Those contribute to confidence but never to a
published record.

---

## Confidence bands

**High confidence** means one of two things:

- Independent corroboration. Two or more *independence classes* reported the address
  (see below), or
- Single-source promotion. Exactly one source reported it, but that source is
  high-precision by nature: Spamhaus DROP hijacked netblocks, and active abuse.ch
  command-and-control servers. These do not need a second opinion — a hijacked
  netblock is a matter of registry record, not of judgement.

**Medium confidence** means two independent sources agreed but the evidence does not
clear the bar for unconditional blocking. The intended action is to challenge or
rate-limit, not drop. Medium exists so that a consumer's policy choice stays theirs:
folding it into high would force a block, and discarding it would throw away real
signal.

**Withheld** entries are scored but never published. Most were reported by only one
ordinary source; some were dropped by a filter; some had only restricted evidence
behind them.

---

## Independence classes

This is the single most important idea on the page, and the reason raw source counts
are not used anywhere.

Many public blocklists copy from each other, aggregate each other, or draw on the
same upstream sensor network. If a pipeline counted files as votes, one source echoed
five times would look like five-way corroboration. That produces a feed that looks
highly corroborated and is actually one opinion wearing five hats.

So each source is assigned an **independence class**, and **a class votes at most
once.** Only the strongest contribution within a family counts toward a score. Adding
a second source to a class that already voted cannot raise an address's score — there
is a test in the suite that proves it, because this property is load-bearing.

Consequences visible on the page:

- The "How much agreement" table counts *classes*, not files. Three sources in one
  class read as one source.
- Some sources show **votes: no** in the source table. They are corroboration priors
  or redundant mega-lists — FireHOL Level 1 and Emerging Threats compromised IPs were
  disabled outright after overlap analysis showed they mostly restated other feeds,
  and IPsum was demoted to a prior for the same reason.
- Some show **scoring only**. Their licences forbid redistribution, so they may raise
  confidence in an address but their data never appears in any download, and they can
  never independently admit a record.

---

## Feed health

One chart, "Feed size and churn per run", plus the per-source status table.

**Upper area chart** — published high and medium counts across every recorded run.
Steps rather than a smooth curve are expected: the pipeline refreshes every six hours,
and a source dropping out or returning moves the whole line at once.

**Lower bar strip** — addresses added (green, up) and removed (red, down) in each run,
on the same time axis as the line above. These two views used to sit in separate
places on the page; they are stacked on a shared axis because churn is only meaningful
against the total it changes. A spike in the bars now sits directly beneath the step it
caused.

Hovering any run reports its size and its churn together.

**Reading churn.** Individual addresses age out of most upstream feeds within about a
week, so steady churn of a few hundred per run is healthy. Sustained near-zero churn
means a source has probably frozen. A single enormous swing usually means a large
source appeared or vanished, not that the internet changed.

**Source status values.**

| Status | Meaning |
|---|---|
| ok | Fetched and parsed this run |
| stale | Fetched, but upstream has not updated recently |
| empty | Fetched and parsed to zero records |
| failed | Fetch or parse error. Recorded in the manifest; does not fail the run |
| skipped | Configured but needs an API key that is not present |

A failing source degrades a run and never fails it. One dead upstream must not stop
the other eleven.

**How refresh failures are caught.** An automated heartbeat compares the committed
manifest against the one published to GitHub Pages and alerts after four missed
refreshes, so a silently stalled pipeline is caught by a machine rather than by a
reader noticing the date. A weekly keepalive job protects the schedule from GitHub's
inactivity disablement for public repositories.

---

## What got filtered out

Counts of what each safeguard removed this run.

| Rule | Why it exists |
|---|---|
| On the allowlist | Cloud providers, CDNs, search crawlers, and public resolvers. Blocking these breaks more than it protects. The allowlist is applied last, after every other stage, and a failed allowlist fetch aborts the run rather than publishing a partially filtered feed. |
| Prefix too wide | One bad `/8` can black-hole an ISP. Entries above a width threshold are rejected regardless of evidence. |
| Private or reserved | Non-global addresses cannot meaningfully appear in a public blocklist. |
| Licence | The only evidence was from sources that may not be republished. The address may well be malicious; we simply cannot say so in a redistributable file. |
| Tor exits | Tagged, never blocked. Whether Tor traffic is acceptable is a policy question for the consumer, not for a feed. |

---

## Threat landscape panels

Aggregate structure of the corpus. Every figure in this section is a derived count,
never an extract.

### IPv4 spectrum

The horizontal axis is the IPv4 address space itself, low to high, cut into 512 equal
slices of 8,388,608 addresses. **No bar points at an individual address** — that is
the point of the slicing. Height is log-scaled, because linear scaling would flatten
everything except the two or three busiest slices into invisibility.

The gaps are as informative as the spikes: they are reserved ranges, and large
allocations nobody has reported to us.

### Networks that keep coming back

Sorted by **days seen**, not by volume. Individual addresses churn out within about a
week, so a large one-day number is an incident, whereas a network present on eight
separate days is a standing pattern. Ranking by volume would surface the former and
bury the latter.

**Per million** divides by the size of the network's announced address space. Without
that normalisation, a ranking like this just rediscovers which hosting providers are
biggest — which needs no threat feed to work out. A small network with a high
per-million figure is a far stronger signal than a large network with a high raw
count.

**Date depth caveat.** Dates come from the upstream feeds that publish them —
bruteforceblocker carries roughly a month and ipthreat roughly ten days — which is why
these windows have more depth than the project's own run history. Days before xfeeds
started running are covered by those two feeds alone, and are therefore thinner than
recent days. Do not read a rising trend into the left-hand edge of a long window.

### IPv6 coverage

Deliberately **not** a parallel set of the IPv4 charts. The IPv6 corpus currently has
no variance in score, band, source, or category, so each of those charts would render
a single bar — the appearance of analysis with none of the substance. The "Not shown
for IPv6, and why" table lists them explicitly, because saying so is more useful than
leaving a reader to guess whether we looked.

What is shown instead is structural:

- **How wide each entry reaches.** Entry count is a poor measure for IPv6: a `/29` and
  a `/48` are both one line and differ by a factor of half a million. Reach is
  measured in covered `/64` networks instead, which is why the most numerous row is
  not the widest bar.
- **Where in global unicast space.** Which `/12` of `2000::/3` the listings fall in,
  derived from the address itself. This is address-space structure, not geography.
- **Adjacent prefixes.** Listings that sit next to each other in address space.
  Contiguous allocations under common control are a stronger signal than the same
  number of unrelated listings. They are reported, not merged: merging would diverge
  from what the upstream published and lose per-entry provenance.

**Why some entries are very wide, and why that is not reckless aggregation.** General
IPv6 practice treats a `/64` as one actor and a `/32` as an entire ISP that should
almost never be blocked outright. A meaningful share of these entries are `/32` or
wider. That is on purpose: Spamhaus DROP lists netblocks leased or stolen outright by
criminal operations, published specifically for firewall and backbone use, where the
whole allocation *is* the finding. **Review the widest entries before deploying
them** — they are correct as published, but they are blunt instruments.

IPv6 is not capped below high confidence, because the equivalent single-class
promotion rule already applies to IPv4. Treating v6 differently would be
inconsistent, not cautious.

### What the whole corpus looks like

The feeds contain only what we are licensed to republish. This panel covers
**everything the pipeline looks at**, including sources whose licences forbid
republishing their addresses.

That is possible because **a count is a derived fact, not an extract.** A restricted
source cannot have its rows copied into a feed file, but it can be credited with the
number of addresses it contributed. This is the only place on the page where a
scoring-only source appears by name against a figure.

Two guarantees constrain this panel:

1. **No individual address appears in it.** Not in any table, not in any tooltip.
   There is no "top offending addresses" list and there will not be one.
2. **Small groups are folded into an unnamed bucket.** Named ASNs below a threshold of
   a handful of addresses are aggregated, so no cell can be narrowed down to identify
   a single address.

The **Sources** column of the ASN table is the interesting one. A network reported by
nine or ten independent sources is not having a bad week; that is a sustained pattern,
and worth examining at the network level rather than address by address.

The **Only source** column counts addresses that nobody else reported — evidence the
feed would simply not have without that source, even though its data never ships.

---

## Licence tiers

Three published tiers, because three different redistribution promises apply.

| Tier | Path | Use |
|---|---|---|
| Primary | `/` | Anything, including commercial work. No source in it restricts commercial use. |
| Non-commercial | `/noncommercial/` | Non-commercial use only, CC BY-NC-SA 4.0. Larger, because it can include share-alike material in full rather than only counting it as corroboration. |
| Clean provenance | `/clean/` | Only sources with a named written licence permitting commercial redistribution. Ships a licence-and-credit manifest. |

**Choosing.** At a company, or building anything anyone pays for: primary. Home lab,
personal server, school, charity, or research: non-commercial, which sees more. This
is not a formality — the licences genuinely differ, and `noncommercial/LICENSE.txt`
spells out the terms.

Attribution travels with the data where a source requires it. Spamhaus attribution is
carried into published file headers as their terms require. Threat data is also
provided by [IPThreat](https://ipthreat.net) and by the
[Turris Sentinel](https://view.sentinel.turris.cz/) project at CZ.NIC (CC BY-NC-SA
4.0, non-commercial tier only). Network attribution in the analysis section uses
[IPtoASN](https://iptoasn.com/) by Frank Denis (Public Domain, PDDL v1.0), which
contributes no threat data and only turns an address into an AS number and a network
name.

---

## What is deliberately absent

- **No top-offending-addresses list.** It would be the restricted data itself in a
  thin disguise.
- **No registration-country mapping.** It was built, then removed: an ASN's
  registration location does not establish where its traffic originates, so a
  country column invited a conclusion the data does not support.
- **No per-record identity for restricted sources.** A scoring-only source can raise
  an address's confidence, but which restricted source vouched for it is never
  published. GreyNoise's terms permit aggregate reporting only, and that is what is
  reported.
- **No TAXII server.** STIX 2.1 is emitted as static bundles over HTTPS. The TAXII
  client ecosystem is stale enough that a static bundle is more interoperable in
  practice.
- **No benign-scanner deletions.** GreyNoise classifications *cap* an indicator at
  medium rather than removing it, preserving the consumer's policy choice.

---

## False positives

No blocklist is perfect. If an address here is legitimate,
[open an issue](https://github.com/neilweitzel/xfeeds/issues). Those are triaged ahead
of everything else, and confirmed mistakes are added to a permanent allowlist so they
cannot reappear in a later run.

Provided as-is with no warranty. Test against your own traffic before blocking in
production.
