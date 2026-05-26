# Security policy

`alibi` is a read-only Windows forensic kit. Its value depends on three properties: the source is what the reviewer reads, the scan does not modify the system, and the detection logic is honest about what it can and cannot see. If you find a flaw in any of those, this document is how to tell us.

## Supported versions

| Version | Supported |
|---|---|
| v3.8.x  | yes |
| < v3.8  | no — please upgrade |

## What's in scope

Reports we want to receive:

- **Detection bypasses** — a cheat / spoofer / DMA artifact / input adapter that the kit *should* flag but doesn't, with enough specificity that we can reproduce.
- **Trust-claim contradictions** — copy in the README, `kit/README.txt`, `alibi-safety-card.html`, or `one-page-guide.html` that says the kit doesn't do X, but the source does X.
- **Side effects** — anything the kit modifies on the host (registry, files, services) that violates the read-only guarantee. The opt-in LOLDrivers fetch is the one disclosed network call; anything else is a bug.
- **Parsing crashes** — malformed input (a weird Prefetch entry, a registry value the kit doesn't expect, a non-UTF8 path) that crashes the scanner before it writes a report.
- **HTML / JS issues** in the visual companion — XSS via untrusted finding metadata, broken offline behavior, anything that calls out to the network.
- **PowerShell / Python parity drift** — a scenario where the canonical PowerShell kit and the Python parity port produce materially different verdicts on the same machine.

## What's out of scope

These are documented limitations, not bugs:

- **DMA cheats at runtime.** No PC-side footprint by design. The kit detects DMA *development* artifacts (`pcileech_top.bin`, FPGA build dirs, branded DMA hardware vendor names).
- **A user lying about whether they ran the kit, or substituting a report from a clean machine.** That requires the kit-self-integrity flow described in [`docs/for-reviewers.md`](./docs/for-reviewers.md) — verify the kit's hashes against `HASHES.txt` before trusting any report.
- **Kernel-level adversaries on the suspect machine.** A rootkit can hide arbitrarily; the kit is keyword + registry + filesystem matching, not anti-rootkit telemetry.
- **Sophisticated artifact wiping** (Prefetch deletion, BAM key flushing, USB device-history scrubbing). The kit acknowledges this in its own coverage-limitations section; a clean result is necessary but not sufficient.

## How to report

**Preferred:** use GitHub's private vulnerability reporting:

→ https://github.com/Sutaigne/alibi/security/advisories/new

This routes the report directly to the maintainers and gives you a private channel to share repro steps, sample artifacts, or sanitized scan output.

**Acceptable also:** open a public issue if and only if the report does not include active-evasion specifics (e.g. "PowerShell-encoded payload format that slips past `$ScriptContent_HighRisk`") that would help cheaters more than it would help defenders. When in doubt, use private reporting.

## Disclosure timeline

We aim for an initial response within 7 days of the report. Substantive fixes target the next minor release (typically within 2–4 weeks). Public disclosure happens after the fix ships, with credit to the reporter unless anonymity is requested.

## What we don't do

- **We don't sign Authenticode certificates.** This is a plain-source kit; binary signing fights the "read every line" trust model.
- **We don't ship a binary that can't be audited.** Every file in the kit is plain `.ps1` / `.py` / `.html` / `.css` / `.js` / `.txt`. The `archive/` zips are historical PowerShell source, not compiled.
- **We don't run a bug bounty.** This is an open community kit, not a commercial product. Credit and a `CHANGELOG.md` entry are what we have to offer.

## Authors

Author: Bread ([@Sutaigne](https://github.com/Sutaigne)). Contributor: Drownmw.
