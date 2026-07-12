# Security policy

`alibi` is a read-only Windows forensic kit. Its value depends on three properties: the source is what the reviewer reads, the scan does not modify the system, and the detection logic is honest about what it can and cannot see. If you find a flaw in any of those, this document is how to tell us.

## Supported versions

| Version | Supported |
|---|---|
| v4.3.x  | yes |
| < v4.3  | no — please upgrade |

## What's in scope

Reports we want to receive:

- **Detection bypasses** — a cheat / spoofer / DMA artifact / input adapter that the kit *should* flag but doesn't, with enough specificity that we can reproduce.
- **Trust-claim contradictions** — copy in the README, `scanner/README.txt`, `alibi-safety-card.html`, or `one-page-guide.html` that says the kit doesn't do X, but the source does X.
- **Side effects** — anything the kit modifies on the host (registry, files, services) that violates the read-only guarantee. The opt-in LOLDrivers fetch is the one disclosed network call; anything else is a bug.
- **Parsing crashes** — malformed input (a weird Prefetch entry, a registry value the kit doesn't expect, a non-UTF8 path) that crashes the scanner before it writes a report.
- **HTML / JS issues** in the visual companion — XSS via untrusted finding metadata, broken offline behavior, anything that calls out to the network.

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

## Antivirus / SmartScreen false positives

A forensic anti-cheat scanner is, byte-for-byte, hard to tell apart from the things it hunts. `alibi` deliberately contains:

- a plaintext database of cheat-brand, spoofer, and DMA-hardware names (`forensic-common.ps1`);
- the literal high-risk command strings it scans a suspect machine for — e.g. `powershell -encodedcommand`, `iex (new-object net.webclient`, driver-signing-bypass flags (`forensic-common.ps1`);
- `.bat` launchers that require elevation (right-click → *Run as administrator*) and run unsigned PowerShell (`-ExecutionPolicy Bypass`), because a downloaded, unsigned script won't run otherwise.

Signature and heuristic engines — and especially **SmartScreen reputation**, which blocks *new, unsigned, rarely-downloaded* files regardless of content — score those exactly as they'd score the real thing. The result is a false positive at download or extract time.

Detections observed so far, both on GitHub ZIP downloads: **`Trojan:Script/Wacatac.B!ml`** and **`Trojan:Win32/Sprisky.U!cl`** (the latter on the *source* ZIP, 2026-06-25). The `!ml` / `!cl` suffixes mean cloud machine-learning / cloud-heuristic verdicts, not confirmed signatures — both are well-known generic false-positive families that fire on many legitimate scripts and tools. A local Defender scan of the same files returns clean, which is the tell (re-verified 2026-07-12: full tree, built release ZIP, and source-style ZIP all scan clean, including with the internet-download Mark of the Web applied). These false positives have been reported to Microsoft for reclassification.

None of it is an infection, and you can prove that:

- **Hashes.** Every shipped file's SHA256 is in [`HASHES.txt`](../HASHES.txt). Compare what you received against it.
- **VirusTotal.** Upload the ZIP to [virustotal.com](https://www.virustotal.com) for a ~70-engine second opinion.
- **The source.** Everything is plain text. The "suspicious" strings are detection signatures, sitting in readable arrays you can audit line by line.

### For people downloading the kit

- **Browser says "Virus detected" / blocks the download.** Override it in the browser's Downloads list (Edge: ⋯ → *Keep* → *Keep anyway*; Chrome: *Keep*), then verify against `HASHES.txt`.
- **"Access to the compressed (zipped) folder is denied" on extract.** That's the *Mark of the Web*, not a virus — Windows tags all internet downloads (see [Microsoft's Attachment Manager note](https://support.microsoft.com/en-us/topic/information-about-the-attachment-manager-in-microsoft-windows-c48a4dcd-8de5-2af5-ee9b-cd795ae42738)). Clear it with `Unblock-File .\alibi-main.zip` (or right-click the ZIP → Properties → **Unblock**), then extract. 7-Zip ignores the tag entirely.

### What we do about it

- **Report false positives to the vendor.** A confirmed false positive should be submitted to Microsoft at the [Defender Security Intelligence portal](https://www.microsoft.com/en-us/wdsi/filesubmission) (mark *"I believe this file is clean"* and note it's an open-source defensive forensic tool). A reclassification there clears the verdict for everyone. If you hit a block on another vendor's engine, tell us via private reporting and we'll submit it there too.
- **Keep the trigger surface minimal.** We don't commit redundant ZIP archives or compiled blobs; the only thing in the repo is the readable source the tool needs to run.

### What we deliberately don't do

- **We don't obfuscate or encode the keyword database to dodge antivirus.** Runtime-decoded string blobs read as *more* malicious to heuristics, not less — and unreadable detection logic would break the kit's whole "read every line" trust model. The signatures stay in plaintext on purpose.
- **We don't Authenticode-sign** (see [What we don't do](#what-we-dont-do)). Signing would raise download reputation, but it fights the same plain-source trust model. We trade that reputation cost for auditability and lean on hashes + VirusTotal + vendor submission instead.

## Disclosure timeline

We aim for an initial response within 7 days of the report. Substantive fixes target the next minor release (typically within 2–4 weeks). Public disclosure happens after the fix ships, with credit to the reporter unless anonymity is requested.

## What we don't do

- **We don't sign Authenticode certificates.** This is a plain-source kit; binary signing fights the "read every line" trust model.
- **We don't ship a binary that can't be audited.** Every file in the kit is plain `.ps1` / `.html` / `.css` / `.js` / `.txt` — no compiled binaries, and no opaque archives. Version history lives in git, not in committed ZIPs.
- **We don't run a bug bounty.** This is an open community kit, not a commercial product. Credit and a `CHANGELOG.md` entry are what we have to offer.

## Authors

Author: Bread ([@Sutaigne](https://github.com/Sutaigne)). Contributor: Drownmw.
