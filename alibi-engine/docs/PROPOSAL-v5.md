# alibi — proposal for the next published version

*Status: draft for review. Author: prepared for Bread / @Sutaigne. Date: 2026-07-11.*

This document proposes a phased path to the next public release. It is grounded
in two real scan reports produced by the shipped v4.2.1 engine, not in
hypotheticals. Both reports are undermined by false positives — one cosmetically,
one fatally — so the spine of this plan is **trust first, coverage second**: a
forensic tool whose verdict a reviewer cannot believe has negative value,
because it launders a guilty machine and a clean one through the same noise.

The plan ships in two waves:

- **v4.3 (now)** — credibility fixes. No architecture change. Kill the
  false positives that break the verdict. P0 code for this wave is already
  drafted in this branch (see *Drafted changes* below).
- **v5 (next)** — architectural rework + the coverage that actually convinces a
  skeptic: intent, removed-hardware, and anti-forensics.

---

## 1. What the two reports proved

### Report A — `DESKTOP-F3SN84F` / `dalto` → INPUT DEVICES DETECTED

A genuine Cronus + Logitech G HUB + HidHide rig. The **verdict is correct**, but
of 34 MEDIUM "dual-use signals" roughly 30 are noise:

- **10 DLLInject MEDIUMs** are Windows Error Reporting crashes (`Fault bucket …,
  type N`, one literally empty). Cause: the bare token `inject` in
  `$DLLInjector_Names` is matched **unbounded against the full Application-log
  message body**, then the report truncates to 200 chars so the matching word is
  invisible.
- **3 LOLDrivers MEDIUMs** are false — `afd.sys` (Winsock) and `KslD.sys`
  (Defender's `MpKslDrv`) are legit System32 files. The SHA256 gate exists but is
  short-circuited: filename-match runs first, and System32 drivers are never
  hashed.
- **~11 duplicate "UNSIGNED: LIGHTSPEED Receiver"** — one Logitech dongle counted
  per endpoint.
- The one genuinely strong lead (an unsigned **"PCI Device"**) gets a single
  generic line with no VID/DEV — the exact place a DMA card would hide.

### Report B — `4070PC` / `lj031` → CHEATS DETECTED  *(the important one)*

**This verdict is a false positive against alibi itself.** The user downloaded
the GitHub source zip to `\Downloads`. `Scan-UserScriptContents` walked into
`dev\intel\extract-known-tokens.ps1` — a dev file whose entire job is to print
alibi's cheat-brand keyword list — matched `aimbot`, and returned HIGH/cheat →
**CHEATS DETECTED**. The existing self-exclusion only covers the six scanner
files by name and the scanner's own folder; it misses the `dev/` tree entirely.

Plus **16 MEDIUM false positives from Opera GX** (installs to `%LOCALAPPDATA%`,
not on the small hardcoded allowlist → every process and every module flagged
"user-writable, no allowlist match"), and the same `afd.sys` / `KslD.sys`
collisions joined by real-but-benign ASUS driver hits (`AsIO3.sys`, `IOMap64.sys`,
`MsIo64.sys`).

**The takeaway that sets the priority order:** anyone who downloads alibi to
inspect it — the exact audience a "read the source, trust the tool" project wants
— gets told their machine has cheats. That single bug is more damaging to the
project than any missing scanner.

---

## 2. Root causes (what's actually wrong, not the symptoms)

1. **No self-immunity.** alibi is a keyword scanner whose own source, dev-intel
   corpus, and sample reports contain every string it hunts. It does not
   recognize its own artifacts as its own.
2. **Allowlist-as-trust doesn't scale.** A hardcoded vendor substring list can
   never enumerate every legit app that installs to a user-writable path. The
   durable trust signal — a valid Authenticode signature — is unused in the
   process/module/user-writable paths.
3. **Filename ≈ evidence.** LOLDrivers and several scanners treat a filename
   match as a finding. Filenames collide (that's *why* malware uses OS driver
   names); only a hash or signature separates impersonator from original.
4. **Unbounded keyword matching in free text.** The `-Bounded` matcher exists but
   is not used on the Application-log message scan, so short tokens match inside
   unrelated words and crash reports.
5. **Severity = keyword class, not evidence strength.** HIGH/MEDIUM is decided by
   which array a string lands in, with almost no correlation, dedup, or
   confidence weighting. Noise and signal get the same colour.
6. **Silent-when-clean scanners.** A reviewer can't distinguish "ran and found
   nothing" from "didn't run" except via buried timing metadata.
7. **Presence, not intent.** The engine detects that Cronus/G HUB/HidHide are
   *present* but never reads what they were configured to do — the evidence that
   actually distinguishes "owns the hardware" from "used it to cheat."

---

## 3. Phase v4.3 — trust-first credibility release (drafted in this branch)

Five P0 fixes, all implemented and ready for review + a CI/Pester pass. They are
surgical and change no architecture. **Note:** drafted without a PowerShell
runtime available in the authoring environment — every function touched was
brace-balance-verified statically, but the release must go through the repo's CI
before tagging.

| ID | Fix | Kills | Files |
|----|-----|-------|-------|
| **P0-1** | Self-immunity: `Test-IsAlibiOwnPath` prunes any alibi kit/checkout (engine tree, `alibi-main*` zip, `dev/intel`, `dev/scripts`, and known dev filenames). Wired into the shared `Get-PrunedFiles` walker plus explicit guards in `Scan-UserScriptContents` and `Scan-Downloads`. | The **CHEATS-DETECTED-on-alibi-itself** false verdict (Report B) | `forensic-common.ps1` |
| **P0-2** | Authenticode trust: `Test-TrustedSignature` (cached by path). A valid signature demotes a user-writable item from MEDIUM to LOW in `Score-Item` (covers processes + services) and in `Scan-ProcessModules`. Allowlist also expanded with common AppData-installing apps. | The **16 Opera GX MEDIUMs** and every future Electron/Chromium FP | `forensic-common.ps1` |
| **P0-3** | LOLDrivers hash-first: hash *every* readable driver; SHA256 match wins over filename; filename-only matches on **Microsoft-signed** drivers are suppressed to INFO. | `afd.sys` / `KslD.sys` false BYOVD hits (both reports) | `forensic-common.ps1` |
| **P0-4** | Injector free-text match: drop generic `inject`/`injector` tokens, require a **word-bounded** match, skip WER/crash providers, and record the matched token. | The **10 phantom DLLInject MEDIUMs** (Report A) | `forensic-common.ps1` |
| **P0-5** | Dedup unsigned-driver findings by device + file. | The **~11 duplicate LIGHTSPEED** rows | `forensic-common.ps1` |

Version bumped `4.2.1 → 4.3.0`.

### v4.3 acceptance criteria
- Scanning a fresh `git clone` / release zip of alibi placed anywhere under a
  scanned root yields **CLEAN** (regression test: seed a repo copy in a temp
  Desktop/Downloads root, assert no HIGH/cheat findings sourced from it).
- Opera GX installed → **0** MEDIUMs attributable to Opera process/module paths.
- `afd.sys` / `KslD.sys` present → **0** LOLDrivers MEDIUMs; at most INFO
  "Microsoft-signed, not BYOVD".
- A WER-heavy Application log → **0** DLLInject findings unless a real bounded
  injector-name token is present.
- One multi-endpoint unsigned receiver → **1** finding.
- No scanner regresses to missing a true positive (keep a labelled fixture of the
  genuine Cronus/HidHide hits from Report A and assert they still fire).

### Non-goals for v4.3
No new scanners, no schema changes, no verdict-model change. Ship trust, then
build.

---

## 4. Phase v5 — architecture + the coverage that convinces

### 4.1 Architecture: separate collection from judgement
Today, collection, keyword-scoring, and severity are fused inside each
`Scan-*` function, and the keyword/allowlist/verdict logic is hardcoded across
2,000+ lines. Proposed structure:

- **Collectors** emit raw, typed *signals* (device, driver, file, process,
  event, registry value) with provenance and timestamps — no scoring.
- **A rules layer** scores signals. Move keyword lists, allowlists, driver
  publishers, and known-hashes into **external, versioned data files** (JSON/CSV)
  so the monthly cheat-intel pulse updates data, not code — and so a reviewer can
  diff "what alibi looks for" without reading PowerShell.
- **A verdict engine** consumes scored signals with explicit, testable rules and
  **correlation** (below).
- **Provenance stamping**: every alibi-authored file carries a sentinel so
  self-immunity is content-based, not path-heuristic.

This makes the whole thing unit-testable against fixtures — today there is no way
to assert "these inputs produce this verdict" without a live Windows box.

### 4.2 Verdict model: confidence, not keyword class
Replace "which array did the string land in" with a scored model:

- Each signal carries a **confidence** (hash/signature > config-content >
  filename > free-text keyword) and **recency**.
- **Correlation escalation.** On Report A, HidHide + Cronus USB + Cronus AppData
  + a fresh G HUB script are four correlated signals that never combine. A combo
  rule (concealment driver + adapter brand + recent script) should escalate where
  no single one does.
- Verdict tiers stay, but each is backed by a "why" that cites signal confidence,
  so `CHEATS DETECTED` is defensible line-by-line.

### 4.3 Coverage — intent (the biggest gap)
Detect *what was done*, not just *what is installed*:

- **Cronus/Zen**: enumerate `%APPDATA%\CronusZen` / `CronusZenBeta`, collect
  `.gpc` / `.gpj` / GamePack **names + hashes + timestamps** (the on-disk proxy
  for what was flashed). Flag CoD-related GamePack names. Absence of the folder
  while Zen Studio is installed = recent wipe = its own signal.
- **G HUB / LGS Lua**: read `%LOCALAPPDATA%\LGHUB` (incl. `settings.db`) and match
  script bodies for anti-recoil markers (`MoveMouseRelative` in a sleep loop,
  `IsMouseButtonPressed(1|3)`, `OnEvent`). Report A found the script and filed it
  INFO unread. Also flag an outdated G HUB (≤2021.10) on an otherwise-current box.
- **HidHide**: read the configured **hide-list + app whitelist** — the intent
  artifact (what it's masking), not just the driver's presence.

### 4.4 Coverage — removed hardware (the DMA/spoofer evasion)
- Enumerate **non-present** PCI/USB devices (`Enum\PCI`, `Enum\USB` ghost
  entries) — catches an unplugged DMA card or spoofer.
- Parse `C:\Windows\INF\setupapi.dev.log` (survives device removal): timestamped
  installs, `VEN_10EE`/Xilinx, and **two devices claiming the same VID/PID/serial**
  (KMBox clone tell).
- Flag **legit-looking-but-wrong** devices: unsigned "Realtek NIC"/NVMe clones,
  duplicate NICs, and surface the unsigned **PCI Device**'s hardware ID with
  `VEN_10EE` called out explicitly.

### 4.5 Coverage — anti-forensics (a too-clean hand-in is a signal)
- OS install date vs. hardware/account/game-install age (fresh reinstall before
  hand-in).
- Log-cleared events: Security **1102**, System **104**, USN **3079**.
- USN journal reset (`fsutil usn queryjournal`), wiper residue (SDelete/CCleaner/
  PrivaZer), empty Prefetch on an old install.
- Uninstall-survivor sweep for device/cheat names: Amcache, Prefetch, UserAssist,
  BAM, MuiCache, RecentApps.
- Emit a **"cleanliness anomaly" score** so a scrubbed machine no longer reads
  identically to a genuinely clean one.

### 4.6 Reporting & honesty
- Explicit **"N/N scanners completed"** line so "ran & clean" ≠ "didn't run".
- Every finding shows its **confidence + why**; suppressed items (e.g.
  MS-signed driver collisions) are visible as INFO, not hidden.
- Grow `KnownCheatHashes` beyond its single hardcoded sample, sourced from the
  intel pulse data file.

---

## 5. Suggested sequencing

1. **v4.3** — merge the drafted P0 fixes, add the regression fixtures in §3, tag,
   re-shoot the two example reports as proof (self-scan → CLEAN; Report A →
   INPUT DEVICES DETECTED with ~4 honest MEDIUMs instead of 34). *Ship.*
2. **v5.0-alpha** — refactor collectors/rules/verdict with fixture-based unit
   tests; move keyword/allowlist/hash data to external files; provenance stamping.
3. **v5.0** — intent scanners (§4.3) + correlation escalation (§4.2). Highest
   evidentiary payoff.
4. **v5.1** — removed-hardware (§4.4) + anti-forensics scoring (§4.5).
5. **v5.2** — reporting/honesty polish (§4.6), expanded intel data.

---

## 6. Risks / open questions
- **Authenticode cost.** Signature checks add latency on user-writable, unlisted
  binaries. Mitigated by path-caching (Opera's 16 PIDs → 1 check). Confirm total
  scan-time impact on a busy machine stays within budget.
- **Signature revocation / offline CRL.** `Get-AuthenticodeSignature` may hit the
  network for revocation. For a "no network calls" tool, pin to
  chain-status-without-revocation or document the exception.
- **Self-immunity vs. real cheats named "alibi".** Path heuristics could let a
  cheat hide under an `alibi-engine` folder name. v5 provenance stamping (content
  sentinel) closes this; v4.3's heuristic is an acceptable interim (worst case: a
  folder literally named to impersonate alibi is skipped — rare, and itself odd).
- **Removed-hardware enumeration requires elevation** and may be noisy on
  machines with lots of device churn — needs a confidence tier, not auto-HIGH.
- **Scope of v5 rewrite.** The refactor is the riskiest item; it can be deferred
  if v4.3 + intent scanners (bolted onto the current engine) deliver most of the
  value sooner.
