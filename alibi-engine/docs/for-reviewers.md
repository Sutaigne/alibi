# For reviewers — how to read an alibi report you didn't run

Someone handed you a `.txt` file (and maybe a matching `_visual.html`) and is asking you to believe it. This guide is how you should approach it.

The whole point of alibi is that the report is *auditable* — every claim it makes is grounded in source you can read. But that auditability only works if you do the verification. This document walks you through it in five steps.

---

## 1. Verify the kit that produced the report

A cheater could hand you a *modified* kit and a link to the *unmodified* repo. Your first job is to confirm those are the same.

If you're auditing in person:

```powershell
# In the kit's root directory (the one with Run scan.bat):
Get-FileHash scanner\forensic-common.ps1 -Algorithm SHA256
Get-FileHash scanner\forensic-scan.ps1   -Algorithm SHA256
Get-FileHash scanner\console-rig-audit.ps1 -Algorithm SHA256
```

Compare those SHA256 values against [`HASHES.txt`](../HASHES.txt) at the root of this repo. If they don't match, you are not looking at the kit you think you're looking at. Stop.

If you're auditing remotely (the user sends you the report only): you can't fully close this gap without a copy of the kit they ran. Ask them to also send the `scanner\` folder, or to re-run the scan in front of you (over screenshare) using a fresh download of `scanner\` from this repo.

## 2. Confirm the report's own header

Open the `.txt` file. The first 20 lines should look like:

```
================================================================
  QUICK READ - START HERE
================================================================

  VERDICT: <one of the four tiers>
  ...

================================================================
  ALIBI v4.3.0 - CONSOLIDATED REPORT
================================================================

  Generated:  <timestamp>
  Hostname:   <hostname>
  Username:   <username>
  OS:         <Windows version>
  Admin mode: True               ← this matters
  Verdict:    <same as above>
```

Things to check:

- **`Admin mode: True`.** If it says `False`, the scan ran without administrator rights, and several scanners (BAM, USB history detail, ShimCache, driver enumeration) will have emitted `WARN` for "access denied" rather than real findings. A `False` scan does not prove a clean machine — it proves the user didn't elevate. Ask them to re-run with admin.
- **`Generated:`** timestamp is recent. If the report is days old, the system state may have changed.
- **`Hostname:`** matches whatever they told you it would.
- **`Verdict:`** matches between the QUICK READ block and the consolidated-report header. If they disagree, the file has been edited.

## 3. Understand what verdict means what

| Mode | Verdict | What the scanner is claiming |
|---|---|---|
| **PC** | `CHEATS DETECTED` | HIGH-confidence cheat brand, HWID spoofer, DMA artifact, or known-hash match within last 180 days. |
| | `INPUT DEVICES DETECTED` | HIGH-confidence input-adapter software (XIM / Cronus / ReaSnow / KMBox / Titan / reWASD). No cheats. |
| | `UNSURE` | MEDIUM dual-use findings only. Needs human review of the named items. |
| | `CLEAN` | No HIGH or MEDIUM matches recent enough to bump the verdict. |
| **Console-rig** | `MITM CHEAT STACK DETECTED` | Vision aimbot or adapter configurator software present. |
| | `CAPTURE STACK PRESENT` | Capture-card / HID-emulator software only — legitimate streamer signal. |
| | `UNSURE` / `CLEAN` | Same semantics as PC mode. |

The verdict you should treat as definitive evidence of cheating is `CHEATS DETECTED` or `MITM CHEAT STACK DETECTED`. Everything else, including `INPUT DEVICES DETECTED`, requires interpretation — input adapters are legal hardware that some games ban and some don't.

A `CLEAN` verdict means the kit did not find what it knows how to look for. See section 5 for what that does not rule out.

## 4. Read the named items

Below the verdict, the report lists the artifacts that drove the call. Every line in "Named items" has a category (`Prefetch`, `MUICache`, `USB`, `DMA`, `AIVision`, `UserScripts`, etc.) and a matched pattern (`engineowning`, `rut.gg`, `cronus`, `aimmy`, `bcdedit /set testsigning`, etc.).

If you want to confirm a match wasn't fabricated:

1. Note the pattern (e.g. `engineowning`).
2. `grep` for it in the kit's keyword arrays — [`scanner/forensic-common.ps1`](../scanner/forensic-common.ps1) line 42 onwards.
3. The pattern should appear verbatim in one of `$CheatBrands_COD`, `$DMA_Indicators`, `$VisionAimbot_AI_PC`, etc. If it does not, the report has been hand-edited — the scanner can't emit a pattern that isn't in its database.

## 5. Known evasions — what `CLEAN` does NOT rule out

- **Pre-scan wiping.** A user who deleted Prefetch (`del C:\Windows\Prefetch\*.pf`), cleared MUICache, and ran `wevtutil cl` against the event logs before the scan will look cleaner than they are. The kit does not detect the act of wiping, only the absence of artifacts.
- **DMA cheats at runtime.** Hardware DMA cheats (PCILeech variants on a separate FPGA) have no PC-side footprint while running. The kit flags only the *development* artifacts (`pcileech_top.bin`, branded DMA hardware build directories). A user who buys a finished DMA card and runs it without ever building firmware on their own PC will produce no DMA findings.
- **Input devices configured on a different PC.** XIM/Cronus/ReaSnow connected via pass-through, with all configuration software on a separate machine, leaves no trace on the scanned PC.
- **Brand-new cheats not yet in the keyword database.** The kit catches what it has been taught to catch. A cheat brand that emerged in the last few weeks may not be in the array yet. Check the [release notes](https://github.com/Sutaigne/alibi/releases) for the most recent keyword additions.
- **Customised / private cheats.** A one-off binary written by a friend, with no recognizable brand string, will not match any keyword. The kit relies on the fact that almost all commercial cheats have distinctive names.

## 6. Escalation

If something on the report does not add up — verdict disagreement, missing `Admin mode: True`, named items whose patterns aren't in the keyword arrays, or a hash that doesn't match `HASHES.txt` — your conclusion should be **"unable to verify,"** not **"cheating confirmed"** and not **"clean."** Ask for a re-run with admin elevation, screenshare-verified, against a fresh download of the kit from this repo.

A clean alibi report is a strong signal but it is not a proof. Treat it the way you'd treat any other forensic snapshot: necessary but not sufficient.

---

**Author:** Bread — Activision ID `Bread#3266221`, GitHub [@Sutaigne](https://github.com/Sutaigne). Contributor: Drownmw.

If you're a CoD-side reviewer and want one more identity anchor before trusting the kit: the author plays under the Activision ID above. You can verify that's a real, active player in-game. The point isn't that an Activision ID is a cryptographic proof of anything — it's that the kit's author has the same skin in the game as the people he's building it for.
