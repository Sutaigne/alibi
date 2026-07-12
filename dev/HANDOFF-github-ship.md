# Handoff — ship alibi v4.3.0 to GitHub

*Written 2026-07-12 on GAMING-BREAD, end of the v4.3 verification session.
Read this first, then `dev/release-plan-v4.3.md` (the live-repo audit, ship
steps, drafted release notes, and About-sidebar copy). Everything below is
already done and verified — the ONLY remaining work is GitHub-side.*

## State of this tree (all verified, nothing pending locally)

- **Repo:** `C:\Users\brads\Downloads\alibi-main\alibi-main`, branch `main`,
  8 commits, annotated tag `v4.3.0` at tip. No remote configured yet.
- **Engine:** the five v4.3 P0 false-positive fixes, applied and live-tested
  twice on this machine (elevated, with this repo deliberately sitting in
  Downloads — the exact self-flagging FP scenario): 0 cheat HIGHs, 0 input
  HIGHs, 1 legitimate MEDIUM (unsigned Realtek driver). Reports stamp v4.3.0.
- **Tests:** `alibi-engine/tests/p0-regression.Tests.ps1` — 14/14, native
  Windows PowerShell 5.1. CI (`.github/workflows/ci.yml`) runs parse-check +
  this suite; both must go green on push.
- **AV posture:** Defender-clean on the full tree, `dev\` alone, the built
  release zip, and a GitHub-source-style zip — including with Mark-of-the-Web
  stamped. The June 25 flag on the source-zip download was
  `Trojan:Win32/Sprisky.U!cl` (cloud heuristic); current defs don't match.
  SECURITY.md documents both observed detections + the Microsoft
  false-positive submission path.
- **Release artifact:** `dist\alibi.zip` (gitignored, built by
  `dev/scripts/build-release.ps1`), SHA256
  `2c825335a1c7a7bba1e144d773f4656b32f45ac66708cc6c21580633f062e822`.
  Rebuild + re-hash if any shipped file changes after this handoff.
- **Docs/copy:** README + START HERE humanized; one-page guide says
  right-click → Run as administrator; trust claims de-rotted (no hardcoded
  line numbers); HASHES.txt correct (it was wrong for 12/26 files in every
  previously shipped kit — line-ending mismatch, root-caused and fixed).

## The task: ship it (steps in `dev/release-plan-v4.3.md`)

Prereq Brad is doing between sessions: installing GitHub access (`gh` CLI
and/or git remote credentials).

1. `git remote add origin https://github.com/Sutaigne/alibi.git ; git fetch origin`
2. **History decision (the one judgment call):** local history was rebuilt
   from a zip, so it is unrelated to the remote's 46 commits. Check:
   `git diff origin/main 832da41 --stat` (baseline commit vs remote tip).
   - Empty diff → `git rebase origin/main` onto the 7 post-baseline commits
     (or cherry-pick `832da41..main` onto `origin/main`), preserving remote
     history. The baseline commit itself becomes redundant and drops out.
   - Non-empty → push `main` as branch `v4.3-p0`, open a PR, reconcile there.
   - **Do NOT force-push over origin/main.**
3. Push `main` + tag: `git push origin main --follow-tags`. Wait for CI green.
   NOTE: if step 2 rewrote commits, re-point the tag at the new tip first
   (`git tag -f -a v4.3.0 -m "<same message>"`).
4. Create the GitHub release from tag `v4.3.0`: title + body are drafted in
   `dev/release-plan-v4.3.md`. Attach `dist\alibi.zip` **and** `HASHES.txt`
   (same asset pattern as every prior release; keeps
   `releases/latest/download/alibi.zip` working). If commits were rewritten
   in step 2, rebuild `dist\alibi.zip` first and update the SHA in the notes.
5. GitHub Settings → About sidebar: paste the new description from the plan
   doc, remove the `python` topic. Website field stays
   `sutaigne.github.io/alibi/`.
6. Post-release verification: fresh-download `alibi.zip` AND the source zip
   from github.com with Defender active. Cloud verdicts (`!cl`/`!ml`) can
   only be tested on the real download. If flagged → submit at
   https://www.microsoft.com/en-us/wdsi/filesubmission (per SECURITY.md).
7. Later (not blocking): re-shoot `docs/screenshots/*.png` from real v4.3
   HTML; regenerate the Pages examples with the PowerShell renderer (the
   hosted ones are Python-rendered from the pre-split era).

## Gotchas that bit this session (don't rediscover these)

- **PowerShell 5.1 mangles `git commit -m` messages containing double
  quotes** (they terminate the argument; git then errors with "pathspec").
  Write the message to a temp file and use `git commit -F <file>`.
- **HASHES.txt ritual:** any change to a shipped file requires regenerating
  HASHES.txt (loop over its entries with `Get-FileHash`, lowercase hex,
  keep the `<sha256> *<relative-path>` format) AND rebuilding `dist\alibi.zip`.
  Hashes are line-ending sensitive; the working tree's endings already match
  the `.gitattributes` export rules (verified byte-level) — don't "fix"
  endings.
- **The tag has been force-moved several times locally.** Fine (never
  pushed), but after it's on GitHub, never move it again — cut v4.3.1.
- **`Run scan.bat` needs a real elevated console** (right-click → Run as
  administrator). For agent-driven verification, run the two scanner .ps1
  directly with `-SkipLOLDrivers -SkipBrowserOpen` from an elevated
  PowerShell (Start-Process -Verb RunAs pops UAC for Brad to approve);
  reports land on the Desktop, machine-readable summaries in
  `%TEMP%\alibi-pc.summary` / `alibi-console.summary`.
- **file:// URLs don't open in the Code browser pane** — serve locally
  (`python -m http.server`) to eyeball HTML.

## After shipping

v5 runway is in `alibi-engine/docs/PROPOSAL-v5.md`. Top carry-overs:
content-sentinel self-immunity (path-shape matching is rename-defeatable),
Authenticode revocation-call pinning, collectors/rules/verdict refactor.
