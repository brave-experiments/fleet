# Git execution policy: change roadmap

## Threat model

A compromised Fleet server (or a hijacked Fleet admin account, or an attacker who can reach Fleet's database) **must not** be able to cause arbitrary code to run on enrolled hosts. The only thing that should run is content committed to a pre-approved git repository under branch protection and signed-commit enforcement.

This document inventories every server-controlled execution path that orbit (or osquery, or the host MDM stack) currently respects, the current state of mitigation in this branch, and the work remaining to fully cover the threat model.

---

## Summary table

| # | Channel | Risk | Status | Side | Effort |
|---|---|---|---|---|---|
| 1 | Named scripts (`/orbit/scripts/request`) | Critical — direct shell exec as root | **Done** | Orbit (+ small Fleet server payload change) | — |
| 2 | osquery distributed queries | Critical — arbitrary SQL data exfil | **Done** | Orbit | — |
| 3 | Software installer scripts (install / post-install / uninstall) | Critical — same as #1 via different endpoint | **Done** | Orbit + small Fleet server payload change | — |
| 4 | Setup experience scripts (DEP / Linux setup) | High — root exec at enrollment | **Done** | Fleet server (SQL JOIN extension; orbit-side flow reused) | — |
| 5 | osquery extensions (`OrbitConfig.Extensions`) | High — native code in osquery process | **Done** | Orbit | — |
| 6 | Other osquery `command_line_startup_flags` | Medium — `--extensions_autoload`, `--config_path`, `--watcher`, etc. | **Done** | Orbit | — |
| 7 | TUF `UpdateChannels` (server-set) | Medium — channel pinning manipulation | **Done** | Orbit | — |
| 8 | Apple/Windows MDM commands | High — outside orbit, separate channel | **Out of scope for orbit** | Fleet server / device MDM stack | Large |
| 9 | Nudge configuration | Low — UI manipulation, no code exec | Acceptable | — | — |
| 10 | Setup-experience SSO browser open | Low — sandboxed web content | Acceptable | — | — |

---

## 1. Named scripts — DONE

**Server endpoint:** `POST /api/fleet/orbit/scripts/request`

**Threat:** server returns `{script_contents: "rm -rf /"}` and orbit runs it.

**Mitigation in this branch:**

- **Fleet server** returns `script_name` alongside `script_contents` so orbit can identify the script by a stable name. This is a tiny payload-surface change, not a logic change — the Fleet server already loads `scriptName` from the database (see `server/service/orbit.go:987-1003`), it just wasn't passing it back to orbit.
  - `server/fleet/scripts.go` — added `ScriptName string` field on `HostScriptResult` (4 LOC)
  - `server/datastore/mysql/scripts.go` — `LEFT JOIN scripts s ON ... s.name AS script_name` on the active and upcoming statements (~10 LOC)
- **Orbit** clones a configured git repository on startup, indexes `scripts/*.sh|.ps1|.py`, and looks each pending script up by name. Runs the git version, blocks if absent, blocks anonymous scripts.
  - `orbit/pkg/gitpolicy/gitpolicy.go` (new)
  - `orbit/pkg/scripts/scripts.go` — `PolicyEnforcer` interface + check in `runOne()`
  - `orbit/pkg/update/notifications.go` — wires enforcer into `Runner`
  - `orbit/cmd/orbit/orbit.go` — five new `--git-policy-*` flags
- **New exit code** `ExitCodePolicyBlocked = -4` reported back to Fleet on a block (`server/fleet/software_installer.go`)
- **Documentation:** `docs/Deploy/git-execution-policy.md`

**Remaining for this item:** unit tests for `gitpolicy` and `scripts.PolicyEnforcer` paths.

### Why a Fleet server change at all?

A pure-orbit approach is possible but has trade-offs:

- **Hash-based allowlist** (orbit hashes `script_contents` and looks up SHA256 in git): zero Fleet server diff, but lets an attacker swap one approved script for another at execution time. Admin clicks "run collect-logs", attacker substitutes "wipe-disk" content (also approved, different hash → different file in git → different behavior). Git is no longer the source of truth for *which script runs* — only for *what set of contents are runnable at all*.
- **Orbit fetches name out of band**: orbit could call a separate Fleet endpoint to look up a script's name by ID. Adds a round-trip and exposes the same data via a different API. Effectively the same change to Fleet's API surface, just split across two endpoints.
- **Surface name on the existing payload** (chosen): adds one column to the response. Smallest possible diff. Lets orbit make a single binding decision: "the server says scripts/request returned execution X for script Y; my git checkout says Y is `<contents>`; I run that or nothing."

The chosen approach treats the script *name* as the thing the admin meant to run, and treats the git repository as the canonical mapping from name → contents. That's what makes git the authoritative source rather than just an allowlist.

---

## 2. osquery distributed queries — DONE

**Server endpoint:** osqueryd talks directly to Fleet on `/api/v1/osquery/distributed/{read,write}` — orbit is not in the path.

**Threat:** server pushes arbitrary SQL via the live-query channel; the policy in (1) is bypassed entirely.

**Mitigation in this branch:**

- When `--git-policy-repo-url` is set, orbit forces `--disable_distributed=true` into the osquery flag file on every config refresh, regardless of what the Fleet server's agent options claim.
  - `orbit/pkg/update/flag_runner.go` — new `ForceDisableDistributed` option in `FlagUpdateOptions`; rewrites the map and writes the flag file even when the server sends no flags
  - `orbit/cmd/orbit/orbit.go` — sets `ForceDisableDistributed: policyEnforcer != nil`
  - Tests in `orbit/pkg/update/flag_runner_test.go`

**Trade-off documented:** policy automations and live queries that depend on distributed queries no longer work for hosts running with the policy active. Scheduled query packs (committed via GitOps) still work.

---

## 3. Software installer scripts — DONE

**Server endpoint:** `POST /api/fleet/orbit/software_install/details`

**Threat:** the response payload contains three server-supplied scripts that orbit runs as root/SYSTEM (`InstallScript`, `PostInstallScript`, `UninstallScript`). A compromised server can put arbitrary shell into any of these.

**Mitigation in this branch:**

- **Fleet server** now returns `software_title` on the install details payload, sourced via `LEFT JOIN software_titles st ON si.title_id = st.id`.
  - `server/fleet/software_installer.go` — `SoftwareTitle string` field on `SoftwareInstallDetails`
  - `server/datastore/mysql/software_installers.go` — JOIN extension on both branches of the UNION query
- **Orbit** resolves install/post-install/uninstall script content by software title against the git policy repository:
  - Path convention: `scripts/installers/<title>/{install,post-install,uninstall}.{sh,ps1}`
  - `orbit/pkg/installer/installer.go` — new `PolicyEnforcer` interface; `applyInstallerPolicy()` rewrites the three scripts in place or sets `ExitCodePolicyBlocked`
  - `orbit/pkg/gitpolicy/gitpolicy.go` — extended with `GetApprovedInstallerScript(title, kind)` and an `installerScripts` index
- **Block conditions** (any one of these returns `ExitCodePolicyBlocked` and aborts the install):
  - `software_title` is empty in the server payload
  - title not present under `scripts/installers/`
  - server sent a post-install or uninstall script but git has none for that title (partial coverage is unsafe)

**Out of scope:** the installer **binary** itself is still served from Fleet's CDN. A compromised server could ship a malicious .pkg/.msi/.deb. To close this gap, future work could add `scripts/installers/<title>/installer.sha256` and verify after download.

---

## 4. Setup experience scripts — DONE

**Server endpoint:** `POST /api/fleet/orbit/scripts/request` (setup-experience scripts reuse the same endpoint as regular scripts, distinguished by `setup_experience_script_id` instead of `script_id`).

**Threat:** root exec at enrollment time, before any user is logged in. Same compromise vector as #1 via a different SQL row.

**Mitigation in this branch:**

- **Fleet server** SQL (`server/datastore/mysql/scripts.go`) now resolves `script_name` from either the regular `scripts` table or the `setup_experience_scripts` table via `COALESCE(s.name, ses.name, '')` and a second `LEFT JOIN`. With the name surfaced, the existing orbit-side script policy enforcer (#1) handles setup-experience executions identically — no orbit-side changes needed.
- Setup-experience scripts must therefore be committed to the same `scripts/` directory as regular scripts. The filename in the policy repository must match the name in `setup_experience_scripts.name`.

---

## 5. osquery extensions — DONE

**Server-controlled field:** `OrbitConfig.Extensions` — server lists extensions to load with per-extension platform and channel.

**Threat:** osquery extensions are arbitrary native binaries loaded into the osquery process. The TUF signing requirement limits the blast radius (a binary must be TUF-signed) but a compromised server can still pick which TUF-signed extensions to load on which hosts.

**Mitigation in this branch:**

- **Orbit** reads `extensions.allowlist` (one extension name per line, `#` comments allowed) from the policy repository root.
  - `orbit/pkg/gitpolicy/gitpolicy.go` — new `AllowedExtensions()` accessor; allowlist re-loaded on every git sync
  - `orbit/pkg/update/flag_runner.go` — `ExtensionRunner.Run` consults the callback; extensions not in the set are dropped before any TUF metadata fetch or `extensions.load` write
- A missing `extensions.allowlist` file is treated as an empty (non-nil) set — i.e. **no extensions allowed**. This is the safe default if the file is forgotten when migrating to the policy.

---

## 6. Other osquery startup flags — DONE

**Server-controlled field:** `OrbitConfig.Flags` (the same `command_line_startup_flags` we partially handled in #2).

**Threat:** osquery has many flags that change its execution behavior. Particularly dangerous if attacker-controlled:

- `--extensions_autoload`, `--extensions_default_index` — bypass the extensions allowlist (#5)
- `--config_path`, `--config_plugin` — re-read config from an attacker-controlled path
- `--watcher_*`, `--disable_watchdog` — disable osquery's process watchdog
- `--audit_*`, `--disable_audit` — turn off audit logging
- `--logger_path` — redirect logs to attacker-controlled paths
- `--enable_extensions_watchdog` — toggle extension behavior

**Mitigation in this branch:**

- **Orbit** maintains a denylist of dangerous prefixes in `orbit/pkg/update/flag_runner.go` (`dangerousFlagPrefixes`). When the policy is active (`PolicyActive: true`), each flag the server sent is checked via `isDangerousFlag()`; matches are dropped with a warning log before the flag file is written.
- Same `PolicyActive` knob also enforces `--disable_distributed=true` (item #2). Both behaviors are tied to the umbrella signal `policyEnforcer != nil` in `orbit.go`.

---

## 7. TUF update channels — DONE

**Server-controlled field:** `OrbitConfig.UpdateChannels` — server tells orbit which TUF channel to use for orbit/osqueryd/desktop binaries.

**Threat:** server flips a host to a malicious-but-TUF-signed channel, or pins to an old/vulnerable channel.

**Mitigation in this branch:**

- **Orbit's** `serverOverridesRunner` (`orbit/cmd/orbit/orbit.go`) gains a `policyActive` flag. When set, `Run()` returns early before any channel comparison, leaving update channels at their compile-time defaults (typically `stable`).
- A compromised server cannot influence channel selection while the policy is in effect.

---

## 8. MDM commands — out of scope for orbit

**Channels:**

- Apple MDM: `mdmcheckin`, command channel, DDM declarations, custom `ShellScript` commands
- Windows MDM (Syncml)
- Linux LUKS / Bitlocker

These flow directly between the host MDM stack and the Fleet server — **orbit is not in the path**. A compromised Fleet server can:

- Send `InstallApplication` for an arbitrary .pkg/.msi
- Send Apple `ShellScript` MDM command (yes, MDM has its own script execution channel separate from orbit)
- Push DDM declarations that include policy-enforced scripts
- Modify configuration profiles (DNS, proxy, certificates) to route traffic through attacker infrastructure

**Why orbit cannot mitigate this:** the host MDM client is part of the OS, not part of orbit. There is no orbit hook in the path.

**Possible mitigations (none in scope of this fork):**

1. **Don't enroll hosts in MDM** for the high-security segment. The git policy alone covers script execution; if you skip MDM, you skip this entire attack surface.
2. **Server-side approval gate**: modify the Fleet server so MDM commands cannot be issued without a corresponding signed git commit. This requires substantial Fleet server changes and key management infrastructure.
3. **Pin MDM SCEP/CA**: use a custom MDM CA that orbit (or a separate enrollment step) verifies before accepting MDM commands. Requires Apple MDM protocol expertise.

**Recommendation:** treat this as a known residual risk. Document which hosts are MDM-enrolled vs script-only, and apply the git policy on top of an MDM deployment that you already trust the server-administrator boundary on. The git policy reduces blast radius from "compromise = code on every host" to "compromise = MDM-only attacks on MDM-enrolled hosts", which is meaningful even without solving (8).

---

## 9. Nudge configuration — acceptable

`OrbitConfig.NudgeConfig` controls macOS update prompts. Server can set deadlines, messages, button labels. Worst case: social engineering via Nudge dialog. No code execution. Acceptable residual risk.

## 10. Setup-experience SSO browser open — acceptable

`orbit/cmd/orbit/orbit.go:1181` opens a browser to `<fleet-url>/mdm/sso?...`. Server controls what HTML is served. Browser sandbox limits this to traditional web vulnerabilities (phishing, XSS), not host code execution. Acceptable.

---

## Implementation status

Items 1–7 are now complete in this branch. Orbit has full coverage of every code-delivery path it controls. Item 8 (MDM) requires a separate workstream and is out of scope for orbit-side changes.

---

## Per-side change summary

### Fleet server changes

| File | Item | Purpose |
|---|---|---|
| `server/fleet/scripts.go` | #1 | Add `ScriptName` field to `HostScriptResult` |
| `server/datastore/mysql/scripts.go` | #1, #4 | `LEFT JOIN scripts` and `setup_experience_scripts` to populate name (`COALESCE(s.name, ses.name, '')`) |
| `server/fleet/software_installer.go` | #1, #3 | Add `ExitCodePolicyBlocked = -4`, output copy, and `SoftwareTitle` field on `SoftwareInstallDetails` |
| `server/datastore/mysql/software_installers.go` | #3 | `LEFT JOIN software_titles` to populate `software_title` on both UNION branches |

The Fleet server changes are deliberately small and additive — they only **expose more identity information** on payloads orbit already receives. They do not change auth, RBAC, or any existing code path. This makes them suitable for upstream submission without a security review of new server-side logic.

### Orbit changes

| File | Item | Purpose |
|---|---|---|
| `orbit/pkg/gitpolicy/gitpolicy.go` | #1, #3, #5 | Git clone/index for scripts, installer scripts, and extension allowlist |
| `orbit/pkg/gitpolicy/gitpolicy_test.go` | #1, #3, #5 | Indexing unit tests |
| `orbit/pkg/scripts/scripts.go` | #1, #4 | Block named-script execution (regular + setup-experience) if not in git |
| `orbit/pkg/update/notifications.go` | #1 | Wire enforcer into the script runner |
| `orbit/pkg/update/flag_runner.go` | #2, #5, #6 | Force `disable_distributed=true`; drop dangerous flag denylist; filter extensions by allowlist |
| `orbit/pkg/update/flag_runner_test.go` | #2, #6 | Unit tests for forced `disable_distributed` and dangerous-flag drop |
| `orbit/pkg/installer/installer.go` | #3 | `PolicyEnforcer` interface; replace install / post-install / uninstall scripts with git versions or block |
| `orbit/pkg/installer/installer_test.go` | #3 | Unit tests for `applyInstallerPolicy()` |
| `orbit/cmd/orbit/orbit.go` | #1, #2, #5, #6, #7 | New CLI flags; wire `policyEnforcer` into flag runner, extension runner, installer runner, and server-overrides runner |

### Documentation

| File | Status |
|---|---|
| `docs/Deploy/git-execution-policy.md` | User-facing; updated to cover items #1–#7 |
| `docs/Deploy/git-execution-policy-roadmap.md` | This file; design rationale and remaining MDM gap |

---

## Upstream merge considerations

The Fleet team will likely have feedback on a few axes. Anticipated questions and recommended answers:

- **Why not server-side?** The Fleet server is the entity in the threat model. Mitigations must live outside its trust boundary.
- **Why not the existing GitOps machinery?** GitOps configures *what Fleet stores*, not *what orbit will accept from Fleet*. The git policy adds a second, host-side enforcement layer.
- **Won't this break the live query / scripts UI?** Yes, by design. The UI continues to function — admins can still attempt to run things — but enforcement now happens on the host. Document this prominently as the trade-off the feature requires.
- **Will this add a hard `git` dependency to orbit?** Only when the policy flag is set. We use the system `git` binary via `exec.CommandContext` to avoid pulling in a Go git library and to leverage existing credential helpers / SSH config on the host.
- **Why force `disable_distributed` instead of letting admins set it?** Because the feature is meaningless if a compromised server can re-enable distributed queries — that defeats the entire policy.

A clean upstream submission should split into independently-reviewable PRs:

1. **PR 1 (server, small):** expose `ScriptName` on `HostScriptResult` (#1, #4). Useful on its own for Fleet UI/audit-log purposes; the SQL join also covers setup-experience scripts. Does not depend on any orbit change.
2. **PR 2 (server, small):** expose `SoftwareTitle` on `SoftwareInstallDetails` (#3). Same shape as PR 1: a column added to the response, populated via JOIN.
3. **PR 3 (orbit, medium):** `gitpolicy` package + scripts/installer/extensions enforcement + new CLI flags. The umbrella PR that turns the server-side data into actual policy enforcement. Includes the `PolicyActive` knob in the flag runner (covers #2, #6) and the early-return in `serverOverridesRunner` (#7).
4. **PR 4 (docs):** the user-facing `git-execution-policy.md` with operator instructions.

PRs 1 and 2 are zero-impact for any operator who isn't using the policy: the new fields are simply unused by stock orbit. PR 3 gates all behavior changes on the new `--git-policy-repo-url` flag — when unset, orbit's behavior is byte-identical to today.
