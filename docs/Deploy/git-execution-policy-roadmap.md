# Git execution policy: change roadmap

## Threat model

A compromised Fleet server (or a hijacked Fleet admin account, or an attacker who can reach Fleet's database) **must not** be able to cause arbitrary code to run on enrolled hosts. The only thing that should run is content committed to a pre-approved git repository under branch protection and signed-commit enforcement.

This document inventories every server-controlled execution path that orbit (or osquery, or the host MDM stack) currently respects, the current state of mitigation in this branch, and the work remaining to fully cover the threat model.

---

## Summary table

| # | Channel | Risk | Status | Side | Effort |
|---|---|---|---|---|---|
| 1 | Named scripts (`/orbit/scripts/request`) | Critical — direct shell exec as root | **Done** in this branch | Orbit + Fleet server | — |
| 2 | osquery distributed queries | Critical — arbitrary SQL data exfil | **Done** in this branch | Orbit | — |
| 3 | Software installer scripts (install / post-install / uninstall) | Critical — same as #1 via different endpoint | **TODO** | Orbit + Fleet server | Medium |
| 4 | Setup experience scripts (DEP / Linux setup) | High — root exec at enrollment | **TODO** | Orbit + Fleet server | Small |
| 5 | osquery extensions (`OrbitConfig.Extensions`) | High — native code in osquery process | **TODO** | Orbit | Small |
| 6 | Other osquery `command_line_startup_flags` | Medium — `--extensions_autoload`, `--config_path`, `--watcher`, etc. | **TODO** | Orbit | Small |
| 7 | TUF `UpdateChannels` (server-set) | Medium — channel pinning manipulation | **TODO** | Orbit | Small |
| 8 | Apple/Windows MDM commands | High — outside orbit, separate channel | **Out of scope for orbit** | Fleet server / device MDM stack | Large |
| 9 | Nudge configuration | Low — UI manipulation, no code exec | Acceptable | — | — |
| 10 | Setup-experience SSO browser open | Low — sandboxed web content | Acceptable | — | — |

---

## 1. Named scripts — DONE

**Server endpoint:** `POST /api/fleet/orbit/scripts/request`

**Threat:** server returns `{script_contents: "rm -rf /"}` and orbit runs it.

**Mitigation in this branch:**

- **Fleet server** now returns `script_name` alongside `script_contents` so orbit can identify the script by a stable name.
  - `server/fleet/scripts.go` — added `ScriptName string` field on `HostScriptResult`
  - `server/datastore/mysql/scripts.go` — `LEFT JOIN scripts s ON ... s.name AS script_name` on `getActiveStmt` and `getUpcomingStmt`
- **Orbit** clones a configured git repository on startup, indexes `scripts/*.sh|.ps1|.py`, and looks each pending script up by name. Runs the git version, blocks if absent, blocks anonymous scripts.
  - `orbit/pkg/gitpolicy/gitpolicy.go` (new)
  - `orbit/pkg/scripts/scripts.go` — `PolicyEnforcer` interface + check in `runOne()`
  - `orbit/pkg/update/notifications.go` — wires enforcer into `Runner`
  - `orbit/cmd/orbit/orbit.go` — five new `--git-policy-*` flags
- **New exit code** `ExitCodePolicyBlocked = -4` reported back to Fleet on a block (`server/fleet/software_installer.go`)
- **Documentation:** `docs/Deploy/git-execution-policy.md`

**Remaining for this item:** unit tests for `gitpolicy` and `scripts.PolicyEnforcer` paths.

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

## 3. Software installer scripts — TODO

**Server endpoint:** `POST /api/fleet/orbit/software/install/{install_uuid}`

**Threat:** the response payload contains three server-supplied scripts that orbit runs as root/SYSTEM:

- `InstallScript`
- `PostInstallScript`
- `UninstallScript`

A compromised server can put arbitrary shell into any of these and orbit will execute it. **This is the single largest remaining gap** — the server simply marks malicious code as a "software install" instead of a "script run" and gets the same code execution.

**Required Fleet server changes:**

- Surface a stable identity for each installer script. Software titles in Fleet have IDs and titles already; the cleanest approach is to expose `software_title` (or the existing software installer record name) on the install payload so orbit can look it up in git.
- Endpoint: probably `server/service/orbit_software_install.go` or similar (verify location).

**Required orbit changes:**

- Restore the `PolicyEnforcer` plumbing in `orbit/pkg/installer/installer.go` (was reverted earlier in this branch's history).
- Look up each of the three scripts in git by a deterministic naming convention. Recommended:
  ```
  scripts/installers/<title>/install.sh
  scripts/installers/<title>/post-install.sh
  scripts/installers/<title>/uninstall.sh
  ```
- If any script is referenced in the server payload but missing from git, refuse the install and report `ExitCodePolicyBlocked`. If the server sends content but git has none for that title, block.

**Out of scope but worth noting:** the installer **binary** itself is also delivered via Fleet's CDN/storage. A compromised server could ship a malicious .pkg/.msi/.deb. Mitigation options:
- Pin SHA256 of approved installers in the git repo (`scripts/installers/<title>/installer.sha256`).
- Verify after download, before running install.sh.

**Effort:** medium. Around 200-300 lines of orbit changes plus Fleet-side endpoint surfacing the title. Tests for both sides.

---

## 4. Setup experience scripts — TODO

**Server endpoint:** `POST /api/fleet/orbit/setup_experience/status` (macOS DEP, Linux setup) returns scripts to run as part of host onboarding.

**Threat:** root exec at enrollment time, before any user is logged in. Same compromise vector as #3.

**Required Fleet server changes:**

- Same as #3: expose a stable name for each setup-experience step so orbit can resolve it in git.

**Required orbit changes:**

- `orbit/pkg/setup_experience/setup_experience.go` — currently runs `payload.Script` content directly. Add the same `PolicyEnforcer` check before execution.
- Naming convention: `scripts/setup-experience/<step-name>.sh`.

**Alternative simpler mitigation:** when the policy is active, **always** block setup-experience scripts — these are typically rare and can be replicated by a normal post-enrollment scheduled script. This avoids the need to surface a name from the server side and trades a minor feature loss for a smaller diff.

**Effort:** small (1–2 hours) if we use the simpler "always block" path; small-medium if we keep parity with #3.

---

## 5. osquery extensions — TODO

**Server-controlled field:** `OrbitConfig.Extensions` (`json.RawMessage`) — server sends a JSON object naming extensions to load, with per-extension `platform` and `channel`.

**Threat:** osquery extensions are arbitrary native binaries (`.ext` / `.ext.exe`) loaded into the osquery process. They can register tables that execute code, run subprocesses, exfiltrate, etc.

**Already partially mitigated:** extensions are downloaded from the TUF metadata server and the binary is signature-verified. **But** the *list of which extensions to load* is server-controlled, and the `channel` field is server-controlled. A compromised server can:
- Switch any host to a malicious-but-TUF-signed extension (if such a thing exists in your TUF repo).
- Pin a host to an old extension channel with a known vulnerability.

**Required orbit changes:**

- When `--git-policy-repo-url` is set, read `extensions.allowlist` from the policy repo (a YAML/JSON list of allowed extension names and pinned channels).
- In `orbit/pkg/update/flag_runner.go` (`ExtensionRunner.Run`): filter the server's `Extensions` map to only entries in the allowlist; ignore the server-supplied `channel` and use the channel from git.
- If the allowlist is empty or absent, refuse to load any extensions.

**Effort:** small. ~100 LOC + tests.

---

## 6. Other osquery startup flags — TODO

**Server-controlled field:** `OrbitConfig.Flags` (the same `command_line_startup_flags` we already partially handle).

**Threat:** osquery has many flags that change its execution behavior. Particularly dangerous if attacker-controlled:

- `--extensions_autoload=<file>` — points osquery at an arbitrary file listing extensions to load (bypasses #5)
- `--extensions_default_index=false` + path manipulation — similar bypass
- `--config_path=<file>` — read config from a different file (could re-enable distributed)
- `--watcher_*` — disable osquery watchdog
- `--audit_*` — turn off audit logging
- `--logger_path=<file>` — redirect logs (impedes detection)
- Anything starting with `--enable_` / `--disable_` — toggling features off

Fleet's server-side validation (`server/fleet/agent_options.go:88-95`) blocks `--host_identifier` and `--extensions_autoload`, but a *compromised* server bypasses its own validator.

**Required orbit changes:**

- When the policy is active, apply an orbit-side **allowlist** of safe flag prefixes/names. Anything not on the list is silently dropped before being written to `osquery.flags`.
- Place the allowlist in `orbit/pkg/update/flag_runner.go` next to the existing `getFlagsFromJSON` logic.

**Effort:** small. ~50 LOC + a test that asserts dangerous flags are dropped.

---

## 7. TUF update channels — TODO

**Server-controlled field:** `OrbitConfig.UpdateChannels` (server tells orbit which TUF channel to use for orbit/osqueryd/desktop binaries).

**Threat:** server flips a host to a malicious-but-TUF-signed channel. TUF signing limits the blast radius — the attacker has to publish a malicious binary through the TUF infrastructure, which is signed separately. But the server can at minimum pin hosts to old/vulnerable channel versions.

**Required orbit changes:**

- When the policy is active, ignore server-sent `UpdateChannels` and use either compile-time defaults or values from a `update-channels.yaml` in the policy repo.
- Implementation: gate the existing channel-application logic in `orbit/pkg/update/` on `policyEnforcer == nil`.

**Effort:** small. ~30 LOC + test.

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

## Recommended implementation order

1. **#3 Software installer scripts** — biggest remaining hole, well-understood, parallel to #1
2. **#4 Setup experience** — small effort, finishes orbit-mediated script paths
3. **#6 Osquery flag allowlist** — small but closes the `--extensions_autoload` bypass that would otherwise defeat #5
4. **#5 Extensions allowlist** — depends on #6 to be airtight
5. **#7 Update channel override** — smallest, lowest priority

After items 1–5 are complete, orbit has full coverage of every code-delivery path it controls. Item 8 (MDM) requires a separate workstream.

---

## Per-side change summary

### Fleet server changes (so far + planned)

| File | Status | Purpose |
|---|---|---|
| `server/fleet/scripts.go` | Done | Add `ScriptName` to `HostScriptResult` |
| `server/datastore/mysql/scripts.go` | Done | `LEFT JOIN scripts` to populate name |
| `server/fleet/software_installer.go` | Done | Add `ExitCodePolicyBlocked = -4` |
| `server/service/orbit_software_install.go` (or wherever installer payloads are built) | TODO #3 | Surface software title on install payload |
| `server/service/orbit_setup_experience.go` (or wherever) | TODO #4 | Surface step name on setup-experience payload |

The Fleet server changes are deliberately small and additive — they only **expose more identity information** on payloads orbit already receives. They do not change auth, RBAC, or any existing code path. This makes them suitable for upstream submission without a security review of new server-side logic.

### Orbit changes (so far + planned)

| File | Status | Purpose |
|---|---|---|
| `orbit/pkg/gitpolicy/gitpolicy.go` | Done | Git clone/index of approved scripts |
| `orbit/pkg/scripts/scripts.go` | Done | Block named-script execution if not in git |
| `orbit/pkg/update/notifications.go` | Done | Wire enforcer into the script runner |
| `orbit/pkg/update/flag_runner.go` | Done | Force `disable_distributed=true` |
| `orbit/cmd/orbit/orbit.go` | Done | New CLI flags |
| `orbit/pkg/installer/installer.go` | TODO #3 | Block installer scripts not in git |
| `orbit/pkg/setup_experience/setup_experience.go` | TODO #4 | Block setup-experience scripts not in git |
| `orbit/pkg/update/flag_runner.go` (extensions section) | TODO #5 | Allowlist osquery extensions |
| `orbit/pkg/update/flag_runner.go` (flag map section) | TODO #6 | Drop dangerous startup flags |
| `orbit/pkg/update/` (channels) | TODO #7 | Ignore server-set update channels |

### Documentation

| File | Status |
|---|---|
| `docs/Deploy/git-execution-policy.md` | Done — covers #1, #2 |
| `docs/Deploy/git-execution-policy.md` | TODO — extend for #3-#7 once implemented |

---

## Upstream merge considerations

The Fleet team will likely have feedback on a few axes. Anticipated questions and recommended answers:

- **Why not server-side?** The Fleet server is the entity in the threat model. Mitigations must live outside its trust boundary.
- **Why not the existing GitOps machinery?** GitOps configures *what Fleet stores*, not *what orbit will accept from Fleet*. The git policy adds a second, host-side enforcement layer.
- **Won't this break the live query / scripts UI?** Yes, by design. The UI continues to function — admins can still attempt to run things — but enforcement now happens on the host. Document this prominently as the trade-off the feature requires.
- **Will this add a hard `git` dependency to orbit?** Only when the policy flag is set. We use the system `git` binary via `exec.CommandContext` to avoid pulling in a Go git library and to leverage existing credential helpers / SSH config on the host.
- **Why force `disable_distributed` instead of letting admins set it?** Because the feature is meaningless if a compromised server can re-enable distributed queries — that defeats the entire policy.

A clean PR for upstream should probably split into:

1. **PR 1 (small, low-risk):** Fleet server change to expose `ScriptName` on `HostScriptResult`. Useful on its own for Fleet UI/audit-log purposes; doesn't depend on the rest.
2. **PR 2 (medium):** orbit-side `gitpolicy` package + script policy enforcer + CLI flags + `disable_distributed` enforcement.
3. **PR 3+:** items 3–7 as separate PRs each, since each is small and independently reviewable.

This staging makes the security argument easier to evaluate at each step and reduces the risk that the whole thing stalls in review.
