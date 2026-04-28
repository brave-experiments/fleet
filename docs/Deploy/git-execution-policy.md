# Git-backed script execution policy

This document describes how to configure Fleet's git execution policy — a hardening feature that prevents a compromised Fleet server from running arbitrary scripts on enrolled hosts. When enabled, **orbit only executes scripts whose content is committed to a pre-configured git repository**, and always runs the version from git rather than the version the server sends.

## Background and threat model

Fleet's normal execution model trusts the server: when an administrator triggers a script run, Fleet sends the script content to the host and orbit executes it. This is convenient but creates a risk: if the Fleet server is compromised, an attacker can craft and dispatch arbitrary shell commands to every enrolled host.

The git execution policy addresses this by making the git repository — not the Fleet server — the authoritative source of script content. The server can still *trigger* a script run by name, but orbit independently resolves that name to the content in git and runs that. Whatever the server claims the script says is ignored.

The threat model this covers:

- A compromised Fleet server sending arbitrary script content
- An administrator account being hijacked and used to create and run malicious scripts
- Supply-chain attacks that modify scripts stored in Fleet's database

The threat model this does **not** cover on its own (see [Additional hardening](#additional-hardening)):

- Arbitrary **osquery distributed queries** sent by the server (data-exfiltration risk)
- Software installer scripts (a separate execution path not yet covered by this policy)

## How it works

When `--git-policy-repo-url` is set, orbit does the following on startup and then periodically:

1. Clones (or pulls) the configured git repository to a local directory on the host.
2. Walks the `scripts/` subdirectory (configurable) and indexes every `.sh`, `.ps1`, and `.py` file by its basename.

When the Fleet server sends a pending script execution:

1. Orbit fetches the execution details from Fleet, which includes the **script name** (e.g. `collect-logs.sh`).
2. Orbit looks up that name in its local git index.
3. If found: orbit executes the content **from git** — the server-provided content is discarded entirely.
4. If not found: orbit reports the execution as blocked (exit code `-4`) back to Fleet without running anything.
5. If the script has no name (an ad-hoc / anonymous run): orbit always blocks it.

Because the git repository is the source of truth, commit signing and branch protection rules on the repository are the actual access control boundary. A compromised Fleet server can name a script to run, but cannot change what that script does.

## Requirements

- `git` must be installed on enrolled hosts (available by default on macOS; must be installed separately on Windows and Linux).
- The policy git repository must be reachable from hosts at the configured URL.
- For strong security guarantees, the repository must have:
  - **Branch protection** on the tracked branch (no force-pushes, required PR reviews).
  - **Commit signing** enforced (e.g. GitHub's "Require signed commits" branch protection rule), so every commit can be attributed to an authenticated identity.

## Configuration

Set the following flags when deploying orbit (via `fleetctl package` or your MDM enrollment profile). Each flag also has a corresponding environment variable.

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--git-policy-repo-url` | `ORBIT_GIT_POLICY_REPO_URL` | *(unset — feature disabled)* | URL of the git repository. HTTPS and SSH are both supported. When unset, no policy is enforced. |
| `--git-policy-repo-branch` | `ORBIT_GIT_POLICY_REPO_BRANCH` | `main` | Branch to track. |
| `--git-policy-repo-dir` | `ORBIT_GIT_POLICY_REPO_DIR` | `<root-dir>/git-policy` | Local path where the repository is cloned on the host. Must be writable by orbit (root/SYSTEM). |
| `--git-policy-scripts-dir` | `ORBIT_GIT_POLICY_SCRIPTS_DIR` | `scripts` | Subdirectory within the repository that contains approved script files. |
| `--git-policy-sync-interval` | `ORBIT_GIT_POLICY_SYNC_INTERVAL` | `5m` | How often orbit re-syncs from the remote. The initial sync on startup is synchronous — if it fails, orbit refuses to start. Subsequent failures retain the last good index and log a warning. |

### Example

```sh
fleetctl package \
  --type=pkg \
  --fleet-url=https://fleet.example.com \
  --enroll-secret=... \
  --enable-scripts \
  --orbit-flag="--git-policy-repo-url=https://github.com/example-org/fleet-gitops" \
  --orbit-flag="--git-policy-repo-branch=main" \
  --orbit-flag="--git-policy-scripts-dir=scripts"
```

If the repository requires authentication (private repo), configure git credential storage on the host before deploying, or use an SSH URL with a read-only deploy key:

```sh
  --orbit-flag="--git-policy-repo-url=git@github.com:example-org/fleet-gitops.git"
```

## Repository structure

The policy repository can be your existing Fleet GitOps repository or a dedicated one. The only requirement is a directory of approved scripts:

```
fleet-gitops/
├── fleet.yml               # existing GitOps config
├── scripts/                # approved scripts (name must match what's in Fleet)
│   ├── collect-logs.sh
│   ├── remediate-defender.ps1
│   └── check-compliance.py
└── ...
```

Script filenames in this directory must exactly match the script names registered in Fleet (the filename used when the script was uploaded via GitOps or the UI). Orbit matches by basename only — subdirectory structure within `scripts/` is ignored during lookup.

### Adding or updating a script

1. Add or edit the file in `scripts/` on a feature branch.
2. Open a pull request. Reviewers approve and the commit is signed.
3. Merge to the tracked branch.
4. Within one sync interval (default 5 minutes), orbit picks up the change.

### Removing a script

Delete the file from `scripts/` via a signed, reviewed commit. From that point on, any Fleet-triggered execution of that script name will be blocked on all hosts that have synced.

## Behavior reference

| Situation | Orbit action |
|-----------|-------------|
| Script name found in git | Execute the **git version** of the script, regardless of content Fleet sent |
| Script name not found in git | Report blocked (exit `-4`, message shown in Fleet UI) |
| Script has no name (ad-hoc run) | Always blocked |
| Initial git sync fails on startup | Orbit refuses to start |
| Periodic sync fails | Retain last good index; log a warning; continue blocking unapproved scripts |
| `--git-policy-repo-url` not set | No policy enforced; normal Fleet behavior |

## Additional hardening

The git execution policy covers **named script execution** only. The following additional measures are needed for a fully hardened deployment.

### Disable osquery distributed queries

Fleet's live query feature (and policy evaluation) works through osquery's [distributed query protocol](https://osquery.readthedocs.io/en/stable/development/osquery-distributed/). This channel operates directly between osqueryd and the Fleet server — orbit is not in the path and cannot gate it. A compromised server could use distributed queries to exfiltrate arbitrary data from hosts even if the git script policy is fully enforced.

To close this channel, disable distributed queries in your Fleet agent options and rely solely on scheduled query packs managed through GitOps:

```yaml
# fleet.yml (or the relevant team config)
agent_options:
  config:
    options:
      disable_distributed: true
```

**Trade-off:** Disabling distributed queries turns off the Fleet live query UI and policy automations that rely on distributed queries. Scheduled packs (committed to the GitOps repo) continue to work. Evaluate whether this trade-off is acceptable for your environment; high-security segments of your fleet (servers, privileged workstations) are the primary candidates.

### Restrict which scripts are uploaded to Fleet

Even with the git policy active, the Fleet UI and API allow administrators to upload new named scripts. An attacker with admin access could upload `collect-logs.sh` with malicious content — orbit would block it because it runs the git version, not the server version, but the script would still appear in Fleet as if it could run.

Mitigations:
- Use Fleet's RBAC to limit who can create/edit scripts to a small set of trusted administrators.
- Rely on GitOps-only script management (`fleetctl gitops`) and remove script-create permissions from all human accounts.
- Audit script changes via Fleet's activity feed and your SIEM.

### Protect the policy repository

The git repository itself becomes a high-value target: anyone who can merge to the tracked branch can add scripts that will run on all enrolled hosts.

Recommended controls:
- Require at least two reviewers on pull requests to the tracked branch.
- Require signed commits (`git commit -S`) and enforce this at the repository level.
- Restrict merge access to a small group of trusted administrators.
- Enable audit logging on the repository (GitHub audit log, GitLab audit events, etc.) and forward it to your SIEM.
- Consider a separate, locked-down repository for the policy (separate from the one developers have write access to).

### Protect the local git cache on hosts

Orbit clones the policy repository to `<root-dir>/git-policy` (default `/var/lib/orbit/git-policy` on Linux, `/opt/orbit/git-policy` on macOS). This directory is owned by root/SYSTEM and not world-readable, but local privilege escalation could allow an attacker to tamper with it before the next sync.

Orbit always resets the local clone to `FETCH_HEAD` on each sync (`git reset --hard`), so any local modifications are overwritten. The practical attack window is the time between a local compromise and the next sync (default 5 minutes).

If that window is too large for your threat model, reduce `--git-policy-sync-interval`. The minimum useful value is limited by your git host's rate limits.

### Keep orbit up to date

The git policy is implemented in orbit itself. Ensure your orbit update channel is set to `stable` (the default) and that automatic updates are not disabled (`--disable-updates` should not be set in high-security environments).

## Limitations

| Limitation | Notes |
|------------|-------|
| Software installer scripts | Install and post-install scripts run by Fleet's software management feature are not yet covered by the git policy. They go through a separate execution path in orbit. |
| osquery distributed queries | Covered by disabling distributed queries in agent options (see above). |
| MDM commands | MDM command execution (profiles, DDM) is not mediated by orbit and is not covered by this policy. |
| Windows git requirement | `git` is not installed by default on Windows. It must be pre-installed or deployed via your MDM before orbit enrollment if you use this feature. |
| Sync latency | Script changes become effective on a host after the next sync (default 5 minutes). Plan for this delay when deploying emergency remediations. |
