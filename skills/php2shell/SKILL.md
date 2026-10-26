---
name: php2shell
description: PHP2Shell (CVE-2026-109618, CVE-2026-109619) and CVE-2026-115560 on Debian and Ubuntu PHP servers. Use to check whether a host is vulnerable or already patched, per PHP branch, and to produce a per-host report.
---

# PHP2Shell

The shortcut this skill replaces: judging a host by `php -v` or a one-off grep over ssh. Ubuntu backports keep the upstream number (`8.3.6`) and carry the fix in the package revision, and a changelog read through `head | grep -q` under `pipefail` misses the CVE lines. The verdict for a branch comes from the audit records, never from a hand check.

Scripts live in `${CLAUDE_PLUGIN_ROOT}/scripts/`. Each run prints a human section plus records `@p2s schema=1 key=value ...`; the record format is defined in `scripts/lib/p2s.sh`.

## Steps

1. **Audit** every host the operator names: `bash ${CLAUDE_PLUGIN_ROOT}/scripts/run.sh audit <host>`, where host is an ssh alias or `user@address`. The audit is read-only. When the permission layer denies the call, hand the operator the same line as a `!` command and read its output back. Done when each host either printed `log: <path>` with a host record in that log, or exited 255 (ssh failed: the host is unreachable).
2. **Report**: `bash ${CLAUDE_PLUGIN_ROOT}/scripts/report.sh <log>...` over the logs from step 1. Show the operator the tables and list unreachable hosts beside them. Done when every host from step 1 has a section or an unreachable line.
3. **Confirm the restart for every `fixed` branch.** The verdict judges the installed package; a running PHP-FPM keeps executing the build it started with until it is restarted, so a host can report `fixed` and still serve the vulnerable code. The audit does not check this yet. Per `fixed` branch, compare the service start (`systemctl show -p ActiveEnterTimestamp --value php<X.Y>-fpm`) with the package install time (`stat -c %y /var/lib/dpkg/info/php<X.Y>-fpm.list`), both read-only; hand them to the operator as `!` commands when the call is denied. Done when each `fixed` branch is either "started after install" or reported as "installed, restart not confirmed". Call a host protected only when all its branches are fixed and started after install.
4. **Stop at the report.** This version audits only: patching, the upload-progress mitigation and auto-updates are not built yet. For each `unfixed` branch, name the host, branch, reason and target. A target of `none` is a statement about the host's cached apt lists, never about whether a fix exists: when `lists_stale` is `yes` or `unknown`, say the lists predate the fixes (or are unknown) and that `apt-get update` comes first, which is a write the operator runs.

## Verdict reasons

| Reason | Meaning |
|---|---|
| `distro-threshold` | Ubuntu build at or above the fixed Ubuntu revision |
| `upstream-threshold` | Upstream part of the version at or above the fixed upstream release |
| `changelog` | No threshold met, but the installed package changelog names both CVEs (vendor backport) |
| `below-threshold` | A threshold exists for this branch and origin, the build is below it, and the changelog does not name both CVEs |
| `no-cve-in-changelog` | No threshold for this branch (EOL: 7.4, 8.0, 8.1 from a PPA) and the changelog does not name both CVEs |

`cve_changelog=missing` means the `php<branch>-common` changelog is absent; treat the branch as unverified, which the verdict reports as `unfixed`.

## Targets

The audit judges the builds apt offers from the lists already on the host (it never runs `apt-get update`) and picks the target a patch would install. A target always keeps the installed build's origin: a PPA version can sort above a fixed Ubuntu revision and still be unfixed.

| Target reason | Meaning |
|---|---|
| `installed-fixed` | Nothing to install |
| `fixed-candidate` | The newest fixed build of the same origin that apt offers |
| `fixed-distro-build-not-in-cached-lists` | Distro build, and the cached lists hold no fixed distro build; a fixed PPA build does not count |
| `no-fixed-build-in-cached-lists` | PPA or other build, and the cached lists hold no fixed build of that origin |

`lists_updated` is when the newest apt list of the branch's origin last changed; `lists_stale=yes` means it is older than the day the fixed builds came out, so the lists cannot contain one. Candidate records with `cve_changelog=download-failed` were judged by version thresholds alone.
