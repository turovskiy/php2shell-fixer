---
name: php2shell
description: PHP2Shell (CVE-2026-109618, CVE-2026-109619) and CVE-2026-115560 on Debian and Ubuntu PHP servers. Use to check whether a host is vulnerable or already patched per PHP branch, to put or keep the upload_progress mitigation in place, and to produce a per-host report.
---

# PHP2Shell

The shortcut this skill replaces: judging a host by `php -v` or a one-off grep over ssh. Ubuntu backports keep the upstream number (`8.3.6`) and carry the fix in the package revision, and a changelog read through `head | grep -q` under `pipefail` misses the CVE lines. The verdict for a branch comes from the audit records, never from a hand check.

Scripts live in `${CLAUDE_PLUGIN_ROOT}/scripts/`. Each run prints a human section plus records `@p2s schema=1 key=value ...`; the record format is defined in `scripts/lib/p2s.sh`.

## Steps

1. **Audit** every host the operator names: `bash ${CLAUDE_PLUGIN_ROOT}/scripts/run.sh audit <host>`, where host is an ssh alias or `user@address`. The audit is read-only. When the permission layer denies the call, hand the operator the same line as a `!` command and read its output back. Done when each host either printed `log: <path>` with a host record in that log, or exited 255 (ssh failed: the host is unreachable).
2. **Report**: `bash ${CLAUDE_PLUGIN_ROOT}/scripts/report.sh <log>...` over the logs from step 1. Show the operator the tables and list unreachable hosts beside them. Done when every host from step 1 has a section or an unreachable line.
3. **Read the restart state of every `fixed` branch.** The verdict judges the installed package; a running PHP-FPM keeps executing the build it started with, so a host can report `fixed` and still serve the vulnerable code. The branch record's `restart` says which: `ok` (started after the newest package of the branch), `needed`, `not-running`, `unknown`. Call a host protected only when every branch is `fixed` with `restart=ok` or `not-running`; for `needed`, the restart is a write the operator runs (`systemctl restart php<X.Y>-fpm`).
4. **Ensure the mitigation** on every host where a `mitigation` record is not `mitigated`: hand the operator `! bash ${CLAUDE_PLUGIN_ROOT}/scripts/run.sh ensure <host>`, since it writes `99-security.ini` and reloads FPM pools. Read its log back and run step 2 over it. Exit 0: every web SAPI mitigated. Exit 3: name each blocker from the records, and leave the fix to the operator, because the files are theirs: an `override` record that `enables=yes` (file, line, pool), a `foreign` 99-security.ini, a SAPI still `On` or `unknown`. Exit 1: a config test failed (the change was rolled back and the pool kept running) or a reload failed; show the output. Done when every host's newest log shows each web SAPI `mitigated` or a named blocker.
5. **Stop at the report.** Patching and auto-updates are not built yet. For each `unfixed` branch, name the host, branch, reason and target. A target of `none` is a statement about the host's cached apt lists, never about whether a fix exists: when `lists_stale` is `yes` or `unknown`, say the lists predate the fixes (or are unknown) and that `apt-get update` comes first, which is a write the operator runs.

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

## Host facts

The audit's last section tells the operator how to patch; report these alongside the verdicts:

- `pool used=no`: no nginx site points at the pool, so stopping it is an alternative to patching it. `used=unknown` (Apache running, or no readable nginx config) is never a stop candidate.
- `hold`: apt will not upgrade a held package; the patch waits until the operator releases it.
- `source release_info=changed`: the PPA changed its Release info (`changed=` names the fields), so `apt-get update` refuses that source and its lists stay stale until the operator accepts the change. `unknown`: no cached InRelease or the fetch failed.
- `autoupdate ppa_covered=no` on a host with a PPA source: PHP from the PPA never updates by itself.

## Mitigation states

`session.upload_progress.enabled = 0` closes CVE-2026-115560 and the session path of CVE-2026-109619, whether or not a fixed build exists. It only counts when set before the request is parsed (php.ini, `conf.d`, pool config); `ini_set()` and `.user.ini` come too late.

| State | Meaning |
|---|---|
| `mitigated` | The SAPI reports Off and no pool re-enables it |
| `override` | A pool `php_value`/`php_admin_value`/`php_flag`/`php_admin_flag` turns it back on; `php-fpm -i` cannot see this, the pool scan does |
| `foreign` | A 99-security.ini without the plugin marker or the legacy fix.sh comment; ensure leaves it alone |
| `not-mitigated` | The SAPI reports On |
| `unknown` | The SAPI binary gave no answer |

`ini=legacy` is a file written by the earlier fix.sh; ensure adopts it unchanged when it already turns upload progress off.
