---
name: php2shell
description: PHP2Shell (CVE-2026-109618, CVE-2026-109619) and CVE-2026-115560 on Debian and Ubuntu PHP servers (PHP-FPM, Apache mod_php). Use to check whether a host is vulnerable or already patched per PHP branch, to put or keep the upload_progress mitigation in place, and to produce a per-host report.
---

# PHP2Shell

The shortcut this skill replaces: judging a host by `php -v` or a one-off grep over ssh. Ubuntu backports keep the upstream number (`8.3.6`) and carry the fix in the package revision, and a changelog read through `head | grep -q` under `pipefail` misses the CVE lines. The verdict for a branch comes from the audit records, never from a hand check.

Scripts live in `${CLAUDE_PLUGIN_ROOT}/scripts/`. Each run prints a human section plus records `@p2s schema=1 key=value ...`; the record format is defined in `scripts/lib/p2s.sh`.

Records name the SAPI in `sapi=`: `fpm` (PHP-FPM, service `php<X.Y>-fpm`), `apache2` (mod_php, service `apache2`), `cgi` (mitigation only). A branch served by both gets one record per SAPI, and each counts on its own.

## Steps

0. **Resume first**: `bash ${CLAUDE_PLUGIN_ROOT}/scripts/next.sh --latest` prints one `<host>: <step> - <reason>` line per host from the saved logs (steps `audit`, `fix`, `ensure`, `autoupdate`, `verify` = audit again after a write, `done`). Take each host to the step it names; "no readable logs" means a fresh start at step 1.
1. **Audit** the hosts the operator names, all in one call: `bash ${CLAUDE_PLUGIN_ROOT}/scripts/run.sh audit <host>...`, host being an ssh alias or `user@address`. Read-only. Each host gets its own log in `~/.cache/php2shell` (survives the session); an unreachable or timed-out host is recorded and the run goes on, and the exit code is the worst host's. ssh runs with BatchMode, so a key that needs a passphrase and is not in the agent fails as `unreachable`: ask the operator to load it. When the permission layer denies the call, hand the operator the same line as a `!` command and read its output back. Done when every host has a log ending in a `run_end` record.
2. **Report**: `bash ${CLAUDE_PLUGIN_ROOT}/scripts/report.sh --latest` renders the newest log per host and mode. Show the operator the tables; an unreachable host has its own section with ssh's error. Done when every host from step 1 has a section.
3. **Read the restart state of every `fixed` branch.** The verdict judges the installed package; a running PHP-FPM pool or Apache keeps executing the build it started with, so a host can report `fixed` and still serve the vulnerable code. The branch record's `restart` says which: `ok` (its service started after the newest package of the branch), `needed`, `not-running`, `unknown`. A mod_php record with `active=not-loaded` is installed but not loaded by Apache: it serves nothing now, and still gets the mitigation. Call a host protected only when every branch is `fixed` with `restart=ok` or `not-running`; `needed` goes to step 5, which restarts it.
4. **Ensure the mitigation** on every host where a `mitigation` record is not `mitigated`: hand the operator `! bash ${CLAUDE_PLUGIN_ROOT}/scripts/run.sh ensure <host>`, since it writes `99-security.ini` and reloads FPM pools and Apache. Read its log back and run step 2 over it. Exit 0: every web SAPI mitigated. Exit 3: name each blocker from the records, and leave the fix to the operator, because the files are theirs: an `override` record that `enables=yes` (file, line, and the pool for `sapi=fpm`; Apache config for `sapi=apache2`), a `foreign` 99-security.ini, a SAPI still `On` or `unknown`. Exit 1: a config test failed (`php-fpm -t`, or `apachectl configtest` for mod_php; the change was rolled back and the service kept running) or a reload failed; show the output. Done when every host's newest log shows each web SAPI `mitigated` or a named blocker.
5. **Fix** every host whose branch is `unfixed` or `restart=needed`: hand the operator `! bash ${CLAUDE_PLUGIN_ROOT}/scripts/run.sh fix <host>`, saying in one line what it changes (apt-get update, the pinned upgrade to each target, 99-security.ini, a restart of the touched pools and of Apache for mod_php). The patch runs on the server as a transient systemd unit, so a dropped connection never stops apt; rerunning the same command attaches to a running patch or hands back a finished one, and never starts a second. Exit 0: fixed, HTTP codes unchanged. Exit 3: a branch has no fixed build in the lists (mitigated meanwhile) or a site's HTTP code changed; name which. Exit 1: preflight stopped it (held package, changed Release info with the accept command, failed apt-get update) or a config test or restart failed (`state=test-failed`: the new ini was removed and the service not restarted; `pool-down`, `apache-down`); show the output and the rollback lines. The HTTP probe asks every nginx PHP site (`nginx -T`) and every Apache vhost (`apachectl -S`); `probe_summary state=no-sites` means neither dump named a site, so nothing was compared. Done when every fixed host gets step 0's `verify`, then an audit.
6. **Auto-updates** on every host whose audit has a `source` record (the ondrej/sury PPA) and `autoupdate ppa_covered=no`: hand the operator `! bash ${CLAUDE_PLUGIN_ROOT}/scripts/run.sh autoupdate <host>`, saying in one line what it changes (a pin file per distro-built PHP branch in `/etc/apt/preferences.d`, then the PPA origin in `/etc/apt/apt.conf.d/51php2shell-ppa-origins`). The order is the safety: the pins come first, then each installed PHP package's `apt-cache policy` candidate must keep the origin of its installed build, and only then is the origin written and checked with `unattended-upgrade --dry-run`. A host without the PPA gets nothing written. Read the `policy` records: `state=kept` per branch is the goal; `pin-ineffective` means a pin is in place and apt still picks the PPA build (a preferences.d name apt skips, or another pin read first that outranks it), `would-change` means no pin covers the branch. Exit 0: configured or already in place (`keeper state=configured|unchanged`). Exit 1: `refused` (name the branch and the pin from the records; the pins stay, the origin was not written; the operator fixes the named file, then rerun), `dryrun-failed` (the origin entry was taken out again), `stopped reason=no-cached-release` (`apt-get update` first), not root. A pin or origin already in place is recognised by content under any file name and not written twice. Done when every PPA host's newest keeper log says `configured` or `unchanged`, then step 0's `verify`.
7. **Report the rest.** For each branch still `unfixed`, name the host, branch, reason and target. A target of `none` is a statement about the host's cached apt lists, never about whether a fix exists: when `lists_stale` is `yes` or `unknown`, say the lists predate the fixes (or are unknown).

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
- `autoupdate ppa_covered=no` on a host with a PPA source: PHP from the PPA never updates by itself; step 6 fixes it.

## Mitigation states

`session.upload_progress.enabled = 0` closes CVE-2026-115560 and the session path of CVE-2026-109619, whether or not a fixed build exists. It only counts when set before the request is parsed (php.ini, `conf.d`, pool config); `ini_set()` and `.user.ini` come too late.

| State | Meaning |
|---|---|
| `mitigated` | The SAPI reports Off and no pool re-enables it |
| `override` | A pool `php_value`/`php_admin_value`/`php_flag`/`php_admin_flag`, or the same directive in Apache config for mod_php, turns it back on; the SAPI's `-i` cannot see this, the pool and Apache scans do |
| `foreign` | A 99-security.ini without the plugin marker or the legacy fix.sh comment; ensure leaves it alone |
| `not-mitigated` | The SAPI reports On |
| `unknown` | The SAPI binary gave no answer |

The Apache scan reads every file Apache's own include dump lists (`apachectl -t -D DUMP_INCLUDES`, so a custom `Include` counts); when the dump fails, `apache2.conf` and the `*.conf` files in `mods-enabled`, `conf-enabled` and `sites-enabled`. `.htaccess` files are not scanned, so a mod_php host with `AllowOverride` set can still re-enable upload progress per directory: say so when reporting such a host as mitigated.

`ini=legacy` is a file written by the earlier fix.sh; ensure adopts it unchanged when it already turns upload progress off.

ensure also installs an apt hook (`/etc/apt/apt.conf.d/99php2shell-ensure` calling `/usr/local/sbin/php2shell-ensure`, log `/var/log/php2shell-ensure.log`), so a PHP branch installed later gets the mitigation without anyone rerunning ensure. The audit's `ensure_hook` record says `present`, `missing` or `outdated` (written by another plugin version or edited by hand); the last two send the host back to ensure. The hook never fails apt: its exit code is swallowed and its failures go to the log.
