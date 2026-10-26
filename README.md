# php2shell-fixer

Claude Code plugin that audits and patches PHP2Shell (CVE-2026-109618, CVE-2026-109619) on Debian and Ubuntu servers running PHP-FPM or mod_php, and keeps the CVE-2026-115560 mitigation in place.

Work in progress. Right now the plugin can audit a PHP-FPM host and tell you, per PHP branch, whether the installed build is fixed and why. Patching, the mitigation and auto-updates are coming next. The plan lives in [issue #1](https://github.com/turovskiy/php2shell-fixer/issues/1) and its sub-issues.

## Install

```
claude plugin marketplace add turovskiy/php2shell-fixer
claude plugin install php2shell-fixer@php2shell-fixer
```

## Use

Ask Claude to check a server for PHP2Shell, or run the scripts yourself:

1. Audit a host. Nothing changes on the server, the script is streamed over ssh:

   ```
   bash scripts/run.sh audit web1
   ```

   `web1` is any ssh alias or `user@address`. The output is saved to `~/.cache/php2shell/<host>-audit-<time>.log`.

2. Build the report from one or more logs:

   ```
   bash scripts/report.sh ~/.cache/php2shell/*-audit-*.log
   ```

   You get one table per host: branch, installed build, where it came from (Ubuntu, Debian or the ondrej PPA), whether the service runs, whether the changelog names both CVEs, and the verdict with its reason.

Why not just `php -v`? Ubuntu ships the fix as `8.3.6-0ubuntu0.24.04.13`, and `php -v` still says `8.3.6`. The audit looks at the package version and its changelog instead.

## Tests

```
bash tests/run.sh
```

The tests touch no real server: `ssh`, `dpkg-query`, `systemctl` and the apt tools are replaced with stubs, and every host is a fake directory tree.
