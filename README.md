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
   bash scripts/run.sh audit <host>
   ```

   `<host>` is an alias from your `~/.ssh/config` or `user@address`. The output is saved to `~/.cache/php2shell/<host>-audit-<time>.log`.

2. Build the report from one or more logs:

   ```
   bash scripts/report.sh ~/.cache/php2shell/*-audit-*.log
   ```

   You get one table per host: branch, installed build, where it came from (Ubuntu, Debian or the ondrej PPA), whether the service runs, whether the changelog names both CVEs, the verdict with its reason, the build a patch would install (target), and how old the host's apt lists are.

Why not just `php -v`? Ubuntu ships the fix as `8.3.6-0ubuntu0.24.04.13`, and `php -v` still says `8.3.6`. The audit looks at the package version and its changelog instead.

"fixed" in the report is about the installed package, not the running service. PHP-FPM keeps running the build it started with until it is restarted, so check that the service started after the package was installed before you tell anyone the server is safe: `systemctl show -p ActiveEnterTimestamp php8.3-fpm` against `stat -c %y /var/lib/dpkg/info/php8.3-fpm.list`. The audit will check this itself later ([#5](https://github.com/turovskiy/php2shell-fixer/issues/5)).

The target comes from the package lists already on the server: the audit only reads, so it never runs `apt-get update`. "none" means the server's lists hold no fixed build, not that no fix exists. When the report marks the lists as older than the fixes, run `apt-get update` on the server and audit again before you decide anything.

## Tests

```
bash tests/run.sh
```

The tests touch no real server: `ssh`, `dpkg-query`, `systemctl` and the apt tools are replaced with stubs, and every host is a fake directory tree.
