# php2shell-fixer

Claude Code plugin that audits and patches PHP2Shell (CVE-2026-109618, CVE-2026-109619) on Debian and Ubuntu servers running PHP-FPM or mod_php, and keeps the CVE-2026-115560 mitigation in place.

Work in progress. The plugin audits PHP-FPM and Apache mod_php hosts, patches them, and keeps the CVE-2026-115560 mitigation in place. Keeping PPA PHP updated on its own is coming next. The plan lives in [issue #1](https://github.com/turovskiy/php2shell-fixer/issues/1) and its sub-issues.

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

   `<host>` is an alias from your `~/.ssh/config` or `user@address`. The output is saved to `~/.cache/php2shell/<host>-audit-<time>.log`. The audit also shows, per PHP-FPM, mod_php and PHP-CGI, whether upload progress is off (see below).

2. Build the report from one or more logs:

   ```
   bash scripts/report.sh ~/.cache/php2shell/*-audit-*.log
   ```

   You get one table per host: branch, SAPI (`fpm` for PHP-FPM, `apache2` for mod_php), installed build, where it came from (Ubuntu, Debian or the ondrej PPA), whether the service runs, whether the changelog names both CVEs, the verdict with its reason, the build a patch would install (target), and how old the host's apt lists are.

Why not just `php -v`? Ubuntu ships the fix as `8.3.6-0ubuntu0.24.04.13`, and `php -v` still says `8.3.6`. The audit looks at the package version and its changelog instead.

"fixed" in the report is about the installed package. PHP-FPM and Apache keep running the build they started with until they are restarted, so the report also has a Restart column: "needed" means the service started before the last PHP package was installed and still runs the old code. Only "fixed" together with Restart "ok" means the server is safe.

Under the tables the report lists host facts that help decide how to patch: which site runs on which PHP-FPM pool (a pool no site uses is marked as a stop candidate), held PHP packages, the ondrej PPA sources and whether the PPA changed its Release info (then `apt-get update` refuses it until you accept the change), and whether unattended-upgrades covers the PPA at all. To check the Release info the audit downloads the PPA's current `InRelease` file into a temp folder and deletes it right after, the same way it handles candidate packages.

The target comes from the package lists already on the server: the audit only reads, so it never runs `apt-get update`. "none" means the server's lists hold no fixed build, not that no fix exists. When the report marks the lists as older than the fixes, run `apt-get update` on the server and audit again before you decide anything.

## Many servers, and picking up where you left off

`run.sh` takes several hosts at once: `bash scripts/run.sh audit <host1> <host2> <host3>`. Each host gets its own log in `~/.cache/php2shell`, so the logs survive a closed session or a reboot. A host that does not answer is marked unreachable and the run moves on to the next one.

Two commands read those logs later:

```
bash scripts/report.sh --latest   # the newest log per server, one report
bash scripts/next.sh --latest     # what to do next on each server: audit, fix, ensure, verify or done
```

Write commands (`ensure`) are never cut off by a time limit, even if a server is slow: a session killed in the middle of apt or a reload leaves the server half changed. Only the read-only audit has a limit (10 minutes per server by default). A dropped connection is another matter: if your laptop sleeps or the network goes, the server most likely stops the command where it was. For `ensure` that is harmless (run it again), but keep the connection up until it finishes.

## Patch a server

```
bash scripts/run.sh fix <host>
```

This is the write that closes PHP2Shell. For every PHP branch that serves requests through PHP-FPM or Apache mod_php it installs the build the audit names as the target, with every package of that PHP version pinned to the same version; PECL extensions such as `php8.3-redis` keep their own versions. It also puts the upload_progress mitigation in place, runs the config test (`php-fpm -t` for a pool, `apachectl configtest` for mod_php), restarts only the pools, or Apache, it changed, and compares the HTTP status code of each nginx PHP site and each Apache vhost before and after. When a config test fails, the new ini is removed and the service is not restarted. On PHP 8.5 without a fixed build it also turns off `fatal_error_backtraces`.

It stops before touching anything when a PHP package is held, when `apt-get update` fails, or when the ondrej PPA changed its Release info; in that last case it prints the `apt-get update --allow-releaseinfo-change-...` command for you to run once you have checked the change. It never accepts it on its own.

The patch runs on the server as its own systemd unit, not inside your ssh session. If your connection drops halfway, apt finishes anyway. Run the same command again: it attaches to the patch that is still running, or shows you the result of the one that finished, and never starts a second patch on top. Every run backs up `/etc/php` to `/root/etc-php-<time>.tgz` and ends with the commands that undo it.

## Keep the mitigation in place

CVE-2026-115560 has no fix yet. Until PHP ships one, the protection is `session.upload_progress.enabled = 0` in every web SAPI (PHP-FPM, mod_php and PHP-CGI). This command puts it in place and keeps it there:

```
bash scripts/run.sh ensure <host>
```

It writes `99-security.ini` into `conf.d` where the file is missing or outdated, runs the config test, and reloads only the PHP-FPM pools, or Apache, it changed. If the test fails, it puts the old file back and leaves the pool or Apache running. Running it again on a host that is already fine changes nothing.

It does not touch a `99-security.ini` someone else wrote, and it does not edit pool or Apache configs. If a pool turns upload progress back on (`php_admin_flag[session.upload_progress.enabled] = on`), or Apache config does (`php_admin_flag session.upload_progress.enabled on`), the command exits with code 3 and names the file and line, and you fix it by hand. `.htaccess` files are not checked. CLI is left alone: it serves no web requests.

This is a write on the server, so run it yourself or approve it when Claude asks.

`ensure` also leaves an apt hook on the server: after every package install or upgrade, apt runs the same check again, so a PHP version you install next month gets the protection too. The hook lives in two files, `/etc/apt/apt.conf.d/99php2shell-ensure` and `/usr/local/sbin/php2shell-ensure`, and writes what it did to `/var/log/php2shell-ensure.log`. It can never make apt fail. To remove it, delete both files. The audit shows whether the hook is in place and up to date.

## Tests

```
bash tests/run.sh
```

The tests touch no real server: `ssh`, `dpkg-query`, `systemctl` and the apt tools are replaced with stubs, and every host is a fake directory tree.
