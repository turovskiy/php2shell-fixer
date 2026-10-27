# php2shell-fixer

Claude Code plugin that audits and patches PHP2Shell (CVE-2026-109618, CVE-2026-109619) on Debian and Ubuntu servers running PHP-FPM or mod_php, and keeps the CVE-2026-115560 mitigation in place.

Work in progress. The plugin audits PHP-FPM and Apache mod_php hosts, patches them, keeps the CVE-2026-115560 mitigation in place, and lets PHP from the ondrej PPA update itself. The plan lives in [issue #1](https://github.com/turovskiy/php2shell-fixer/issues/1) and its sub-issues.

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

The target comes from the package lists already on the server: the audit only reads, so it never runs `apt-get update`. "none" means the server's lists hold no fixed build, not that no fix exists. When the report marks the lists as older than the fixes, run `apt-get update` on the server and audit again before you decide anything. Two releases are the exception, and the report says so under the table: Debian 11 gets no PHP2Shell fix at all (`no-fix-for-release`), and Ubuntu 20.04 and older get it only through Ubuntu Pro ESM (`fix-only-in-esm` while no ESM source is enabled). There `apt-get update` changes nothing, and `next.sh` answers `manual` once the host is mitigated.

## Many servers, and picking up where you left off

`run.sh` takes several hosts at once: `bash scripts/run.sh audit <host1> <host2> <host3>`. Each host gets its own log in `~/.cache/php2shell`, so the logs survive a closed session or a reboot. A host that does not answer is marked unreachable and the run moves on to the next one.

Two commands read those logs later:

```
bash scripts/report.sh --latest   # the newest log per server, one report
bash scripts/next.sh --latest     # what to do next on each server: audit, investigate, fix, ensure, autoupdate, verify, manual or done
```

The audit also checks for signs that a server was already attacked, since exploitation began on 2026-10-17 (before the fixed builds came out): PHP or Apache crashes in the logs, a shell or a download tool started by PHP that is running right now, and PHP files changed since that day in the site folders and in `/tmp`, `/var/tmp` and `/dev/shm`. Each check has a time limit and a file limit. The report lists what it found under "Indicators of compromise", and `next.sh` says `investigate` before anything else when a shell runs under PHP, or when crashes and new PHP files show up together. If that happens, patching is not enough: the server may already hold a web shell or have leaked its secrets, so isolate it, rebuild it, and change every password and key the sites used. A clean result is not proof either: file dates can be faked and old logs get deleted.

The audit also looks for PHP that did not come from Ubuntu or Debian packages: cPanel's `ea-php`, Plesk's PHP, LiteSpeed's `lsphp`, or a build in `/usr/local`. It finds the running ones through `/proc` and the installed ones in those vendors' usual folders. The plugin cannot judge or patch such a PHP: the vendor updates it, and its version number says little, because vendors backport fixes. So the report lists them, `fix` and `ensure` leave them alone and say so, and `next.sh` gives such a server `manual` instead of `done`, naming who updates each one.

Write commands (`ensure`, `autoupdate`) are never cut off by a time limit, even if a server is slow: a session killed in the middle of apt or a reload leaves the server half changed. Only the read-only audit has a limit (10 minutes per server by default). A dropped connection is another matter. If your laptop sleeps or the network goes, the server does not stop the command at once: it stops the next time the command prints something, or lets it run to the end if it prints little. So you cannot tell where it stopped. For `ensure` that is harmless (run it again), but keep the connection up until it finishes.

## Patch a server

```
bash scripts/run.sh fix <host>
```

This is the write that closes PHP2Shell. For every PHP branch that serves requests through PHP-FPM or Apache mod_php it installs the build the audit names as the target, with every package of that PHP version pinned to the same version; PECL extensions such as `php8.3-redis` keep their own versions. It also puts the upload_progress mitigation in place, runs the config test (`php-fpm -t` for a pool, `apachectl configtest` for mod_php), restarts only the pools, or Apache, it changed, and compares the HTTP status code of each nginx PHP site and each Apache vhost before and after. Each vhost is asked on its own port and address: https on 443, plain http on any other port. For mod_php the restart is a full `systemctl restart apache2`, so every Apache site on the server is down for a few seconds: run the first mod_php patch on a client server at a quiet hour and watch it. When a config test fails, the new ini is removed and the service is not restarted.

The packages themselves want to restart PHP-FPM or reload Apache while they install, before the new settings are tested. To stop that, the patch puts a `/usr/sbin/policy-rc.d` in place for the install only. It tells `invoke-rc.d` and `deb-systemd-invoke` that no service may be started, stopped or restarted. If the server already has its own `policy-rc.d`, it is moved to `/var/lib/php2shell/policy-rc.d.kept` for the install and then put back unchanged, even if apt fails or the patch is stopped. A package script that calls `systemctl` or `service` directly would not ask `policy-rc.d`; the PHP and Apache packages go through `invoke-rc.d` and `deb-systemd-invoke`.

On PHP 8.5 without a fixed build it also turns off `fatal_error_backtraces`.

It stops before touching anything when a PHP package is held, when `apt-get update` fails, or when the ondrej PPA changed its Release info; in that last case it prints the `apt-get update --allow-releaseinfo-change-...` command for you to run once you have checked the change. It never accepts it on its own.

The patch runs on the server as its own systemd unit, not inside your ssh session. If your connection drops halfway, apt finishes anyway. Run the same command again: it attaches to the patch that is still running, or shows you the result of the one that finished, and never starts a second patch on top. Every run backs up `/etc/php` to `/root/etc-php-<time>.tgz` and ends with the commands that undo it.

Before installing, it also saves the packages it is about to replace, as `.deb` files in `/var/lib/php2shell/debs-<time>/php<X.Y>/`, so the undo command installs those files and does not depend on the Ubuntu or Debian archive: the security and updates sections keep only the newest build, so the old one is usually gone from there right after the patch. If a package cannot be downloaded, the patch rebuilds it from the installed files with `dpkg-repack` when that tool is installed. If neither works, the patch still goes on, but the summary and the report name the packages that were not saved, and the undo command for them falls back to asking apt for the old version. The last three runs' files are kept; older ones are removed when a new run saves its own.

## Keep the mitigation in place

CVE-2026-115560 has no fix yet. Until PHP ships one, the protection is `session.upload_progress.enabled = 0` in every web SAPI (PHP-FPM, mod_php and PHP-CGI). This command puts it in place and keeps it there:

```
bash scripts/run.sh ensure <host>
```

It writes `99-security.ini` into `conf.d` where the file is missing or outdated, runs the config test, and reloads only the PHP-FPM pools, or Apache, it changed. If the test fails, it puts the old file back and leaves the pool or Apache running. Running it again on a host that is already fine changes nothing.

It does not touch a `99-security.ini` someone else wrote, and it does not edit pool or Apache configs. If a pool turns upload progress back on (`php_admin_flag[session.upload_progress.enabled] = on`), or Apache config does (`php_admin_flag session.upload_progress.enabled on`, in any file Apache reads, your own `Include` files too), the command exits with code 3 and names the file and line, and you fix it by hand. The same goes for nginx turning it back on for a PHP-FPM site (`fastcgi_param PHP_VALUE "session.upload_progress.enabled=1"`, or `PHP_ADMIN_VALUE`) and for a `.user.ini` file in the site's folder: both apply per request, so PHP's own settings cannot show them. The `.user.ini` search goes 4 folders deep and reads at most 200 files per site; if it stops there, the report says so. `.htaccess` files are not checked. CLI is left alone: it serves no web requests.

This is a write on the server, so run it yourself or approve it when Claude asks.

`ensure` also leaves an apt hook on the server: after every package install or upgrade, apt runs the same check again, so a PHP version you install next month gets the protection too. The hook lives in two files, `/etc/apt/apt.conf.d/99php2shell-ensure` and `/usr/local/sbin/php2shell-ensure`, and writes what it did to `/var/log/php2shell-ensure.log`. It can never make apt fail. To remove it, delete both files. The audit shows whether the hook is in place and up to date.

## Keep PPA PHP updated

On Ubuntu, unattended-upgrades installs security updates from Ubuntu only. PHP from the ondrej PPA stays on whatever version was installed until someone upgrades it by hand. Adding the PPA to unattended-upgrades is not enough on its own: a PHP version that came from Ubuntu would then start pulling builds from the PPA, and a PPA build with a higher number is not always a fixed one.

```
bash scripts/run.sh autoupdate <host>
```

Know what you switch on before running it. The ondrej PPA has no separate security section, so once it is in unattended-upgrades, the server installs every new PHP build the PPA publishes, not only CVE fixes, on the unattended-upgrades schedule, and the package restarts PHP-FPM as it installs. Libraries the PPA ships alongside PHP update the same way. Tell the client that PHP on that server now updates by itself, and decide per server whether that is acceptable.

Before anything else it checks that the PPA has not changed its Release info (Origin, Label) since apt last downloaded it. If it has, the command writes nothing and prints the `apt-get update --allow-releaseinfo-change-...` command for you to run once you have checked the change. Only the PHP PPA counts: `ondrej/nginx` or `ondrej/apache2` on the same server never gets into unattended-upgrades.

Then it does three things, in this order:

1. For every PHP version installed from Ubuntu or Debian that the PPA also ships, it writes a pin that keeps the PPA builds away from it: `/etc/apt/preferences.d/php2shell-php8.3.pref` with `Pin-Priority: -1`. The `.pref` ending matters. apt reads only files in that folder with no extension or with `.pref`, and `php8.3` alone already counts as having one (`.3`).
2. It asks apt (`apt-cache policy`) which build it would now install for every PHP package, and where each build comes from, by the source apt lists for it rather than by the version number. If any package would switch between Ubuntu or Debian and the PPA, or a pinned PHP version still has a PPA build apt does not hold off (a pin that does nothing, even while the PPA build happens to be older), the command stops, names the PHP version and the pin that does not work, and goes no further. The pins it wrote stay: they only keep each version where it is.
3. It adds the PPA to the list unattended-upgrades accepts (`/etc/apt/apt.conf.d/51php2shell-ppa-origins`) and runs `unattended-upgrade --dry-run` to check the PPA shows up and that unattended-upgrades would not now upgrade an Ubuntu or Debian PHP package from the PPA. If either check fails, that file is taken out again. If your connection drops right after the file is written, the file is put back as it was. If it drops while the check runs, the server finishes the check anyway and keeps or removes the file by its result. Either way, run the same command again to see where the server stands.

If a server already has an equivalent pin or PPA entry, under any file name, the command finds it by content and writes nothing twice. A pin under a name apt skips (for example `ondrej-php.conf`) shows up in step 2, and the command tells you what to rename it to. On a server without the PPA it writes nothing. Every run ends with the commands that undo what it wrote; a file it had to overwrite is kept first in `/var/lib/php2shell/backup`, and the undo command copies it back.

This is a write on the server, so run it yourself or approve it when Claude asks.

## Tests

```
bash tests/run.sh
```

The tests touch no real server: `ssh`, `dpkg-query`, `systemctl` and the apt tools are replaced with stubs, and every host is a fake directory tree.

CI runs on every push and pull request: shellcheck 0.11.0 on every script, a syntax check of each mode's bundle (what ssh would receive), then the tests. To run shellcheck locally the same way:

```
shellcheck -x -S warning scripts/*.sh scripts/lib/*.sh tests/run.sh
```

The libraries have no shebang, because they are joined into one stream before they reach a server, so each starts with `# shellcheck shell=bash`.
