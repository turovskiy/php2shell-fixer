# shellcheck shell=bash
# PHP2Shell patch for PHP-FPM and mod_php hosts. Two parts in one program:
# - the launcher (the tail of this file) runs in the ssh session: it starts the worker as a transient systemd
#   unit, or attaches to a run still going, or hands back a finished run's log, and follows that log;
# - the worker (p2s_fix_worker) is the patch itself, detached from ssh, so a dropped connection never
#   stops apt halfway.
# Per branch, one pinned install covers every SAPI; then each running SAPI gets its mitigation, its config
# test (php-fpm -t for a pool, apachectl configtest for mod_php) and a restart of its service (the pool, or
# apache2), and one "fix" record.
# Runs as the tail of the bundle from run.sh (after versions.sh, p2s.sh, mitigation.sh, hostfacts.sh,
# branch.sh): run.sh fix <host>
# Server state: /var/lib/php2shell/fix-<stamp>.{log,exit,worker.sh,reported} and "current" (the last run).
# Exit (the worker's, passed on): 0 every running branch fixed and HTTP unchanged; 3 a branch still unfixed
#   (mitigation applied) or an HTTP status changed; 1 preflight failed, apt failed, a config test failed or a
#   pool or Apache is down after its restart.
set -u
export LC_ALL=C

P2S_STATE=$(p2s_path /var/lib/php2shell)

# HTTP status of every site nginx sends to PHP and every vhost Apache serves, one "site code" per line, asked
# locally: https for port 443 (nginx sites always), plain http at the vhost's own port otherwise, resolved to
# the vhost's address (127.0.0.1 when it listens on any). The site is the name, or "name:port" off 443. Both
# dumps are the effective config, so symlinked and included sites count; a name on the same port is asked once.
p2s_probe() {
  local ngx aps n port addr
  {
    if ngx=$(nginx -T </dev/null 2>/dev/null); then p2s_nginx_sites "$ngx" | cut -d'|' -f1 | tr ',' '\n' | sed 's/$/|443|-/'; fi
    # apachectl -S prints warnings (AH00558) with the dump; the parser keeps only vhost lines.
    if aps=$(apachectl -S </dev/null 2>&1); then p2s_apache_sites "$aps"; fi
  } | grep -E '^[A-Za-z0-9.-]+\.[A-Za-z]+\|' | sort -t'|' -k1,1 -k2,2n -u | head -25 \
    | while IFS='|' read -r n port addr; do
      [ "$addr" != - ] || addr=127.0.0.1
      if [ "$port" = 443 ]; then
        printf '%s %s\n' "$n" "$(curl -sk -o /dev/null -m 15 -w '%{http_code}' --resolve "$n:443:$addr" "https://$n/" </dev/null)"
      else
        printf '%s:%s %s\n' "$n" "$port" "$(curl -s -o /dev/null -m 15 -w '%{http_code}' --resolve "$n:$port:$addr" "http://$n:$port/" </dev/null)"
      fi
    done
}

# PHP modules a SAPI loads: php-fpm -m for FPM, the CLI with Apache's ini for mod_php.
p2s_sapi_modules() { # $1 branch, $2 sapi
  case $2 in
    fpm) "php-fpm$1" -m </dev/null 2>/dev/null ;;
    apache2) p2s_php_apache2 "$1" -m 2>/dev/null ;;
  esac
}

# The patch. $1 run stamp. Returns 0, 1 or 3 as described at the top.
p2s_fix_worker() {
  local stamp=$1 host held upd urc fields backup before_probe after_probe
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l LC_ALL=C
  host=$(hostname </dev/null)
  echo "== php2shell fix: $host ($(p2s_os)), run $stamp"
  p2s_record kind=host host="$host" os="$(p2s_os)"
  P2S_RC=0 P2S_ROLLBACK=()
  P2S_TMP=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "rm -rf '$P2S_TMP'" RETURN

  echo "== preflight"
  held=$(apt-mark showhold </dev/null 2>/dev/null | grep -E '^(php|libapache2-mod-php)' | paste -sd, -)
  if [ -n "$held" ]; then
    echo "STOP: held PHP packages: $held. apt will not upgrade them; release them with apt-mark unhold first."
    p2s_record kind=preflight host="$host" result=failed reason=held packages="$held"
    return 1
  fi
  upd=$(apt-get -o DPkg::Lock::Timeout=600 -o Acquire::Retries=3 update </dev/null 2>&1)
  urc=$?
  if grep -qE "changed its '(Origin|Label|Suite|Codename|Version)' value" <<<"$upd"; then
    fields=$(grep -oE "changed its '[A-Za-z]+' value" <<<"$upd" | sed -E "s/.*'([A-Za-z]+)'.*/\\1/" | sort -u)
    grep -E "changed its" <<<"$upd"
    echo "STOP: a source changed its Release info; apt-get update refuses it until you accept the change."
    echo "Check the change is expected, then accept it with:"
    echo "  apt-get update $(for f in $fields; do printf -- '--allow-releaseinfo-change-%s ' "${f,,}"; done)"
    p2s_record kind=preflight host="$host" result=failed reason=release-info-changed fields="$(paste -sd, - <<<"$fields")"
    return 1
  fi
  if [ "$urc" != 0 ]; then
    tail -5 <<<"$upd"
    echo "STOP: apt-get update failed (exit $urc)"
    p2s_record kind=preflight host="$host" result=failed reason=apt-update-failed
    return 1
  fi
  backup=/root/etc-php-$stamp.tgz
  if ! tar czf "$(p2s_path "$backup")" -C "$(p2s_path /)" etc/php </dev/null 2>/dev/null; then
    echo "STOP: backup of /etc/php failed"
    p2s_record kind=preflight host="$host" result=failed reason=backup-failed
    return 1
  fi
  before_probe=$(p2s_probe)
  echo "backup $backup"
  p2s_record kind=preflight host="$host" result=ok backup="$backup" sites="$(grep -c . <<<"$before_probe")"

  local all branch b sapi pkg ver row running idle psapi ppkg before pkgs installed bstate after nver cve
  local vafter rafter sbefore safter svafter unit state restart mods ini85 changed
  local -A mbefore needed
  all=$(p2s_branch_packages)
  for branch in $(awk -F'|' '!seen[$1]++ {print $1}' <<<"$all"); do
    echo "== php$branch"
    # The branch's SAPIs that serve requests now (FPM pool active, mod_php loaded by a running Apache).
    running=() idle=()
    while IFS='|' read -r b sapi pkg ver; do
      [ "$b" = "$branch" ] || continue
      if p2s_sapi_running "$branch" "$sapi"; then running+=("$sapi|$pkg|$ver"); else idle+=("$sapi|$pkg|$ver"); fi
    done <<<"$all"
    if [ ${#running[@]} -eq 0 ]; then
      for row in "${idle[@]}"; do
        IFS='|' read -r sapi pkg ver <<<"$row"
        echo "php$branch $sapi is not running: left alone"
        p2s_record kind=fix host="$host" branch="$branch" before="$ver" after="$ver" target=- fixed=- \
          restart=skipped modules=- state=not-running sapi="$sapi"
      done
      continue
    fi
    # The same judgement as the audit, on the lists apt-get update just refreshed, through the first running
    # SAPI's package: every package of the branch is pinned to the one target below.
    IFS='|' read -r psapi ppkg before <<<"${running[0]}"
    p2s_branch_eval "$host" "$branch" "$before" "$ppkg" "$psapi"
    [ ${#BR_CHUMAN[@]} -eq 0 ] || printf '%s\n' "${BR_CHUMAN[@]}"
    [ ${#BR_CRECORDS[@]} -eq 0 ] || printf '%s\n' "${BR_CRECORDS[@]}"
    # Every package built from the branch's source package (php8.3), by the source field and not by name:
    # PECL extensions such as php8.3-redis or php8.3-imagick come from their own sources with their own
    # versions, and pinning them to the PHP version would make apt refuse the whole install.
    pkgs=$(dpkg-query -W -f='${db:Status-Abbrev}|${binary:Package}|${source:Package}\n' "php$branch-*" "libapache2-mod-php$branch" </dev/null 2>/dev/null \
      | awk -F'|' -v s="php$branch" '$1 ~ /^ii/ && $3 == s {print $2}' | sort -u | paste -sd' ' -)
    # Before the install: each SAPI's modules, and whether its service already runs an older build than the
    # one installed (started before its last install), which needs a restart even without a new install.
    mbefore=() needed=()
    for row in "${running[@]}"; do
      IFS='|' read -r sapi pkg ver <<<"$row"
      mbefore[$sapi]=$(p2s_sapi_modules "$branch" "$sapi")
      needed[$sapi]=$(p2s_restart_state "$branch" active "$sapi" | awk '{print $3}')
    done
    installed=no bstate=""
    if [ "$BR_TARGET" = none ]; then
      echo "php$branch: $before is $BR_VERDICT; no install ($BR_TREASON)"
    else
      echo "php$branch: $before -> $BR_TARGET for: $pkgs"
      # shellcheck disable=SC2046
      if apt-get -o DPkg::Lock::Timeout=600 -o Acquire::Retries=5 -o Dpkg::Options::=--force-confold \
        install -y -q --allow-downgrades $(for p in $pkgs; do printf '%s=%s ' "$p" "$BR_TARGET"; done) </dev/null; then
        installed=yes
        P2S_ROLLBACK+=("apt-get install --allow-downgrades $(for p in $pkgs; do printf '%s=%s ' "$p" "$before"; done)")
      else
        echo "apt-get install failed"
        bstate=apt-failed
        P2S_RC=1
      fi
    fi
    after=$(dpkg-query -W -f='${Version}' "$ppkg" </dev/null 2>/dev/null)
    # shellcheck disable=SC2086
    nver=$(dpkg-query -W -f='${Version}\n' $pkgs </dev/null 2>/dev/null | sort -u | grep -c .)
    [ "$nver" -le 1 ] || echo "WARNING: php$branch packages are on $nver different versions"
    cve=$(p2s_installed_cve "$branch")
    read -r vafter rafter <<<"$(p2s_verdict "$branch" "$after" "$(p2s_package_origin "$ppkg" "$after")" "$cve")"
    echo "php$branch now $after: $vafter ($rafter)"

    for row in "${running[@]}"; do
      IFS='|' read -r sapi pkg sbefore <<<"$row"
      unit=$(p2s_sapi_unit "$branch" "$sapi")
      safter=$(dpkg-query -W -f='${Version}' "$pkg" </dev/null 2>/dev/null)
      read -r svafter _ <<<"$(p2s_verdict "$branch" "$safter" "$(p2s_package_origin "$pkg" "$safter")" "$cve")"
      state=$bstate restart=skipped changed=$installed
      [ "${needed[$sapi]}" = needed ] && changed=yes
      if [ -z "$state" ]; then
        # The service is restarted below, so ensure only writes and tests; it does not reload.
        p2s_ensure_sapi "$host" "$branch" "$sapi" no
        [ "$P2S_EACTION" = test-failed ] && state=test-failed
        [ "$P2S_EACTION" = written ] && changed=yes
      fi
      ini85=""
      if [ -z "$state" ] && [ "$branch" = 8.5 ] && [ "$svafter" = unfixed ]; then
        # The fatal error backtrace path of CVE-2026-109619 exists only in 8.5; closed until a fixed build lands.
        ini85=$(p2s_path "/etc/php/8.5/$sapi/conf.d/99-php2shell-backtraces.ini")
        printf '%s: CVE-2026-109619 backtrace path, until PHP 8.5 is fixed.\nfatal_error_backtraces = 0\n' "$P2S_INI_MARKER" >"$ini85"
        P2S_ROLLBACK+=("rm ${ini85#"${P2S_ROOT:-}"} && systemctl restart $unit")
        changed=yes
        echo "php8.5 $sapi: fatal_error_backtraces = 0 written"
      fi
      if [ -z "$state" ] && [ "$changed" = no ]; then
        restart=not-needed
      elif [ -z "$state" ] && ! p2s_config_ok "$branch" "$sapi"; then
        [ -z "$ini85" ] || rm -f "$ini85"
        echo "php$branch $sapi: config test failed; $unit not restarted"
        state=test-failed
        P2S_RC=1
      fi
      if [ -z "$state" ] && [ "$changed" = yes ]; then
        systemctl restart "$unit" </dev/null
        if [ "$(systemctl is-active "$unit" </dev/null 2>/dev/null)" = active ]; then
          restart='done'
        else
          restart=failed state=$([ "$sapi" = fpm ] && echo pool-down || echo apache-down)
          echo "$unit is DOWN after its restart:"
          journalctl -u "$unit" -n 20 --no-pager </dev/null 2>&1
          P2S_RC=1
        fi
      fi
      if [ "$(p2s_sapi_modules "$branch" "$sapi")" = "${mbefore[$sapi]}" ]; then mods=same; else mods=changed; fi
      [ -n "$state" ] || state=$([ "$svafter" = fixed ] && echo fixed || echo unfixed-mitigated)
      if [ "$state" = unfixed-mitigated ] && [ "$P2S_RC" = 0 ]; then P2S_RC=3; fi
      p2s_record kind=fix host="$host" branch="$branch" before="$sbefore" after="$safter" target="$BR_TARGET" \
        fixed="$([ "$svafter" = fixed ] && echo yes || echo no)" restart="$restart" modules="$mods" state="$state" \
        sapi="$sapi" target_reason="$BR_TREASON"
    done
    # A SAPI that serves nothing now keeps running nothing: its packages moved with the branch, nothing more.
    for row in "${idle[@]}"; do
      IFS='|' read -r sapi pkg ver <<<"$row"
      safter=$(dpkg-query -W -f='${Version}' "$pkg" </dev/null 2>/dev/null)
      echo "php$branch $sapi is not running: not restarted"
      p2s_record kind=fix host="$host" branch="$branch" before="$ver" after="$safter" target="$BR_TARGET" fixed=- \
        restart=skipped modules=- state=not-running sapi="$sapi"
    done
  done

  echo "== http after"
  after_probe=$(p2s_probe)
  local name code acode pstate=unchanged
  if [ -z "$before_probe" ]; then
    pstate=no-sites
    echo "no sites found: nothing to compare"
  else
    while read -r name code; do
      acode=$(awk -v n="$name" '$1 == n {print $2}' <<<"$after_probe")
      p2s_record kind=probe host="$host" name="$name" before="$code" after="${acode:--}"
      [ "$code" = "$acode" ] || { pstate=changed; echo "$name: $code -> ${acode:--}"; }
    done <<<"$before_probe"
    [ "$pstate" = changed ] || echo "all $(grep -c . <<<"$before_probe") status codes unchanged"
  fi
  p2s_record kind=probe_summary host="$host" state="$pstate"
  if [ "$pstate" = changed ] && [ "$P2S_RC" = 0 ]; then P2S_RC=3; fi

  echo "== summary $host"
  echo "rollback:"
  echo "  tar xzf $backup -C /   # /etc/php as it was before this run, then restart the pools"
  [ ${#P2S_ROLLBACK[@]} -eq 0 ] || printf '  %s\n' "${P2S_ROLLBACK[@]}"
  echo "exit $P2S_RC"
  return "$P2S_RC"
}

# Print a run's log as it grows until its exit file appears, then mark it reported and exit with its code.
p2s_follow() { # $1 stamp
  local log=$P2S_STATE/fix-$1.log ex=$P2S_STATE/fix-$1.exit off=0 size code
  while :; do
    if [ -f "$log" ]; then
      size=$(stat -c %s "$log")
      if [ "$size" -gt "$off" ]; then tail -c +$((off + 1)) "$log" | head -c $((size - off)); off=$size; fi
    fi
    [ -e "$ex" ] && break
    if [ "$(systemctl is-active "php2shell-fix-$1" </dev/null 2>/dev/null)" != active ] && [ ! -e "$ex" ]; then
      sleep 2
      [ -e "$ex" ] && continue
      echo "STOP: unit php2shell-fix-$1 ended without an exit code; the log above is all there is"
      touch "$P2S_STATE/fix-$1.reported"
      exit 1
    fi
    sleep 1
  done
  code=$(cat "$ex")
  touch "$P2S_STATE/fix-$1.reported"
  echo "== patch run $1 finished: exit $code"
  exit "$code"
}

host=$(hostname </dev/null)
if [ "$(id -u </dev/null)" != 0 ]; then
  p2s_record kind=host host="$host" os="$(p2s_os)"
  echo "STOP: fix must run as root"
  exit 1
fi
mkdir -p "$P2S_STATE"
# One launcher at a time: two operators starting a patch together must not start two.
exec 9>"$P2S_STATE/lock"
flock -n 9 || { echo "STOP: another php2shell fix launcher is running on $host"; exit 1; }

cur=$(cat "$P2S_STATE/current" 2>/dev/null)
if [ -n "$cur" ] && [ ! -e "$P2S_STATE/fix-$cur.reported" ]; then
  if [ -e "$P2S_STATE/fix-$cur.exit" ]; then
    echo "== run $cur finished while nobody was watching; its log follows. No new patch was started."
  else
    echo "== attaching to run $cur, still going. No new patch was started."
  fi
  p2s_follow "$cur"
fi

# Milliseconds: a run started right after the last one was reported must not reuse its files.
stamp=$(date -u +%Y%m%dT%H%M%S%3NZ)
worker=$P2S_STATE/fix-$stamp.worker.sh
{
  echo '#!/bin/bash'
  printf 'export P2S_ROOT=%q\n' "${P2S_ROOT:-}"
  declare -p P2S_UPSTREAM_FIXED P2S_UBUNTU_FIXED P2S_ESM_ONLY P2S_NO_FIX P2S_FIXES_RELEASED P2S_SCHEMA P2S_INI_MARKER P2S_INI_LEGACY P2S_STATE
  declare -f
  printf 'p2s_fix_worker %q >>%q 2>&1\n' "$stamp" "$P2S_STATE/fix-$stamp.log"
  printf 'echo $? >%q.tmp && mv %q.tmp %q\n' "$P2S_STATE/fix-$stamp.exit" "$P2S_STATE/fix-$stamp.exit" "$P2S_STATE/fix-$stamp.exit"
} >"$worker"
echo "$stamp" >"$P2S_STATE/current"
# 9>&-: the unit must not hold the launcher lock, or the next launcher could not attach.
if ! systemd-run --unit="php2shell-fix-$stamp" --collect --quiet /bin/bash "$worker" </dev/null 9>&-; then
  echo "STOP: systemd-run could not start the patch unit"
  rm -f "$P2S_STATE/current"
  exit 1
fi
echo "== patch started as unit php2shell-fix-$stamp; it goes on if this connection drops"
p2s_follow "$stamp"
