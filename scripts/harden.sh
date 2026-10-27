# shellcheck shell=bash
# Opt-in stopgap for branches that stay unfixed (CVE-2026-109618's OOM path): never run by fix or ensure, and
# only for a branch whose installed build the same judgement as the audit finds unfixed. Per SAPI:
# - PHP-FPM: in every pool of the branch a marked block with php_admin_value[memory_limit] = -1 and
#   pm.max_requests = 1 (the pool's own pm.max_requests commented out), each pool file backed up first; then
#   php-fpm<X.Y> -t, and on failure every pool file of the branch put back and nothing restarted;
# - mod_php: /etc/apache2/conf-available/php2shell-harden.conf with php_admin_value memory_limit -1, a2enconf,
#   apachectl configtest (on failure disabled and removed again); prefork has no per-request recycling;
# - both: a systemd drop-in with MemoryMax=${P2S_MEMORY_MAX:-75%} on the service, unless the unit already has a
#   MemoryMax (reported, left alone); an RLIMIT_AS or RLIMIT_DATA on it is reported too, never set.
# The service restarts only when something of its own changed. A rerun on a hardened host writes nothing.
# Runs as the tail of the bundle from run.sh (after versions.sh, p2s.sh, mitigation.sh, hostfacts.sh,
# branch.sh, pins.sh, harden.sh): run.sh harden <host>
# Exit: 0 hardened, already in place, or nothing unfixed; 1 not root, a write or backup failed, a config test
#       failed (changes put back) or the service is down after its restart.
set -u
export LC_ALL=C

host=$(hostname </dev/null)
echo "== php2shell harden: $host ($(p2s_os))"
p2s_record kind=host host="$host" os="$(p2s_os)"
if [ "$(id -u </dev/null)" != 0 ]; then
  echo "STOP: harden must run as root"
  exit 1
fi
P2S_RC=0 P2S_ROLLBACK=()
P2S_TMP=$(mktemp -d)
trap 'rm -rf "$P2S_TMP"' EXIT

# The MemoryMax drop-in of a unit. Sets HD_CHANGED=yes when it wrote one; prints what the unit has.
harden_dropin() { # $1 unit
  local unit=$1 d mm las ldata
  d=$(p2s_harden_dropin "$unit")
  read -r mm las ldata <<<"$(p2s_unit_limits "$unit")"
  [ "$las" = infinity ] && [ "$ldata" = infinity ] \
    || echo "WARNING: $unit has LimitAS=$las LimitDATA=$ldata: an address-space or data limit triggers the OOM path itself; left alone"
  if [ "$(cat "$(p2s_path "$d")" 2>/dev/null)" = "$(p2s_harden_dropin_content "$unit")" ]; then
    HD_STATE=${P2S_MEMORY_MAX:-75%}
  elif [ ! -e "$(p2s_path "$d")" ] && [ "$mm" != infinity ]; then
    echo "$unit already has MemoryMax=$mm: left alone"
    HD_STATE=existing:$mm
  elif p2s_write_file "$d" "$(p2s_harden_dropin_content "$unit")"; then
    systemctl daemon-reload </dev/null
    HD_CHANGED=yes HD_STATE=${P2S_MEMORY_MAX:-75%}
    P2S_ROLLBACK+=("rm $d && systemctl daemon-reload && systemctl restart $unit")
    echo "$unit: MemoryMax=${P2S_MEMORY_MAX:-75%} in $d"
  else
    echo "STOP: could not write $d"
    HD_STATE=failed
    P2S_RC=1
  fi
}

# Restart a unit whose config changed; 1 when it is not active afterwards.
harden_restart() { # $1 unit
  systemctl restart "$1" </dev/null
  if [ "$(systemctl is-active "$1" </dev/null 2>/dev/null)" != active ]; then
    echo "$1 is DOWN after its restart:"
    journalctl -u "$1" -n 20 --no-pager </dev/null 2>&1
    return 1
  fi
}

harden_fpm() { # $1 branch
  local b=$1 unit=php$1-fpm f new bk wrote=() state=hardened n
  HD_CHANGED=no HD_STATE=-
  n=${#P2S_ROLLBACK[@]}
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    new=$(p2s_harden_pool_content "$f")
    [ "$new" != "$(cat "$f")" ] || continue
    if ! bk=$(p2s_backup "${f#"${P2S_ROOT:-}"}"); then
      echo "STOP: could not back up ${f#"${P2S_ROOT:-}"} to $P2S_BACKUP_DIR"
      state=backup-failed P2S_RC=1
      break
    fi
    if ! p2s_write_file "${f#"${P2S_ROOT:-}"}" "$new"; then
      echo "STOP: could not write ${f#"${P2S_ROOT:-}"}"
      state=write-failed P2S_RC=1
      break
    fi
    wrote+=("$bk|${f#"${P2S_ROOT:-}"}")
    P2S_ROLLBACK+=("cp $bk ${f#"${P2S_ROOT:-}"}   # pool file of php$b, then: systemctl restart $unit")
    echo "php$b fpm: harden block written to ${f#"${P2S_ROOT:-}"} (backup $bk)"
    HD_CHANGED=yes
  done <<<"$(p2s_harden_pool_files "$b")"
  if [ "$state" = hardened ] && [ "$HD_CHANGED" = yes ] && ! p2s_config_ok "$b" fpm; then
    state=test-failed P2S_RC=1
  fi
  if [ "$state" != hardened ]; then
    # Every pool file of the branch as it was; the running pool never saw the change.
    for f in "${wrote[@]}"; do p2s_restore_file "${f%%|*}" "${f#*|}"; done
    P2S_ROLLBACK=("${P2S_ROLLBACK[@]:0:$n}")
    echo "php$b fpm: $state; pool files put back, $unit not restarted"
    p2s_record kind=harden host="$host" branch="$b" sapi=fpm memory_limit=- max_requests=- memory_max=- state="$state"
    return
  fi
  harden_dropin "$unit"
  if [ "$HD_CHANGED" = yes ] && [ "$(systemctl is-active "$unit" </dev/null 2>/dev/null)" = active ]; then
    harden_restart "$unit" || { state=pool-down P2S_RC=1; }
  fi
  [ "$HD_CHANGED" = yes ] || state=unchanged
  p2s_record kind=harden host="$host" branch="$b" sapi=fpm memory_limit=-1 max_requests=1 memory_max="$HD_STATE" state="$state"
  echo "php$b fpm: memory_limit -1 (admin), pm.max_requests 1, MemoryMax $HD_STATE: $state"
}

harden_apache() { # $1 branch
  local b=$1 c state=hardened had=no prev=""
  HD_CHANGED=no HD_STATE=-
  c=$(p2s_path "$P2S_HARDEN_APACHE")
  if [ "$(cat "$c" 2>/dev/null)" != "$(p2s_harden_apache_content)" ] || [ ! -e "$(p2s_path /etc/apache2/conf-enabled/php2shell-harden.conf)" ]; then
    [ -e "$c" ] && { had=yes; prev=$(cat "$c"); }
    if ! p2s_write_file "$P2S_HARDEN_APACHE" "$(p2s_harden_apache_content)" || ! a2enconf -q php2shell-harden </dev/null; then
      state=write-failed P2S_RC=1
    elif ! p2s_config_ok "$b" apache2; then
      state=test-failed P2S_RC=1
    else
      HD_CHANGED=yes
      P2S_ROLLBACK+=("a2disconf php2shell-harden && rm $P2S_HARDEN_APACHE && systemctl restart apache2")
      echo "php$b apache2: memory_limit -1 as php_admin_value in $P2S_HARDEN_APACHE, enabled"
    fi
    if [ "$state" != hardened ]; then
      a2disconf -q php2shell-harden </dev/null >/dev/null 2>&1
      if [ "$had" = yes ]; then printf '%s\n' "$prev" >"$c"; else rm -f "$c"; fi
      echo "php$b apache2: $state; $P2S_HARDEN_APACHE taken out again, Apache not restarted"
      p2s_record kind=harden host="$host" branch="$b" sapi=apache2 memory_limit=- max_requests=- memory_max=- state="$state"
      return
    fi
  fi
  echo "php$b apache2: prefork has no per-request recycling; MaxConnectionsPerChild is left as it is"
  harden_dropin apache2
  if [ "$HD_CHANGED" = yes ] && [ "$(systemctl is-active apache2 </dev/null 2>/dev/null)" = active ]; then
    harden_restart apache2 || { state=apache-down P2S_RC=1; }
  fi
  [ "$HD_CHANGED" = yes ] || state=unchanged
  p2s_record kind=harden host="$host" branch="$b" sapi=apache2 memory_limit=-1 max_requests=- memory_max="$HD_STATE" state="$state"
  echo "php$b apache2: memory_limit -1 (admin), MemoryMax $HD_STATE: $state"
}

pkgs=$(p2s_branch_packages)
[ -n "$pkgs" ] || echo "no PHP-FPM or mod_php branch installed"
while IFS='|' read -r branch sapi pkg ver; do
  [ -n "$branch" ] || continue
  # The same judgement as the audit: harden is for a branch whose installed build is still vulnerable.
  p2s_branch_eval "$host" "$branch" "$ver" "$pkg" "$sapi"
  if [ "$BR_VERDICT" != unfixed ]; then
    echo "php$branch $sapi: $ver is $BR_VERDICT; nothing written"
    p2s_record kind=harden host="$host" branch="$branch" sapi="$sapi" memory_limit=- max_requests=- memory_max=- state="skipped-$BR_VERDICT"
    continue
  fi
  case $sapi in
    fpm) harden_fpm "$branch" ;;
    apache2) harden_apache "$branch" ;;
  esac
done <<<"$pkgs"

echo "== summary $host"
if [ ${#P2S_ROLLBACK[@]} -gt 0 ]; then
  echo "rollback:"
  printf '  %s\n' "${P2S_ROLLBACK[@]}"
fi
echo "exit $P2S_RC"
exit "$P2S_RC"
