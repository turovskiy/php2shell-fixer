# shellcheck shell=bash
# Opt-in compensating controls for a branch that stays unfixed: the OOM path of CVE-2026-109618, which the
# upload_progress mitigation does not close. memory_limit -1 as php_admin_value (a plain ini value is undone
# by ini_set(), WordPress's WP_MEMORY_LIMIT among others), each FPM worker recycled after one request
# (pm.max_requests = 1), and a cgroup MemoryMax on the service so one request cannot take the host's RAM.
# Never RLIMIT_AS or RLIMIT_DATA: they trigger the same OOM path. Shared by harden.sh (writes) and audit.sh
# (reports what is in place). Sourced after p2s.sh.

P2S_HARDEN_MARK='; php2shell-fixer harden (CVE-2026-109618) until a fixed build is installed'
P2S_HARDEN_END='; php2shell-fixer harden end'
# A line of the pool's own that harden replaces is kept, commented, after this prefix.
P2S_HARDEN_WAS=';php2shell-fixer-was: '
P2S_HARDEN_APACHE=/etc/apache2/conf-available/php2shell-harden.conf

# A pool file with the harden block at the end of every pool section ([global] is not a pool) and the
# section's own pm.max_requests lines commented out. An existing block is dropped and written again, so the
# result is the same however often it runs.
p2s_harden_pool_content() { # $1 pool file (root-prefixed)
  awk -v mark="$P2S_HARDEN_MARK" -v end="$P2S_HARDEN_END" -v was="$P2S_HARDEN_WAS" '
    function close_pool() {
      if (pool != "" && pool != "global") {
        print mark; print "php_admin_value[memory_limit] = -1"; print "pm.max_requests = 1"; print end
      }
    }
    $0 == mark { inblock = 1; next }
    inblock { if ($0 == end) inblock = 0; next }
    /^[[:space:]]*\[[^]]+\][[:space:]]*$/ { close_pool(); pool = $0; gsub(/[][[:space:]]/, "", pool); print; next }
    pool != "" && pool != "global" && /^[[:space:]]*pm\.max_requests[[:space:]]*=/ { print was $0; next }
    { print }
    END { close_pool() }' "$1"
}

# The FPM config files of a branch that hold a pool section, one per line, root-prefixed.
p2s_harden_pool_files() { # $1 branch
  local f
  for f in "$(p2s_path "/etc/php/$1/fpm/php-fpm.conf")" "$(p2s_path "/etc/php/$1/fpm/pool.d")"/*.conf; do
    [ -f "$f" ] && grep -E '^[[:space:]]*\[[^]]+\][[:space:]]*$' "$f" | grep -vqE '\[global\]' && echo "$f"
  done
}

p2s_harden_dropin() { echo "/etc/systemd/system/$1.service.d/php2shell-memory.conf"; }   # $1 unit
p2s_harden_dropin_content() { # $1 unit
  echo '# Managed by php2shell-fixer harden (CVE-2026-109618): a runaway request is killed by the cgroup OOM'
  echo '# killer instead of taking the host'"'"'s RAM.'
  echo "# Rollback: rm $(p2s_harden_dropin "$1") && systemctl daemon-reload && systemctl restart $1"
  echo '[Service]'
  echo "MemoryMax=${P2S_MEMORY_MAX:-75%}"
}
p2s_harden_apache_content() {
  echo '# Managed by php2shell-fixer harden (CVE-2026-109618): memory_limit as an admin value, so ini_set() cannot'
  echo "# raise it again. Rollback: a2disconf php2shell-harden && rm $P2S_HARDEN_APACHE && systemctl restart apache2"
  echo '<IfModule mod_php.c>'
  echo '    php_admin_value memory_limit -1'
  echo '</IfModule>'
  echo '<IfModule mod_php7.c>'
  echo '    php_admin_value memory_limit -1'
  echo '</IfModule>'
}

# The unit's own memory and resource limits: "MemoryMax LimitAS LimitDATA", "infinity" where unset.
p2s_unit_limits() { # $1 unit
  systemctl show -p MemoryMax -p LimitAS -p LimitDATA "$1" </dev/null 2>/dev/null | awk -F= '
    { v[$1] = $2 }
    END { printf "%s %s %s\n", (v["MemoryMax"] == "" ? "infinity" : v["MemoryMax"]),
      (v["LimitAS"] == "" ? "infinity" : v["LimitAS"]), (v["LimitDATA"] == "" ? "infinity" : v["LimitDATA"]) }'
}

# What harden has in place for a SAPI: "memory_limit max_requests memory_max", "-" for each part not in place.
p2s_harden_state() { # $1 branch, $2 sapi
  local f ml=- mr=- mm=- unit d
  case $2 in
    fpm)
      unit=php$1-fpm
      while IFS= read -r f; do
        [ -n "$f" ] && grep -qxF -- "$P2S_HARDEN_MARK" "$f" && ml=-1 mr=1
      done <<<"$(p2s_harden_pool_files "$1")" ;;
    apache2)
      unit=apache2
      [ -e "$(p2s_path /etc/apache2/conf-enabled/php2shell-harden.conf)" ] && ml=-1 ;;
    *) echo "- - -"; return ;;
  esac
  d=$(p2s_path "$(p2s_harden_dropin "$unit")")
  [ -f "$d" ] && mm=$(sed -nE 's/^MemoryMax=(.*)$/\1/p' "$d" | tail -1)
  echo "$ml $mr ${mm:--}"
}
