# CVE-2026-115560 mitigation: session.upload_progress off in every web SAPI. Shared by audit.sh (inspects)
# and ensure.sh (writes). Sourced after p2s.sh. Covers FPM, mod_php (SAPI apache2) and CGI; CLI serves no web
# requests.

P2S_INI_MARKER='; Managed by php2shell-fixer'
# fix.sh wrote this comment on hosts patched before the plugin existed; such a file is ours too.
P2S_INI_LEGACY='PHP2Shell hardening'

# The 99-security.ini the plugin writes. No timestamp, so an unchanged host compares equal and stays untouched.
p2s_ini_content() {
  printf '%s: CVE-2026-115560 mitigation, also closes the session path of CVE-2026-109619.\n' "$P2S_INI_MARKER"
  printf '; Rollback: delete this file, then reload the SAPI (systemctl reload php<X.Y>-fpm).\n'
  printf 'session.upload_progress.enabled = 0\n'
}

# Who owns a 99-security.ini: absent | owned (plugin marker) | legacy (fix.sh comment) | foreign.
p2s_ini_owner() {
  if [ ! -e "$1" ]; then echo absent
  elif grep -qF -- "$P2S_INI_MARKER" "$1" 2>/dev/null; then echo owned
  elif grep -qF -- "$P2S_INI_LEGACY" "$1" 2>/dev/null; then echo legacy
  else echo foreign
  fi
}

# True when an ini file turns upload progress off.
p2s_ini_disables() {
  grep -qiE '^[[:space:]]*session\.upload_progress\.enabled[[:space:]]*=[[:space:]]*"?(0|off|false|no)"?[[:space:]]*$' "$1" 2>/dev/null
}

# The systemd unit that serves a SAPI: php<X.Y>-fpm for FPM, apache2 for mod_php, none for CGI.
p2s_sapi_unit() { # $1 branch, $2 sapi
  case $2 in fpm) echo "php$1-fpm" ;; apache2) echo apache2 ;; esac
}

# Does Apache load the branch's mod_php? Debian enables it as mods-enabled/php<X.Y>.load.
p2s_modphp_loaded() { # $1 branch
  [ -e "$(p2s_path "/etc/apache2/mods-enabled/php$1.load")" ]
}

# Does the SAPI serve requests now: its unit is active and, for mod_php, Apache loads the module.
p2s_sapi_running() { # $1 branch, $2 sapi
  local unit
  unit=$(p2s_sapi_unit "$1" "$2")
  [ -n "$unit" ] || return 1
  [ "$2" != apache2 ] || p2s_modphp_loaded "$1" || return 1
  [ "$(systemctl is-active "$unit" </dev/null 2>/dev/null)" = active ]
}

# The branch's CLI binary with Apache's php.ini and conf.d: mod_php has no binary of its own to ask, and
# libapache2-mod-php depends on the CLI of its branch.
p2s_php_apache2() { # $1 branch, then php arguments
  local b=$1
  shift
  PHP_INI_SCAN_DIR=$(p2s_path "/etc/php/$b/apache2/conf.d") "php$b" -c "$(p2s_path "/etc/php/$b/apache2/php.ini")" "$@" </dev/null
}

# Effective master value in a SAPI, from the SAPI binary itself: On | Off | unknown.
# php-fpm -i and php -i print "key => local => master"; php-cgi -i prints an HTML table row.
p2s_upload_progress() { # $1 branch, $2 sapi (fpm|cgi|apache2)
  local out v
  case $2 in
    fpm) out=$("php-fpm$1" -i </dev/null 2>/dev/null) ;;
    cgi) out=$("php-cgi$1" -i </dev/null 2>/dev/null) ;;
    apache2) out=$(p2s_php_apache2 "$1" -i 2>/dev/null) ;;
    *) false ;;
  esac || { echo unknown; return; }
  v=$(sed -nE 's/<[^>]*>/ /g; s/^[[:space:]]*session\.upload_progress\.enabled[[:space:]]+(=>[[:space:]]*)?([A-Za-z]+).*/\2/p' <<<"$out" | head -1)
  case $v in On | Off) echo "$v" ;; *) echo unknown ;; esac
}

# Pool-level overrides of session.upload_progress.enabled in an FPM branch, one per line:
# file|line|pool|directive|value|enables (yes when the override turns it back on).
p2s_fpm_overrides() { # $1 branch
  local f
  for f in "$(p2s_path "/etc/php/$1/fpm/php-fpm.conf")" "$(p2s_path "/etc/php/$1/fpm/pool.d")"/*.conf; do
    [ -f "$f" ] || continue
    awk -v file="$f" '
      /^[[:space:]]*\[[^]]+\][[:space:]]*$/ { pool = $0; gsub(/[][[:space:]]/, "", pool); next }
      /^[[:space:]]*php_(admin_)?(value|flag)\[session\.upload_progress\.enabled\][[:space:]]*=/ {
        line = $0
        directive = line; sub(/^[[:space:]]*/, "", directive); sub(/\[.*/, "", directive)
        value = line; sub(/^[^=]*=[[:space:]]*/, "", value); sub(/[[:space:]]*(;.*)?$/, "", value); gsub(/"/, "", value)
        enables = (tolower(value) ~ /^(1|on|true|yes)$/) ? "yes" : "no"
        printf "%s|%d|%s|%s|%s|%s\n", file, NR, (pool == "" ? "-" : pool), directive, value, enables
      }' "$f"
  done
}

# The Apache config files, one per line: every file Apache reads, from its own include dump (apachectl -t
# -D DUMP_INCLUDES, so a custom Include counts), else the files Debian's apache2.conf includes: apache2.conf
# and *.conf in mods-enabled, conf-enabled and sites-enabled. Paths carry the root prefix.
p2s_apache_conf_files() {
  local a out f
  if out=$(apachectl -t -D DUMP_INCLUDES </dev/null 2>/dev/null) && grep -q '^Included configuration files:' <<<"$out"; then
    sed -nE 's/^[[:space:]]*\((\*|[0-9]+)\) (\/.*)$/\2/p' <<<"$out" | awk '!seen[$0]++' \
      | while IFS= read -r f; do p2s_path "$f"; echo; done
    return
  fi
  a=$(p2s_path /etc/apache2)
  printf '%s\n' "$a/apache2.conf" "$a"/mods-enabled/*.conf "$a"/conf-enabled/*.conf "$a"/sites-enabled/*.conf
}

# Apache-level overrides of session.upload_progress.enabled, in the same format as p2s_fpm_overrides with
# pool "-". Apache reads them for mod_php only. Scans the files of p2s_apache_conf_files, read through their
# symlinks. Apache directive names are case-insensitive; .htaccess files are not scanned.
p2s_apache_overrides() {
  local f
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    awk -v file="$f" '
      tolower($1) ~ /^php_(admin_)?(value|flag)$/ && $2 == "session.upload_progress.enabled" {
        value = $3; gsub(/"/, "", value)
        enables = (tolower(value) ~ /^(1|on|true|yes)$/) ? "yes" : "no"
        printf "%s|%d|-|%s|%s|%s\n", file, NR, tolower($1), value, enables
      }' "$f"
  done < <(p2s_apache_conf_files)
}

# Overrides that apply to a SAPI: pool configs for FPM, Apache config for a mod_php Apache loads.
p2s_overrides() { # $1 branch, $2 sapi
  case $2 in
    fpm) p2s_fpm_overrides "$1" ;;
    apache2) if p2s_modphp_loaded "$1"; then p2s_apache_overrides; fi ;;
  esac
}

# Inspect one SAPI and print its records: one "override" per pool or Apache override, then one "mitigation".
# Sets P2S_MSTATE: mitigated | override | foreign | not-mitigated | unknown.
# $1 host, $2 branch, $3 sapi, $4 ini owner (p2s_ini_owner), $5 what ensure did (inspected for an audit)
p2s_mitigation_report() {
  local host=$1 branch=$2 sapi=$3 owner=$4 action=$5 value enabling=0 f l p d v e
  value=$(p2s_upload_progress "$branch" "$sapi")
  while IFS='|' read -r f l p d v e; do
    [ -n "$f" ] || continue
    if [ "$e" = yes ]; then
      enabling=$((enabling + 1))
      echo "php$branch $sapi: ${f#"${P2S_ROOT:-}"}:$l ($d $v) turns upload progress back on"
    fi
    p2s_record kind=override host="$host" branch="$branch" sapi="$sapi" file="${f#"${P2S_ROOT:-}"}" line="$l" \
      pool="$p" directive="$d" value="$v" enables="$e"
  done <<<"$(p2s_overrides "$branch" "$sapi")"
  if [ "$enabling" -gt 0 ]; then P2S_MSTATE=override
  elif [ "$owner" = foreign ]; then P2S_MSTATE=foreign
  elif [ "$value" = Off ]; then P2S_MSTATE=mitigated
  elif [ "$value" = On ]; then P2S_MSTATE=not-mitigated
  else P2S_MSTATE=unknown
  fi
  p2s_record kind=mitigation host="$host" branch="$branch" sapi="$sapi" ini="$owner" action="$action" \
    upload_progress="$value" overrides="$enabling" state="$P2S_MSTATE"
}

# Installed web SAPIs, one "branch sapi" per line (8.3 fpm), from the php<X.Y>-fpm, php<X.Y>-cgi and
# libapache2-mod-php<X.Y> (SAPI apache2) packages.
p2s_web_sapis() {
  dpkg-query -W -f='${db:Status-Abbrev}|${binary:Package}\n' 'php*-fpm' 'php*-cgi' 'libapache2-mod-php*' </dev/null 2>/dev/null \
    | awk -F'|' '$1 !~ /^ii/ { next }
      $2 ~ /^php[0-9]+\.[0-9]+-(fpm|cgi)$/ { s = $2; sub(/^php/, "", s); split(s, a, "-"); print a[1], a[2] }
      $2 ~ /^libapache2-mod-php[0-9]+\.[0-9]+$/ { s = $2; sub(/^libapache2-mod-php/, "", s); print s, "apache2" }' | sort -u
}

# Does the SAPI still load its config? FPM has a config test, mod_php has Apache's; CGI has none, so the
# binary must at least start without an ini error. Prints the tail of the output on failure.
p2s_config_ok() { # $1 branch, $2 sapi
  local out
  case $2 in
    fpm) out=$(php-fpm"$1" -t </dev/null 2>&1) ;;
    apache2) out=$(apachectl configtest </dev/null 2>&1) ;;
    cgi) out=$(php-cgi"$1" -v </dev/null 2>&1) && ! grep -qiE 'parse error|syntax error' <<<"$out" ;;
  esac || { echo "$out" | tail -5; return 1; }
}

# Put the mitigation in place for one SAPI and print its records. $1 host, $2 branch, $3 sapi, $4 reload
# (yes: reload a running FPM pool, or Apache loading the mod_php, whose ini changed; no: the caller restarts
# it).
# Uses the caller's P2S_RC (raised to 1 on a failed test or reload, to 3 when the SAPI is not mitigated)
# and appends to the caller's P2S_ROLLBACK array. Sets P2S_EACTION and P2S_MSTATE.
p2s_ensure_sapi() {
  local host=$1 branch=$2 sapi=$3 reload=$4 dir ini owner had=no prev="" unit
  dir=$(p2s_path "/etc/php/$branch/$sapi/conf.d")
  ini=$dir/99-security.ini
  owner=$(p2s_ini_owner "$ini")
  P2S_EACTION=unchanged
  if [ ! -d "$dir" ]; then
    P2S_EACTION=no-conf-dir
  elif [ "$owner" = foreign ]; then
    P2S_EACTION=left-foreign
  elif [ "$owner" = legacy ] && p2s_ini_disables "$ini"; then
    P2S_EACTION=adopted
  elif [ "$(cat "$ini" 2>/dev/null)" != "$(p2s_ini_content)" ]; then
    [ -e "$ini" ] && { had=yes; prev=$(cat "$ini"); }
    p2s_ini_content >"$ini"
    if p2s_config_ok "$branch" "$sapi"; then
      P2S_EACTION=written
      unit=$(p2s_sapi_unit "$branch" "$sapi")
      if [ -n "$unit" ]; then
        if [ "$reload" != yes ]; then
          :
        elif ! p2s_sapi_running "$branch" "$sapi"; then
          P2S_EACTION=written-not-running
        elif ! systemctl reload "$unit" </dev/null; then
          P2S_EACTION=reload-failed
          P2S_RC=1
        fi
        P2S_ROLLBACK+=("rm ${ini#"${P2S_ROOT:-}"} && systemctl reload $unit")
      else
        P2S_ROLLBACK+=("rm ${ini#"${P2S_ROOT:-}"}")
      fi
      [ "$had" = yes ] && P2S_ROLLBACK[-1]="restore the previous ${ini#"${P2S_ROOT:-}"} (content above), then reload"
    else
      # Roll back before anything reloads: the running pool keeps its old config.
      if [ "$had" = yes ]; then printf '%s\n' "$prev" >"$ini"; else rm -f "$ini"; fi
      P2S_EACTION=test-failed
      P2S_RC=1
    fi
    [ "$had" = yes ] && { echo "previous $ini:"; printf '%s\n' "$prev" | sed 's/^/  | /'; }
  fi
  p2s_mitigation_report "$host" "$branch" "$sapi" "$owner" "$P2S_EACTION"
  echo "php$branch $sapi: 99-security.ini $owner, $P2S_EACTION -> $P2S_MSTATE"
  if [ "$P2S_MSTATE" != mitigated ] && [ "$P2S_RC" = 0 ]; then P2S_RC=3; fi
}

# The apt hook: after every dpkg run, apt calls a local copy of ensure, so a PHP branch installed later gets
# its 99-security.ini too. Two files, both generated here so audit and ensure build the same reference.
P2S_HOOK_SCRIPT=/usr/local/sbin/php2shell-ensure
P2S_HOOK_CONF=/etc/apt/apt.conf.d/99php2shell-ensure
P2S_HOOK_LOG=/var/log/php2shell-ensure.log

# What the hook script runs: ensure on every web SAPI, logged, and exit 0 whatever happens, because apt's
# own result must never depend on it.
p2s_hook_run() {
  local host branch sapi log
  # A log that cannot be opened must not stop the mitigation: bash skips a block whose redirection fails.
  log=$(p2s_path "$P2S_HOOK_LOG")
  mkdir -p "${log%/*}" 2>/dev/null
  touch "$log" 2>/dev/null || log=/dev/null
  {
    host=$(hostname </dev/null)
    echo "== $(date -u +%Y-%m-%dT%H:%M:%SZ) php2shell ensure from the apt hook on $host"
    P2S_RC=0 P2S_ROLLBACK=()
    while read -r branch sapi; do
      [ -n "$branch" ] || continue
      p2s_ensure_sapi "$host" "$branch" "$sapi" yes
    done <<<"$(p2s_web_sapis)"
    [ "$P2S_RC" = 0 ] || echo "ensure finished with exit $P2S_RC: see the records above"
  } >>"$log" 2>&1
  return 0
}

# The hook script, from a fixed list of functions so every bundle that holds mitigation.sh builds it alike.
p2s_hook_script() {
  echo '#!/bin/bash'
  echo '# Managed by php2shell-fixer; "run.sh ensure <host>" writes and updates it. apt calls it after every'
  echo "# dpkg run ($P2S_HOOK_CONF) to put the CVE-2026-115560 mitigation on every web SAPI, PHP branches"
  echo '# installed later included. It never fails: apt must not depend on it. Log:' "$P2S_HOOK_LOG"
  printf 'export P2S_ROOT=%q\n' "${P2S_ROOT:-}"
  declare -p P2S_SCHEMA P2S_INI_MARKER P2S_INI_LEGACY P2S_HOOK_LOG
  declare -f p2s_path p2s_record p2s_os p2s_ini_content p2s_ini_owner p2s_ini_disables p2s_sapi_unit \
    p2s_modphp_loaded p2s_sapi_running p2s_php_apache2 p2s_upload_progress p2s_fpm_overrides p2s_apache_overrides \
    p2s_overrides p2s_mitigation_report \
    p2s_web_sapis p2s_config_ok p2s_ensure_sapi p2s_hook_run
  echo 'export LC_ALL=C'
  echo 'p2s_hook_run'
  echo 'exit 0'
}

p2s_hook_conf() {
  echo '// Managed by php2shell-fixer: re-applies the CVE-2026-115560 mitigation after every dpkg run.'
  echo "// Rollback: rm $P2S_HOOK_CONF $P2S_HOOK_SCRIPT"
  echo "DPkg::Post-Invoke { \"if [ -x $P2S_HOOK_SCRIPT ]; then timeout 120 $P2S_HOOK_SCRIPT || true; fi\"; };"
}

# present | missing | outdated: the installed hook against what this plugin version writes.
p2s_hook_state() {
  local s c
  s=$(p2s_path "$P2S_HOOK_SCRIPT") c=$(p2s_path "$P2S_HOOK_CONF")
  if [ ! -e "$s" ] && [ ! -e "$c" ]; then echo missing
  elif [ "$(cat "$s" 2>/dev/null)" = "$(p2s_hook_script)" ] && [ "$(cat "$c" 2>/dev/null)" = "$(p2s_hook_conf)" ]; then echo present
  else echo outdated
  fi
}

# Write the hook where it is missing or outdated. Sets P2S_HOOK_ACTION: installed | updated | unchanged | failed.
p2s_hook_install() {
  local state s c
  state=$(p2s_hook_state)
  s=$(p2s_path "$P2S_HOOK_SCRIPT") c=$(p2s_path "$P2S_HOOK_CONF")
  if [ "$state" = present ]; then
    P2S_HOOK_ACTION=unchanged
    return 0
  fi
  if mkdir -p "$(dirname "$s")" "$(dirname "$c")" && p2s_hook_script >"$s.new" && chmod 755 "$s.new" && mv "$s.new" "$s" \
    && p2s_hook_conf >"$c.new" && mv "$c.new" "$c"; then
    P2S_HOOK_ACTION=$([ "$state" = missing ] && echo installed || echo updated)
  else
    rm -f "$s.new" "$c.new"
    P2S_HOOK_ACTION=failed
  fi
}

