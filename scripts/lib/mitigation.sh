# CVE-2026-115560 mitigation: session.upload_progress off in every web SAPI. Shared by audit.sh (inspects)
# and ensure.sh (writes). Sourced after p2s.sh. Covers FPM and CGI; CLI serves no web requests.

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

# Effective master value in a SAPI, from the SAPI binary itself: On | Off | unknown.
# php-fpm -i prints "key => local => master"; php-cgi -i prints an HTML table row.
p2s_upload_progress() { # $1 branch, $2 sapi (fpm|cgi)
  local bin out v
  case $2 in fpm) bin=php-fpm$1 ;; cgi) bin=php-cgi$1 ;; *) echo unknown; return ;; esac
  out=$("$bin" -i </dev/null 2>/dev/null) || { echo unknown; return; }
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

# Inspect one SAPI and print its records: one "override" per pool override, then one "mitigation".
# Sets P2S_MSTATE: mitigated | override | foreign | not-mitigated | unknown.
# $1 host, $2 branch, $3 sapi, $4 ini owner (p2s_ini_owner), $5 what ensure did (inspected for an audit)
p2s_mitigation_report() {
  local host=$1 branch=$2 sapi=$3 owner=$4 action=$5 value enabling=0 f l p d v e
  value=$(p2s_upload_progress "$branch" "$sapi")
  if [ "$sapi" = fpm ]; then
    while IFS='|' read -r f l p d v e; do
      [ -n "$f" ] || continue
      [ "$e" = yes ] && enabling=$((enabling + 1))
      p2s_record kind=override host="$host" branch="$branch" sapi="$sapi" file="${f#"${P2S_ROOT:-}"}" line="$l" \
        pool="$p" directive="$d" value="$v" enables="$e"
    done <<<"$(p2s_fpm_overrides "$branch")"
  fi
  if [ "$enabling" -gt 0 ]; then P2S_MSTATE=override
  elif [ "$owner" = foreign ]; then P2S_MSTATE=foreign
  elif [ "$value" = Off ]; then P2S_MSTATE=mitigated
  elif [ "$value" = On ]; then P2S_MSTATE=not-mitigated
  else P2S_MSTATE=unknown
  fi
  p2s_record kind=mitigation host="$host" branch="$branch" sapi="$sapi" ini="$owner" action="$action" \
    upload_progress="$value" overrides="$enabling" state="$P2S_MSTATE"
}

# Installed web SAPIs, one "branch sapi" per line (8.3 fpm), from php<X.Y>-fpm and php<X.Y>-cgi packages.
p2s_web_sapis() {
  dpkg-query -W -f='${db:Status-Abbrev}|${binary:Package}\n' 'php*-fpm' 'php*-cgi' </dev/null 2>/dev/null \
    | awk -F'|' '$1 ~ /^ii/ && $2 ~ /^php[0-9]+\.[0-9]+-(fpm|cgi)$/ {
        s = $2; sub(/^php/, "", s); split(s, a, "-"); print a[1], a[2] }' | sort -u
}
