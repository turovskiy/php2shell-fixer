# shellcheck shell=bash
# Read-only indicators of compromise since exploitation began (P2S_EXPLOIT_SINCE, versions.sh): crashes of the
# PHP SAPIs and Apache, shells and downloaders run by PHP, PHP files changed since. Signals for a person to
# review, never a verdict: a clean result is no proof (mtimes can be set back, logs rotated away), and a CMS
# update changes many PHP files. Every scan is bounded in time and output, to stay well inside the audit's
# per-host limit. Sourced after p2s.sh, mitigation.sh and hostfacts.sh; used by audit.sh.

# Lines on stdin to "<count>|<first>|<last>" for those stamped at or after $1 (YYYY-MM-DD); nothing when none.
# A timestamp is read in the formats these logs use: ISO 8601 (journalctl -o short-iso, dmesg --time-format
# iso), nginx 2026/10/27 10:00:00, PHP-FPM 27-Oct-2026 10:00:00, Apache Tue Oct 27 10:00:00.123456 2026. A
# line without one is not counted. No {n} intervals: mawk does not read them everywhere.
p2s_ioc_window() { # $1 since
  awk -v since="$1" '
    BEGIN { split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " "); for (i = 1; i <= 12; i++) mon[m[i]] = sprintf("%02d", i) }
    function stamp(l,   s, a) {
      if (match(l, /[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][T ][0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) {
        s = substr(l, RSTART, 19); sub(/ /, "T", s); return s }
      if (match(l, /[0-9][0-9][0-9][0-9]\/[0-9][0-9]\/[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) {
        s = substr(l, RSTART, 19); gsub(/\//, "-", s); sub(/ /, "T", s); return s }
      if (match(l, /[0-9][0-9]-[A-Z][a-z][a-z]-[0-9][0-9][0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) {
        s = substr(l, RSTART, RLENGTH); split(s, a, /[- ]/)
        return a[3] "-" mon[a[2]] "-" a[1] "T" a[4] }
      if (match(l, /[A-Z][a-z][a-z] [A-Z][a-z][a-z] [ 0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9][.0-9]* [0-9][0-9][0-9][0-9]/)) {
        s = substr(l, RSTART, RLENGTH); n = split(s, a, / +/)
        sub(/\..*/, "", a[4]); return a[5] "-" mon[a[2]] "-" sprintf("%02d", a[3]) "T" a[4] }
      return ""
    }
    { t = stamp($0); if (t == "" || substr(t, 1, 10) < since) next
      c++; if (first == "" || t < first) first = t; if (t > last) last = t }
    END { if (c) print c "|" first "|" last }'
}

# Crashes since $1, one "source|count|first|last" per source that has any: kernel (segfaults of php-fpm,
# php-cgi, lsphp, apache2 or httpd in journalctl -k, else dmesg), php-fpm ("exited on signal 11" in the
# PHP-FPM logs), apache (AH00052 Segmentation fault in Apache's error logs), php-fatal (the "Allowed memory
# size ... in Unknown on line 0" fatal the OOM path leaves, in the PHP-FPM, Apache and nginx error logs).
# Plain and .1 logs only; older ones are compressed and rarely reach back to the window anyway.
p2s_ioc_crashes() { # $1 since
  local since=$1 k l fpm apache nginx
  k=$(timeout 60 journalctl -k --since "$since" -o short-iso --no-pager -q </dev/null 2>/dev/null) \
    || k=$(timeout 30 dmesg --time-format iso </dev/null 2>/dev/null)
  l=$(grep -E '(php-fpm|php-cgi|lsphp|apache2|httpd)[^ ]*\[[0-9]+\]: segfault' <<<"$k" | p2s_ioc_window "$since")
  [ -z "$l" ] || echo "kernel|$l"
  fpm=$(p2s_path /var/log)
  apache=$(p2s_path /var/log/apache2)
  nginx=$(p2s_path /var/log/nginx)
  l=$(timeout 60 grep -hE 'exited on signal 11' "$fpm"/php*-fpm.log "$fpm"/php*-fpm.log.1 2>/dev/null </dev/null | p2s_ioc_window "$since")
  [ -z "$l" ] || echo "php-fpm|$l"
  l=$(timeout 60 grep -hE 'AH00052: .*Segmentation fault' "$apache"/*error.log "$apache"/*error.log.1 2>/dev/null </dev/null \
    | p2s_ioc_window "$since")
  [ -z "$l" ] || echo "apache|$l"
  l=$(timeout 60 grep -hE 'Allowed memory size of [0-9]+ bytes exhausted.* in Unknown on line 0' "$fpm"/php*-fpm.log \
    "$fpm"/php*-fpm.log.1 "$apache"/*error.log "$apache"/*error.log.1 "$nginx"/*error.log "$nginx"/*error.log.1 2>/dev/null </dev/null \
    | p2s_ioc_window "$since")
  [ -z "$l" ] || echo "php-fatal|$l"
}

# Live shells and downloaders whose parent is a PHP worker or Apache: one "pid|parent comm|args" per process.
# PHP that runs sh (mail() through sendmail, a cron wrapper) shows here too; it is for review.
p2s_ioc_shell_children() {
  ps -eo pid=,ppid=,comm=,args= 2>/dev/null | awk '
    { pid[NR] = $1; pp[NR] = $2; c[NR] = $3; a = $4; for (i = 5; i <= NF; i++) a = a " " $i; args[NR] = a; comm[$1] = $3 }
    END {
      for (i = 1; i <= NR; i++) {
        if (c[i] !~ /^(sh|bash|dash|nc|ncat|curl|wget|python[0-9.]*|perl)$/) continue
        p = comm[pp[i]]
        if (p ~ /^(php-fpm|php-cgi|lsphp|apache2|httpd)/) print pid[i] "|" p "|" args[i]
      }
    }'
}

# The directories a web request can reach PHP in: every nginx root and Apache DocumentRoot, then /tmp,
# /var/tmp and /dev/shm, where a dropped file lands first. One per line, each once, as the host sees them.
p2s_ioc_dirs() {
  local ngx f
  ngx=$(nginx -T </dev/null 2>/dev/null) || ngx=""
  {
    awk -F'|' '$1 == "R" {print $2}' <(p2s_nginx_php_settings "$ngx")
    while IFS= read -r f; do
      [ -f "$f" ] && awk 'tolower($1) == "documentroot" { v = $2; gsub(/"/, "", v); print v }' "$f"
    done < <(p2s_apache_conf_files 2>/dev/null)
    printf '%s\n' /tmp /var/tmp /dev/shm
  } | awk 'NF && !seen[$0]++'
}

# PHP files (*.php, *.phtml, *.phar) changed since $1 in each p2s_ioc_dirs directory, one
# "dir|<dir>|count|first|last|capped" per directory that has any, then "file|<mtime>|<path>" for the newest
# 50 overall. Stops at P2S_IOC_FILE_CAP files per directory (5000) and 60 s, and says so (capped=yes).
p2s_ioc_new_php() { # $1 since
  local since=$1 cap=${P2S_IOC_FILE_CAP:-5000} d all="" out n capped
  while IFS= read -r d; do
    [ -d "$(p2s_path "$d")" ] || continue
    out=$(timeout 60 find "$(p2s_path "$d")" -xdev -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' \) \
      -newermt "$since" -printf '%TY-%Tm-%TdT%TH:%TM:%TS|%p\n' 2>/dev/null </dev/null | head -n $((cap + 1)))
    [ -n "$out" ] || continue
    n=$(grep -c . <<<"$out")
    capped=no
    if [ "$n" -gt "$cap" ]; then out=$(head -n "$cap" <<<"$out"); n=$cap capped=yes; fi
    out=$(sed -E 's/^([^|]*)\.[0-9]+\|/\1|/' <<<"$out")
    echo "dir|$d|$n|$(cut -d'|' -f1 <<<"$out" | sort | head -1)|$(cut -d'|' -f1 <<<"$out" | sort | tail -1)|$capped"
    all+="$out"$'\n'
  done < <(p2s_ioc_dirs)
  grep . <<<"$all" | sort -r | head -50 | while IFS='|' read -r t f; do echo "file|$t|${f#"${P2S_ROOT:-}"}"; done
}
