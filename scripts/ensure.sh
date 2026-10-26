# Keeps the CVE-2026-115560 mitigation in place: session.upload_progress off in every web SAPI (FPM, CGI)
# of every installed PHP branch. Writes 99-security.ini where it is missing or outdated, leaves CLI and
# foreign files alone, and reloads only the FPM pools whose config changed. Idempotent.
# Runs as the tail of the bundle from run.sh (after versions.sh, p2s.sh, mitigation.sh): run.sh ensure <host>
# Exit: 0 every web SAPI mitigated; 3 an override re-enables it, a foreign 99-security.ini, or a SAPI still
#       On or unknown; 1 not root, a config test failed (change rolled back) or a reload failed.
set -u
export LC_ALL=C

host=$(hostname </dev/null)
echo "== php2shell ensure: $host ($(p2s_os))"
p2s_record kind=host host="$host" os="$(p2s_os)"
if [ "$(id -u </dev/null)" != 0 ]; then
  echo "STOP: ensure must run as root"
  exit 1
fi

rc=0
rollback=()
fail() { rc=1; }
needs_operator() { [ "$rc" = 0 ] && rc=3; }

# Does the SAPI still load its config after the change? FPM has a config test; CGI has none, so the
# binary must at least start without an ini error.
config_ok() { # $1 branch, $2 sapi
  local out
  case $2 in
    fpm) out=$(php-fpm"$1" -t </dev/null 2>&1) ;;
    cgi) out=$(php-cgi"$1" -v </dev/null 2>&1) && ! grep -qiE 'parse error|syntax error' <<<"$out" ;;
  esac || { echo "$out" | tail -5; return 1; }
}

sapis=$(p2s_web_sapis)
[ -n "$sapis" ] || echo "no PHP-FPM or PHP-CGI installed"
while read -r branch sapi; do
  [ -n "$branch" ] || continue
  dir=$(p2s_path "/etc/php/$branch/$sapi/conf.d")
  ini=$dir/99-security.ini
  owner=$(p2s_ini_owner "$ini")
  action=unchanged
  if [ ! -d "$dir" ]; then
    action=no-conf-dir
  elif [ "$owner" = foreign ]; then
    action=left-foreign
  elif [ "$owner" = legacy ] && p2s_ini_disables "$ini"; then
    action=adopted
  elif [ "$(cat "$ini" 2>/dev/null)" != "$(p2s_ini_content)" ]; then
    had=no
    [ -e "$ini" ] && { had=yes; prev=$(cat "$ini"); }
    p2s_ini_content >"$ini"
    if config_ok "$branch" "$sapi"; then
      action=written
      if [ "$sapi" = fpm ]; then
        if [ "$(systemctl is-active "php$branch-fpm" </dev/null 2>/dev/null)" != active ]; then
          action=written-not-running
        elif ! systemctl reload "php$branch-fpm" </dev/null; then
          action=reload-failed
          fail
        fi
        rollback+=("rm ${ini#"${P2S_ROOT:-}"} && systemctl reload php$branch-fpm")
      else
        rollback+=("rm ${ini#"${P2S_ROOT:-}"}")
      fi
      [ "$had" = yes ] && rollback[-1]="restore the previous ${ini#"${P2S_ROOT:-}"} (content above), then reload"
    else
      # Roll back before anything reloads: the running pool keeps its old config.
      if [ "$had" = yes ]; then printf '%s\n' "$prev" >"$ini"; else rm -f "$ini"; fi
      action=test-failed
      fail
    fi
    [ "$had" = yes ] && { echo "previous $ini:"; printf '%s\n' "$prev" | sed 's/^/  | /'; }
  fi
  p2s_mitigation_report "$host" "$branch" "$sapi" "$owner" "$action"
  echo "php$branch $sapi: 99-security.ini $owner, $action -> $P2S_MSTATE"
  case $P2S_MSTATE in mitigated) ;; *) needs_operator ;; esac
done <<<"$sapis"

echo "== summary $host"
if [ ${#rollback[@]} -gt 0 ]; then
  echo "rollback:"
  printf '  %s\n' "${rollback[@]}"
fi
echo "exit $rc"
exit "$rc"
