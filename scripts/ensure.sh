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

P2S_RC=0 P2S_ROLLBACK=()
sapis=$(p2s_web_sapis)
[ -n "$sapis" ] || echo "no PHP-FPM or PHP-CGI installed"
while read -r branch sapi; do
  [ -n "$branch" ] || continue
  p2s_ensure_sapi "$host" "$branch" "$sapi" yes
done <<<"$sapis"

echo "== summary $host"
if [ ${#P2S_ROLLBACK[@]} -gt 0 ]; then
  echo "rollback:"
  printf '  %s\n' "${P2S_ROLLBACK[@]}"
fi
echo "exit $P2S_RC"
exit "$P2S_RC"
