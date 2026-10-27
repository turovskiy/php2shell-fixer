# shellcheck shell=bash
# Keeps the CVE-2026-115560 mitigation in place: session.upload_progress off in every web SAPI (FPM, mod_php,
# CGI) of every installed PHP branch. Writes 99-security.ini where it is missing or outdated, leaves CLI and
# foreign files alone, and reloads only the FPM pools, or Apache for a loaded mod_php, whose config changed.
# Installs an apt hook that runs the same ensure after every dpkg run, so PHP branches installed later get it
# too. Idempotent.
# Runs as the tail of the bundle from run.sh (after versions.sh, p2s.sh, mitigation.sh, hostfacts.sh):
# run.sh ensure <host>
# Exit: 0 every web SAPI mitigated; 3 an override re-enables it (pool, Apache, nginx PHP_VALUE, .user.ini), a
#       foreign 99-security.ini, a SAPI still On or unknown, or the apt hook could not be written; 1 not root,
#       a config test failed (change rolled back) or a reload failed.
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
[ -n "$sapis" ] || echo "no PHP-FPM, mod_php or PHP-CGI installed"
while read -r branch sapi; do
  [ -n "$branch" ] || continue
  p2s_ensure_sapi "$host" "$branch" "$sapi" yes
done <<<"$sapis"

# PHP outside dpkg reads its vendor's ini, not /etc/php: nothing here reaches it.
while IFS='|' read -r fpath fsapi frunning _; do
  [ -n "$fpath" ] && echo "PHP outside dpkg left alone: $fpath ($fsapi, running $frunning); its vendor's config is not touched"
done <<<"$(p2s_foreign_php)"

# Keep it in place: apt runs a local ensure after every dpkg run from now on.
p2s_hook_install
p2s_record kind=ensure_hook host="$host" action="$P2S_HOOK_ACTION" state="$(p2s_hook_state)"
echo "apt hook ($P2S_HOOK_CONF): $P2S_HOOK_ACTION"
case $P2S_HOOK_ACTION in
  installed) P2S_ROLLBACK+=("rm $P2S_HOOK_CONF $P2S_HOOK_SCRIPT   # the apt hook") ;;
  failed) [ "$P2S_RC" = 0 ] && P2S_RC=3 ;;
esac

echo "== summary $host"
if [ ${#P2S_ROLLBACK[@]} -gt 0 ]; then
  echo "rollback:"
  printf '  %s\n' "${P2S_ROLLBACK[@]}"
fi
echo "exit $P2S_RC"
exit "$P2S_RC"
