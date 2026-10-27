# shellcheck shell=bash
# Read-only PHP2Shell audit of one host. Changes nothing.
# Runs as the tail of the bundle from run.sh (after versions.sh, p2s.sh, mitigation.sh, hostfacts.sh, ioc.sh,
# harden.sh, branch.sh):
# run.sh audit <host>
# Output: a human-readable section plus "@p2s" records (schema in p2s.sh): one "branch" record per PHP-FPM
# or mod_php (SAPI apache2) branch with its verdict and target, one "candidate" record per build apt offers
# for it, and one "mitigation" record (plus "override" records) per web SAPI, then the host facts: web
# servers, sites and pools, PHP outside dpkg ("foreign_php"), held packages, PPA sources with their Release
# info, unattended-upgrades; last the indicators of compromise ("ioc", "ioc_file").
set -u
export LC_ALL=C

host=$(hostname </dev/null)
os=$(p2s_os)

echo "== php2shell audit: $host ($os)"
p2s_record kind=host host="$host" os="$os"

# Installed PHP-FPM and mod_php packages of a versioned branch, one "branch|sapi|package|version" per line.
pkgs=$(p2s_branch_packages)
[ -n "$pkgs" ] || echo "no PHP-FPM or mod_php branch installed"

# Candidate .debs are fetched into one temp dir that goes away however the audit ends.
P2S_TMP=$(mktemp -d)
trap 'rm -rf "$P2S_TMP"' EXIT

while IFS='|' read -r branch sapi pkg ver; do
  [ -n "$branch" ] || continue
  # mod_php counts as running only while Apache loads it; an installed module left disabled serves nothing.
  if [ "$sapi" = apache2 ] && ! p2s_modphp_loaded "$branch"; then
    active=not-loaded
  else
    active=$(systemctl is-active "$(p2s_sapi_unit "$branch" "$sapi")" </dev/null 2>/dev/null)
  fi
  p2s_branch_eval "$host" "$branch" "$ver" "$pkg" "$sapi"
  read -r started installed_at restart <<<"$(p2s_restart_state "$branch" "$active" "$sapi")"

  echo "php$branch $sapi: $ver ($BR_ORIGIN, $active), CVEs in changelog: $BR_CVE -> $BR_VERDICT ($BR_REASON), target $BR_TARGET ($BR_TREASON)"
  echo "  started $started, packages installed $installed_at: restart $restart"
  echo "  $BR_ORIGIN apt lists last changed: $BR_LISTS (older than the fixes: $BR_STALE)"
  [ ${#BR_CHUMAN[@]} -eq 0 ] || printf '%s\n' "${BR_CHUMAN[@]}"
  p2s_record kind=branch host="$host" branch="$branch" sapi="$sapi" installed="$ver" origin="$BR_ORIGIN" \
    active="${active:-unknown}" cve_changelog="$BR_CVE" verdict="$BR_VERDICT" reason="$BR_REASON" \
    target="$BR_TARGET" target_reason="$BR_TREASON" lists_updated="$BR_LISTS" lists_stale="$BR_STALE" \
    started="$started" installed_at="$installed_at" restart="$restart"
  [ ${#BR_CRECORDS[@]} -eq 0 ] || printf '%s\n' "${BR_CRECORDS[@]}"
done <<<"$pkgs"

echo "== upload_progress mitigation (CVE-2026-115560)"
while read -r mbranch msapi; do
  [ -n "$mbranch" ] || continue
  owner=$(p2s_ini_owner "$(p2s_path "/etc/php/$mbranch/$msapi/conf.d/99-security.ini")")
  p2s_mitigation_report "$host" "$mbranch" "$msapi" "$owner" inspected
  echo "php$mbranch $msapi: 99-security.ini $owner -> $P2S_MSTATE"
done <<<"$(p2s_web_sapis)"

# What the opt-in harden mode has in place, per SAPI; nothing when none of it is.
while IFS='|' read -r branch sapi pkg ver; do
  [ -n "$branch" ] || continue
  read -r hml hmr hmm <<<"$(p2s_harden_state "$branch" "$sapi")"
  [ "$hml$hmr$hmm" = --- ] && continue
  p2s_record kind=harden host="$host" branch="$branch" sapi="$sapi" memory_limit="$hml" max_requests="$hmr" memory_max="$hmm" state=in-place
  echo "php$branch $sapi: harden in place (memory_limit $hml, max_requests $hmr, MemoryMax $hmm)"
done <<<"$pkgs"

hook=$(p2s_hook_state)
p2s_record kind=ensure_hook host="$host" state="$hook"
echo "apt hook that keeps the mitigation in place: $hook"

echo "== host facts"
# Which site runs on which pool: nginx -T is the effective config, so symlinked and included sites count.
ngx=$(nginx -T </dev/null 2>/dev/null)
case $? in
  0) nginx_state=present ;;
  127) nginx_state=absent ngx="" ;;   # not installed
  *) nginx_state=config-error ngx="" ;;
esac
apache=$(systemctl is-active apache2 </dev/null 2>/dev/null)
apache=${apache:-unknown}
p2s_record kind=webserver host="$host" nginx="$nginx_state" apache2="$apache"
echo "nginx: $nginx_state, apache2: $apache"
sites=$(p2s_nginx_sites "$ngx")

pools=()
while IFS='|' read -r branch sapi pkg ver; do
  [ "$sapi" = fpm ] || continue
  while IFS='|' read -r pool listen; do
    [ -n "$pool" ] || continue
    pools+=("$branch|$pool|$listen")
  done <<<"$(p2s_fpm_pools "$branch")"
done <<<"$pkgs"

for p in "${pools[@]}"; do
  IFS='|' read -r branch pool listen <<<"$p"
  n=0
  while IFS='|' read -r names pass; do
    [ -n "$pass" ] && p2s_listen_matches "$listen" "$pass" && n=$((n + 1))
  done <<<"$sites"
  # Apache (proxy_fcgi) and an unreadable nginx config can use a pool this scan cannot see.
  if [ "$n" -gt 0 ]; then used=yes
  elif [ "$nginx_state" != present ] || [ "$apache" = active ]; then used=unknown
  else used=no
  fi
  p2s_record kind=pool host="$host" branch="$branch" pool="$pool" listen="$(p2s_enc "$listen")" sites="$n" used="$used"
  echo "php$branch pool $pool ($listen): $n site(s), used $used"
done

while IFS='|' read -r names pass; do
  [ -n "$pass" ] || continue
  mb=- mp=-
  for p in "${pools[@]}"; do
    IFS='|' read -r branch pool listen <<<"$p"
    if p2s_listen_matches "$listen" "$pass"; then mb=$branch mp=$pool; break; fi
  done
  p2s_record kind=vhost host="$host" names="$(p2s_enc "$names")" pass="$(p2s_enc "$pass")" branch="$mb" pool="$mp"
  echo "site $names -> $pass (php$mb pool $mp)"
done <<<"$sites"

# PHP outside dpkg (a control panel's, LiteSpeed's, a source build): this audit cannot judge it and fix and
# ensure leave it alone, so it only gets named, with where it comes from.
while IFS='|' read -r path fsapi running fver; do
  [ -n "$path" ] || continue
  src=$(p2s_foreign_source "$path")
  p2s_record kind=foreign_php host="$host" path="$path" sapi="$fsapi" running="$running" version="$fver" source="$src"
  echo "PHP outside dpkg: $path ($fsapi, $src, version $fver, running $running): not judged, not patched here"
done <<<"$(p2s_foreign_php)"

# Held PHP packages block a patch: apt will not upgrade them.
while read -r held; do
  [ -n "$held" ] || continue
  p2s_record kind=hold host="$host" package="$held"
  echo "held: $held"
done <<<"$(apt-mark showhold </dev/null 2>/dev/null | grep -E '^(php|libapache2-mod-php)')"

# PPA sources, and whether their Release info changed since the cached lists: apt-get update refuses such a
# source until someone accepts the change.
while IFS='|' read -r file uri suite; do
  [ -n "$uri" ] || continue
  rc=$(p2s_release_check "$uri" "$suite")
  read -r info changed <<<"$(head -1 <<<"$rc")"
  tail -n +2 <<<"$rc"
  p2s_record kind=source host="$host" file="$file" uri="$uri" suite="$suite" release_info="$info" changed="$changed"
  echo "source $uri $suite ($file): release info $info$([ "$changed" = - ] || echo " ($changed)")"
done <<<"$(p2s_php_sources)"

# unattended-upgrades as apt sees it after merging every apt.conf.d file.
cfg=$(apt-config dump </dev/null 2>/dev/null)
periodic=$(sed -nE 's/^APT::Periodic::Unattended-Upgrade "([^"]*)";$/\1/p' <<<"$cfg" | tail -1)
origins=$(sed -nE 's/^Unattended-Upgrade::(Allowed-Origins|Origins-Pattern):: "([^"]*)";$/\2/p' <<<"$cfg")
covered=no
grep -qiE 'ondrej|sury' <<<"$origins" && covered=yes
p2s_record kind=autoupdate host="$host" periodic="${periodic:-unset}" origins="$(grep -c . <<<"$origins")" ppa_covered="$covered"
while IFS= read -r o; do
  [ -n "$o" ] && p2s_record kind=uu_origin host="$host" value="$(p2s_enc "$o")"
done <<<"$origins"
echo "unattended-upgrades: periodic ${periodic:-unset}, ondrej PPA covered: $covered"

echo "== indicators of compromise since $P2S_EXPLOIT_SINCE (for review: a clean result is no proof)"
while IFS='|' read -r src n first last; do
  [ -n "$src" ] || continue
  p2s_record kind=ioc host="$host" type=crash source="$src" count="$n" first="$first" last="$last"
  echo "crash ($src): $n since the window, first $first, last $last"
done <<<"$(p2s_ioc_crashes "$P2S_EXPLOIT_SINCE")"
while IFS='|' read -r pid parent args; do
  [ -n "$pid" ] || continue
  p2s_record kind=ioc host="$host" type=shell_child source="$parent" count=1 first=- last=- pid="$pid" command="$(p2s_enc "$args")"
  echo "RUNNING UNDER $parent: pid $pid: $args"
done <<<"$(p2s_ioc_shell_children)"
while IFS='|' read -r kind a b c d e; do
  case $kind in
    dir)
      p2s_record kind=ioc host="$host" type=new_php source="$a" count="$b" first="$c" last="$d" capped="$e"
      echo "PHP files changed in $a: $b$([ "$e" = no ] || echo " (stopped at the cap)"), $c .. $d" ;;
    file)
      p2s_record kind=ioc_file host="$host" mtime="$a" path="$(p2s_enc "$b")"
      echo "  $a $b" ;;
  esac
done <<<"$(p2s_ioc_new_php "$P2S_EXPLOIT_SINCE")"
