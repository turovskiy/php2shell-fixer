# Read-only PHP2Shell audit of one host. Changes nothing.
# Runs as the tail of the bundle from run.sh (after versions.sh, p2s.sh, mitigation.sh, hostfacts.sh):
# run.sh audit <host>
# Output: a human-readable section plus "@p2s" records (schema in p2s.sh): one "branch" record per PHP-FPM
# branch with its verdict and target, one "candidate" record per build apt offers for it, and one
# "mitigation" record (plus "override" records) per web SAPI, then the host facts: web servers, sites and
# pools, held packages, PPA sources with their Release info, unattended-upgrades.
set -u
export LC_ALL=C

host=$(hostname </dev/null)
os=$(p2s_os)

echo "== php2shell audit: $host ($os)"
p2s_record kind=host host="$host" os="$os"

# Installed PHP-FPM packages of a versioned branch (php8.3-fpm), not the php-fpm metapackage or removed ones.
pkgs=$(dpkg-query -W -f='${db:Status-Abbrev}|${binary:Package}|${Version}\n' 'php*-fpm' </dev/null 2>/dev/null \
  | awk -F'|' '$1 ~ /^ii/ && $2 ~ /^php[0-9]+\.[0-9]+-fpm$/ {print $2 "|" $3}')
[ -n "$pkgs" ] || echo "no PHP-FPM branch installed"

# Candidate .debs are fetched into one temp dir that goes away however the audit ends.
P2S_TMP=$(mktemp -d)
trap 'rm -rf "$P2S_TMP"' EXIT

# Does the build apt would install name both CVEs? $1 package, $2 version.
# Prints yes | no | missing (no changelog in the .deb) | download-failed. Installs nothing.
# Every command here reads /dev/null: this program itself arrives on stdin (ssh host 'bash -s').
candidate_cve() {
  local d log="" deb=""
  d=$(mktemp -d "$P2S_TMP/deb.XXXXXX") || { echo download-failed; return; }
  if ! (cd "$d" && apt-get download -q "$1=$2" </dev/null >/dev/null 2>&1); then
    echo download-failed
  else
    for deb in "$d"/*.deb; do
      [ -f "$deb" ] || continue
      log=$(dpkg-deb --fsys-tarfile "$deb" </dev/null 2>/dev/null \
        | tar -xO --wildcards './usr/share/doc/*/changelog.Debian.gz' 2>/dev/null | zcat 2>/dev/null)
    done
    if [ -z "${deb:-}" ] || [ ! -f "$deb" ]; then echo download-failed
    elif [ -z "$log" ]; then echo missing
    elif p2s_changelog_has_cves "$log"; then echo yes
    else echo no
    fi
  fi
  rm -rf "$d"
}

# Did FPM restart after the branch's packages were last installed? A running pool keeps the build it
# started with. Prints "<started> <installed> <ok|needed|not-running|unknown>", times as UTC ISO.
# Install time is the newest dpkg file list of the branch (php8.3-*.list), so an extension upgrade counts.
restart_state() { # $1 branch, $2 service state from is-active
  local started s_epoch="" f t i_epoch=""
  started=$(systemctl show -p ActiveEnterTimestamp --value "php$1-fpm" </dev/null 2>/dev/null)
  # date -d "" means today 00:00, so an empty or n/a start time must not reach it.
  case $started in '' | n/a) ;; *) s_epoch=$(date -u -d "$started" +%s 2>/dev/null) ;; esac
  for f in "$(p2s_path /var/lib/dpkg/info)/php$1-"*.list; do
    [ -f "$f" ] || continue
    t=$(stat -c %Y "$f")
    if [ -z "$i_epoch" ] || [ "$t" -gt "$i_epoch" ]; then i_epoch=$t; fi
  done
  local state
  if [ "$2" != active ]; then state=not-running
  elif [ -z "$s_epoch" ] || [ -z "$i_epoch" ]; then state=unknown
  elif [ "$s_epoch" -ge "$i_epoch" ]; then state=ok
  else state=needed
  fi
  echo "$(if [ "$2" = active ]; then p2s_iso "$s_epoch"; else echo -; fi) $(p2s_iso "$i_epoch") $state"
}

# When the apt lists of one origin last changed: the newest Packages list of that origin, as UTC ISO time,
# or "unknown". The audit never runs apt-get update, so candidates are only as fresh as these lists.
lists_date() {
  local f t newest=""
  for f in "$(p2s_path /var/lib/apt/lists)"/*_Packages*; do
    [ -f "$f" ] && [ "$(p2s_list_origin "$f")" = "$1" ] || continue
    t=$(stat -c %Y "$f")
    if [ -z "$newest" ] || [ "$t" -gt "$newest" ]; then newest=$t; fi
  done
  p2s_iso "$newest"
}

while IFS='|' read -r pkg ver; do
  [ -n "$pkg" ] || continue
  branch=${pkg#php}
  branch=${branch%-fpm}
  origin=$(p2s_origin "$ver")
  changelog=$(p2s_path "/usr/share/doc/php$branch-common/changelog.Debian.gz")
  if [ ! -f "$changelog" ]; then
    cve=missing
  elif p2s_changelog_has_cves "$(zcat "$changelog" 2>/dev/null)"; then
    cve=yes
  else
    cve=no
  fi
  active=$(systemctl is-active "php$branch-fpm" </dev/null 2>/dev/null)
  read -r verdict reason <<<"$(p2s_verdict "$branch" "$ver" "$origin" "$cve")"

  # Every build apt offers for the branch. Only an unfixed branch gets its candidates judged, and only
  # those of its own origin that are newer than the installed build: the rest cannot become the target.
  offered=$(apt-cache madison "php$branch-fpm" </dev/null 2>/dev/null | awk -F'|' '{gsub(/ /, "", $2)} $2 != "" && !seen[$2]++ {print $2}')
  cands=()
  crecords=()
  chuman=()
  while IFS= read -r cv; do
    [ -n "$cv" ] || continue
    co=$(p2s_origin "$cv")
    if [ "$verdict" = unfixed ] && [ "$co" = "$origin" ] && dpkg --compare-versions "$cv" gt "$ver"; then
      ccve=$(candidate_cve "php$branch-common" "$cv")
      read -r cverdict creason <<<"$(p2s_verdict "$branch" "$cv" "$co" "$ccve")"
    else
      ccve=not-checked cverdict=- creason=not-assessed
    fi
    cands+=("$cv|$co|$cverdict")
    chuman+=("  offered $cv ($co): CVEs in changelog: $ccve -> $cverdict ($creason)")
    crecords+=("$(p2s_record kind=candidate host="$host" branch="$branch" version="$cv" origin="$co" \
      cve_changelog="$ccve" verdict="$cverdict" reason="$creason")")
  done <<<"$offered"
  read -r target treason <<<"$(p2s_target "$ver" "$origin" "$verdict" "${cands[@]}")"
  lists=$(lists_date "$origin")
  read -r started installed_at restart <<<"$(restart_state "$branch" "$active")"
  stale=$(p2s_lists_stale "$lists")

  echo "php$branch fpm: $ver ($origin, $active), CVEs in changelog: $cve -> $verdict ($reason), target $target ($treason)"
  echo "  started $started, packages installed $installed_at: restart $restart"
  echo "  $origin apt lists last changed: $lists (older than the fixes: $stale)"
  [ ${#chuman[@]} -eq 0 ] || printf '%s\n' "${chuman[@]}"
  p2s_record kind=branch host="$host" branch="$branch" sapi=fpm installed="$ver" origin="$origin" \
    active="${active:-unknown}" cve_changelog="$cve" verdict="$verdict" reason="$reason" \
    target="$target" target_reason="$treason" lists_updated="$lists" lists_stale="$stale" \
    started="$started" installed_at="$installed_at" restart="$restart"
  [ ${#crecords[@]} -eq 0 ] || printf '%s\n' "${crecords[@]}"
done <<<"$pkgs"

echo "== upload_progress mitigation (CVE-2026-115560)"
while read -r mbranch msapi; do
  [ -n "$mbranch" ] || continue
  owner=$(p2s_ini_owner "$(p2s_path "/etc/php/$mbranch/$msapi/conf.d/99-security.ini")")
  p2s_mitigation_report "$host" "$mbranch" "$msapi" "$owner" inspected
  echo "php$mbranch $msapi: 99-security.ini $owner -> $P2S_MSTATE"
done <<<"$(p2s_web_sapis)"

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
while IFS='|' read -r pkg ver; do
  [ -n "$pkg" ] || continue
  branch=${pkg#php}
  branch=${branch%-fpm}
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

# Held PHP packages block a patch: apt will not upgrade them.
while read -r held; do
  [ -n "$held" ] || continue
  p2s_record kind=hold host="$host" package="$held"
  echo "held: $held"
done <<<"$(apt-mark showhold </dev/null 2>/dev/null | grep -E '^(php|libapache2-mod-php)')"

# PPA sources, and whether their Release info changed since the cached lists: apt-get update refuses such a
# source until someone accepts the change. The fresh InRelease is fetched into the temp dir; nothing else.
helper=$(p2s_path /usr/lib/apt/apt-helper)
while IFS='|' read -r file uri suite; do
  [ -n "$uri" ] || continue
  cached=$(p2s_path /var/lib/apt/lists)/$(p2s_inrelease_name "$uri" "$suite")
  info=unknown changed=-
  if [ -f "$cached" ] && [ -x "$helper" ]; then
    dest=$P2S_TMP/InRelease.$suite
    if timeout 30 "$helper" -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 \
      download-file "${uri%/}/dists/$suite/InRelease" "$dest" </dev/null >/dev/null 2>&1; then
      old=$(p2s_release_info "$(cat "$cached")")
      new=$(p2s_release_info "$(cat "$dest")")
      if [ "$old" = "$new" ]; then
        info=same
      else
        info=changed
        changed=$(diff <(echo "$old") <(echo "$new") | sed -nE 's/^[<>] ([A-Za-z]+):.*/\1/p' | sort -u | paste -sd, -)
        diff <(echo "$old") <(echo "$new") | sed -nE 's/^< /  cached: /p; s/^> /  remote: /p'
      fi
    fi
    rm -f "$dest"
  fi
  p2s_record kind=source host="$host" file="$file" uri="$uri" suite="$suite" release_info="$info" changed="$changed"
  echo "source $uri $suite ($file): release info $info$([ "$changed" = - ] || echo " ($changed)")"
done <<<"$(p2s_php_sources)"

# unattended-upgrades as apt sees it after merging every apt.conf.d file.
cfg=$(apt-config dump </dev/null 2>/dev/null)
periodic=$(sed -nE 's/^APT::Periodic::Unattended-Upgrade "([^"]*)";$/\1/p' <<<"$cfg" | tail -1)
origins=$(sed -nE 's/^Unattended-Upgrade::(Allowed-Origins|Origins-Pattern):: "([^"]*)";$/\2/p' <<<"$cfg")
covered=no
grep -qiE 'ondrej' <<<"$origins" && covered=yes
p2s_record kind=autoupdate host="$host" periodic="${periodic:-unset}" origins="$(grep -c . <<<"$origins")" ppa_covered="$covered"
while IFS= read -r o; do
  [ -n "$o" ] && p2s_record kind=uu_origin host="$host" value="$(p2s_enc "$o")"
done <<<"$origins"
echo "unattended-upgrades: periodic ${periodic:-unset}, ondrej PPA covered: $covered"
