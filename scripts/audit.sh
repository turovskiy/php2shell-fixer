# Read-only PHP2Shell audit of one host. Changes nothing.
# Runs as the tail of the bundle from run.sh (after versions.sh and p2s.sh): run.sh audit <host>
# Output: a human-readable section plus "@p2s" records (schema in p2s.sh): one "branch" record per PHP-FPM
# branch with its verdict and target, one "candidate" record per build apt offers for it.
set -u
export LC_ALL=C

field() { # field <file> <key>: value of KEY=... in an os-release style file, quotes stripped
  sed -nE "s/^$2=\"?([^\"]*)\"?$/\1/p" "$1" 2>/dev/null | head -1
}

host=$(hostname)
osr=$(p2s_path /etc/os-release)
os="$(field "$osr" ID)-$(field "$osr" VERSION_ID)"
[ "$os" = - ] && os=unknown

echo "== php2shell audit: $host ($os)"
p2s_record kind=host host="$host" os="$os"

# Installed PHP-FPM packages of a versioned branch (php8.3-fpm), not the php-fpm metapackage or removed ones.
pkgs=$(dpkg-query -W -f='${db:Status-Abbrev}|${binary:Package}|${Version}\n' 'php*-fpm' 2>/dev/null \
  | awk -F'|' '$1 ~ /^ii/ && $2 ~ /^php[0-9]+\.[0-9]+-fpm$/ {print $2 "|" $3}')
if [ -z "$pkgs" ]; then
  echo "no PHP-FPM branch installed"
  exit 0
fi

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

# When the apt lists of one origin last changed: the newest Packages list of that origin, as UTC ISO time,
# or "unknown". The audit never runs apt-get update, so candidates are only as fresh as these lists.
lists_date() {
  local f t newest=""
  for f in "$(p2s_path /var/lib/apt/lists)"/*_Packages*; do
    [ -f "$f" ] && [ "$(p2s_list_origin "$f")" = "$1" ] || continue
    t=$(stat -c %Y "$f")
    if [ -z "$newest" ] || [ "$t" -gt "$newest" ]; then newest=$t; fi
  done
  if [ -n "$newest" ]; then date -u -d "@$newest" +%Y-%m-%dT%H:%M:%SZ; else echo unknown; fi
}

while IFS='|' read -r pkg ver; do
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
  stale=$(p2s_lists_stale "$lists")

  echo "php$branch fpm: $ver ($origin, $active), CVEs in changelog: $cve -> $verdict ($reason), target $target ($treason)"
  echo "  $origin apt lists last changed: $lists (older than the fixes: $stale)"
  [ ${#chuman[@]} -eq 0 ] || printf '%s\n' "${chuman[@]}"
  p2s_record kind=branch host="$host" branch="$branch" sapi=fpm installed="$ver" origin="$origin" \
    active="${active:-unknown}" cve_changelog="$cve" verdict="$verdict" reason="$reason" \
    target="$target" target_reason="$treason" lists_updated="$lists" lists_stale="$stale"
  [ ${#crecords[@]} -eq 0 ] || printf '%s\n' "${crecords[@]}"
done <<<"$pkgs"
