# Read-only PHP2Shell audit of one host. Changes nothing.
# Runs as the tail of the bundle from run.sh (after versions.sh and p2s.sh): run.sh audit <host>
# Output: a human-readable section plus "@p2s" records (schema in p2s.sh), one per PHP-FPM branch.
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
  active=$(systemctl is-active "php$branch-fpm" 2>/dev/null)
  read -r verdict reason <<<"$(p2s_verdict "$branch" "$ver" "$origin" "$cve")"
  echo "php$branch fpm: $ver ($origin, $active), CVEs in changelog: $cve -> $verdict ($reason)"
  p2s_record kind=branch host="$host" branch="$branch" sapi=fpm installed="$ver" origin="$origin" \
    active="${active:-unknown}" cve_changelog="$cve" verdict="$verdict" reason="$reason"
done <<<"$pkgs"
