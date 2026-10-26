# Shared library: root prefix, record format, verdict. Sourced after versions.sh, both locally and in the
# bundle that run.sh streams to a host.

P2S_SCHEMA=1

# Every filesystem path goes through the root prefix, so tests can point the scripts at a fake host.
p2s_path() { printf '%s%s' "${P2S_ROOT:-}" "$1"; }

# Host OS as ID-VERSION_ID from os-release (ubuntu-24.04), or unknown.
p2s_os() {
  local f id ver
  f=$(p2s_path /etc/os-release)
  id=$(sed -nE 's/^ID="?([^"]*)"?$/\1/p' "$f" 2>/dev/null | head -1)
  ver=$(sed -nE 's/^VERSION_ID="?([^"]*)"?$/\1/p' "$f" 2>/dev/null | head -1)
  if [ -n "$id$ver" ]; then echo "$id-$ver"; else echo unknown; fi
}

# One machine-readable record: "@p2s schema=1 key=value ...". Values carry no spaces.
p2s_record() {
  printf '@p2s schema=%s' "$P2S_SCHEMA"
  printf ' %s' "$@"
  printf '\n'
}

# Where a build comes from: the ondrej/sury PPA, the distro (Ubuntu or Debian), or something else.
p2s_origin() {
  case $1 in
    *sury*) echo ppa ;;
    *ubuntu* | *~deb* | *+deb[0-9]*) echo distro ;;
    *) echo other ;;
  esac
}

# Origin of an apt list file in /var/lib/apt/lists, by name, matching p2s_origin:
# ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_noble_main_binary-amd64_Packages -> ppa
# mirrors.digitalocean.com_ubuntu_dists_noble-security_main_binary-amd64_Packages -> distro
p2s_list_origin() {
  case ${1##*/} in
    *sury* | *ondrej*) echo ppa ;;
    *_ubuntu_dists_* | *_debian_dists_* | *debian-security_dists_*) echo distro ;;
    *) echo other ;;
  esac
}

# Are apt lists dated $1 (UTC ISO time, or "unknown") too old to offer the fixed builds? Prints yes|no|unknown.
p2s_lists_stale() {
  case $1 in
    unknown | '') echo unknown ;;
    *) [[ ${1%%T*} < $P2S_FIXES_RELEASED ]] && echo yes || echo no ;;
  esac
}

# Upstream part of a Debian version: 1:7.4.33-24+ubuntu24.04.1+deb.sury.org+1 -> 7.4.33
p2s_upstream() {
  local v=${1#*:}
  echo "${v%%-*}"
}

# True when the changelog text names both CVEs. Ubuntu names the patch CVE-2026-109618_109619.patch.
# Takes the text, not a pipe: "zcat | head | grep -q" under pipefail fails on a long changelog.
p2s_changelog_has_cves() {
  grep -qE 'CVE-2026-109618' <<<"$1" && grep -qE '(CVE-2026-|_)109619' <<<"$1"
}

# Verdict for an installed build. Prints "<fixed|unfixed> <reason>".
# $1 branch (8.3), $2 installed version, $3 origin (p2s_origin), $4 changelog names both CVEs (yes|no|missing)
p2s_verdict() {
  local branch=$1 ver=$2 origin=$3 cve=$4
  local upstream=${P2S_UPSTREAM_FIXED[$branch]:-} ubuntu=""
  # The Ubuntu threshold applies only to an Ubuntu build; a sury version string also contains "ubuntu".
  [ "$origin" = distro ] && [[ $ver == *ubuntu* ]] && ubuntu=${P2S_UBUNTU_FIXED[$branch]:-}
  if [ -n "$ubuntu" ] && dpkg --compare-versions "$ver" ge "$ubuntu"; then
    echo "fixed distro-threshold"
  elif [ -n "$upstream" ] && dpkg --compare-versions "$(p2s_upstream "$ver")" ge "$upstream"; then
    echo "fixed upstream-threshold"
  elif [ "$cve" = yes ]; then
    echo "fixed changelog"
  elif [ -n "$upstream" ] || [ -n "$ubuntu" ]; then
    echo "unfixed below-threshold"
  else
    echo "unfixed no-cve-in-changelog"
  fi
}

# Target build for a branch. Prints "<version|none> <reason>".
# $1 installed version, $2 its origin, $3 its verdict; then one "version|origin|verdict" per build apt offers.
# A build stays with its origin: a PPA version can sort above a fixed Ubuntu revision and still be unfixed.
p2s_target() {
  local installed=$1 origin=$2 verdict=$3 best="" c v o d
  shift 3
  if [ "$verdict" = fixed ]; then
    echo "none installed-fixed"
    return
  fi
  for c in "$@"; do
    IFS='|' read -r v o d <<<"$c"
    [ "$o" = "$origin" ] && [ "$d" = fixed ] || continue
    dpkg --compare-versions "$v" gt "$installed" || continue
    if [ -z "$best" ] || dpkg --compare-versions "$v" gt "$best"; then best=$v; fi
  done
  if [ -n "$best" ]; then
    echo "$best fixed-candidate"
  elif [ "$origin" = distro ]; then
    echo "none fixed-distro-build-not-in-cached-lists"
  else
    echo "none no-fixed-build-in-cached-lists"
  fi
}
