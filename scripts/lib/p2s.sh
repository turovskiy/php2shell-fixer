# Shared library: root prefix, record format, verdict. Sourced after versions.sh, both locally and in the
# bundle that run.sh streams to a host.

P2S_SCHEMA=1

# Every filesystem path goes through the root prefix, so tests can point the scripts at a fake host.
p2s_path() { printf '%s%s' "${P2S_ROOT:-}" "$1"; }

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
