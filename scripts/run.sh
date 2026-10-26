#!/usr/bin/env bash
# Local runner. Streams a mode's scripts to a host as one bash program over ssh, so nothing is copied
# to the server, and saves the output to a log that report.sh reads.
# Usage: run.sh audit <host>     host: an ssh alias or user@address
#        run.sh bundle <mode>    print the stream for <mode> (what ssh would receive)
# Logs:  ${P2S_CACHE:-$XDG_CACHE_HOME/php2shell}/<host>-<mode>-<UTC stamp>.log
# Exit:  the remote program's exit code (ssh's own failures are 255); 2 on bad usage.
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CACHE=${P2S_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/php2shell}

usage() {
  sed -n '4,5s/^# \{0,1\}//p' "${BASH_SOURCE[0]}" >&2
  exit 2
}

bundle() {
  case $1 in
    audit) cat "$HERE/lib/versions.sh" "$HERE/lib/p2s.sh" "$HERE/audit.sh" ;;
    *) echo "unknown mode: $1" >&2; return 2 ;;
  esac
}

case ${1:-} in
  bundle)
    [ $# -eq 2 ] || usage
    bundle "$2"
    ;;
  audit)
    [ $# -eq 2 ] || usage
    mode=$1 host=$2
    mkdir -p "$CACHE"
    log="$CACHE/${host//[^A-Za-z0-9._-]/_}-$mode-$(date -u +%Y%m%dT%H%M%SZ).log"
    ssh "$host" 'bash -s' < <(bundle "$mode") > "$log" 2>&1
    rc=$?
    cat "$log"
    echo "log: $log"
    exit "$rc"
    ;;
  *) usage ;;
esac
