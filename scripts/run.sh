#!/usr/bin/env bash
# Local runner. Streams a mode's scripts to each host as one bash program over ssh, so nothing is copied
# to a server, and saves each host's output to its own log that report.sh and next.sh read.
# Usage: run.sh audit|ensure|fix|autoupdate <host>... host: an ssh alias or user@address; audit only reads,
#        the others write
#        run.sh bundle <mode>                        print the stream for <mode> (what ssh would receive)
# Logs:  ${P2S_CACHE:-$XDG_CACHE_HOME/php2shell}/<host>-<mode>-<UTC stamp with ms>.log, opened by a "run"
#        record and closed by a "run_end" record (exit code; status ok, exit-<n>, unreachable or timeout).
# SSH:   BatchMode, so keys and agent come from the operator's ssh config and nothing prompts; connect timeout
#        P2S_CONNECT_TIMEOUT (10 s). Only the read-only audit has a per-host limit, P2S_HOST_TIMEOUT (600 s):
#        a write mode is never cut off, because a killed session can leave apt or a reload half done.
#        ssh gets no pty, so a dropped connection sends the remote program no SIGHUP: it ends by SIGPIPE on
#        its next write, or not at all while its output still fits the buffers. A mode that runs apt must
#        detach on the server itself rather than rely on this runner (fix does), and autoupdate puts its
#        origin entry back as it was when the drop (or a kill) comes before the dry run has judged it.
# Exit:  the highest exit code among the hosts (ssh's own failures 255, a timed-out audit 124); 2 on bad usage.
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CACHE=${P2S_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/php2shell}
CONNECT_TIMEOUT=${P2S_CONNECT_TIMEOUT:-10}
HOST_TIMEOUT=${P2S_HOST_TIMEOUT:-600}

usage() {
  sed -n '4,6s/^# \{0,1\}//p' "${BASH_SOURCE[0]}" >&2
  exit 2
}

bundle() {
  case $1 in
    audit) cat "$HERE/lib/versions.sh" "$HERE/lib/p2s.sh" "$HERE/lib/mitigation.sh" "$HERE/lib/hostfacts.sh" "$HERE/lib/branch.sh" "$HERE/audit.sh" ;;
    ensure) cat "$HERE/lib/versions.sh" "$HERE/lib/p2s.sh" "$HERE/lib/mitigation.sh" "$HERE/ensure.sh" ;;
    fix) cat "$HERE/lib/versions.sh" "$HERE/lib/p2s.sh" "$HERE/lib/mitigation.sh" "$HERE/lib/hostfacts.sh" "$HERE/lib/branch.sh" "$HERE/fix.sh" ;;
    autoupdate) cat "$HERE/lib/versions.sh" "$HERE/lib/p2s.sh" "$HERE/lib/hostfacts.sh" "$HERE/lib/pins.sh" "$HERE/autoupdate.sh" ;;
    *) echo "unknown mode: $1" >&2; return 2 ;;
  esac
}

run_host() { # $1 mode, $2 host; prints the log, returns the host's exit code
  local mode=$1 host=$2 target stamp base log n rc status
  target=${host//[^A-Za-z0-9._@-]/_}
  stamp=$(date -u +%Y%m%dT%H%M%S.%3NZ)
  # Milliseconds keep name order equal to run order; the loop only guards a same-millisecond rerun.
  base="$CACHE/${host//[^A-Za-z0-9._-]/_}-$mode-$stamp"
  log=$base.log n=2
  while [ -e "$log" ]; do log=$base-$n.log; n=$((n + 1)); done
  printf '@p2s schema=1 kind=run target=%s mode=%s started=%s\n' "$target" "$mode" "$stamp" >"$log"
  local ssh=(ssh -o BatchMode=yes -o "ConnectTimeout=$CONNECT_TIMEOUT" "$host" 'bash -s')
  if [ "$mode" = audit ]; then
    timeout -k 10 "$HOST_TIMEOUT" "${ssh[@]}" < <(bundle "$mode") >>"$log" 2>&1
  else
    "${ssh[@]}" < <(bundle "$mode") >>"$log" 2>&1
  fi
  rc=$?
  case $rc in
    0) status=ok ;;
    255) status=unreachable ;;
    124 | 137) status=timeout ;;
    *) status=exit-$rc ;;
  esac
  printf '@p2s schema=1 kind=run_end target=%s mode=%s exit=%s status=%s\n' "$target" "$mode" "$rc" "$status" >>"$log"
  cat "$log"
  echo "log: $log"
  return "$rc"
}

case ${1:-} in
  bundle)
    [ $# -eq 2 ] || usage
    bundle "$2"
    ;;
  audit | ensure | fix | autoupdate)
    [ $# -ge 2 ] || usage
    mode=$1
    shift
    mkdir -p "$CACHE"
    # P2S_ALLOW_TMP_CACHE=1 silences this for the test suite, which keeps its logs in a temp dir.
    case ${P2S_ALLOW_TMP_CACHE:-}:$CACHE/ in
      1:*) ;;
      *:/tmp/* | *:/var/tmp/*) echo "warning: logs in $CACHE may not survive a reboot; set P2S_CACHE" >&2 ;;
    esac
    worst=0 summary=()
    for host in "$@"; do
      [ $# -gt 1 ] && echo "######## $host"
      run_host "$mode" "$host"
      rc=$?
      [ "$rc" -gt "$worst" ] && worst=$rc
      summary+=("$host: exit $rc")
    done
    if [ $# -gt 1 ]; then
      echo "######## summary"
      printf '%s\n' "${summary[@]}"
    fi
    exit "$worst"
    ;;
  *) usage ;;
esac
