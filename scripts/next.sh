#!/usr/bin/env bash
# The next step per host, read from the newest saved log of each mode, so an interrupted session resumes
# where it stopped. Steps: audit, fix, ensure, verify (audit again after a write), done.
# Usage: next.sh --latest       every run.sh log in ${P2S_CACHE:-$XDG_CACHE_HOME/php2shell}
#        next.sh <log>...
# Prints one "<host>: <step> - <reason>" line per host. Exit 0; 2 on bad usage or no logs.
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/logs.sh
. "$HERE/lib/logs.sh"
CACHE=${P2S_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/php2shell}

case ${1:-} in
  '') sed -n '4,5s/^# \{0,1\}//p' "${BASH_SOURCE[0]}" >&2; exit 2 ;;
  --latest) mapfile -t logs < <(p2s_cache_logs "$CACHE") ;;
  *) logs=("$@") ;;
esac
newest=$(p2s_newest_logs "${logs[@]}")
[ -n "$newest" ] || { echo "no readable logs" >&2; exit 2; }

word() { sed -nE "s/.*(^| )$1=([^ ]*).*/\\2/p" <<<"$2"; }   # word <key> <summary>

# One host at a time: its newest audit, and its newest write run (ensure or fix) if that is newer.
for target in $(cut -f1 <<<"$newest" | sort -u); do
  rows=$(awk -F'\t' -v t="$target" '$1 == t' <<<"$newest")
  audit=$(awk -F'\t' '$2 == "audit"' <<<"$rows")
  write=$(awk -F'\t' '$2 == "ensure" || $2 == "fix"' <<<"$rows" | sort -t "$(printf '\t')" -k3,3r | head -1)
  a_stamp=$(cut -f3 <<<"$audit")
  if [ -z "$audit" ]; then
    step=audit reason="no audit yet"
  else
    a=$(p2s_log_summary "$(cut -f4 <<<"$audit")")
    a_status=$(word status "$a")
    if [ -n "$write" ] && [[ $(cut -f3 <<<"$write") > $a_stamp ]]; then
      w=$(p2s_log_summary "$(cut -f4 <<<"$write")")
      w_mode=$(cut -f2 <<<"$write")
      case $(word status "$w") in
        ok | none) step=verify reason="$w_mode finished after the last audit; audit again to confirm" ;;
        *)
          step=$w_mode
          reason="last $w_mode: $(word status "$w")"
          [ "$(word unfixed "$w")" = - ] || reason+=", unfixed: php$(word unfixed "$w" | sed 's/,/, php/g')"
          [ "$(word unmitigated "$w")" = - ] || reason+=", not mitigated: $(word unmitigated "$w")"
          [ "$(word overrides "$w")" = - ] || reason+=", pool override: $(word overrides "$w") (the operator removes it)"
          ;;
      esac
    elif [ "$a_status" = unreachable ] || [ "$a_status" = timeout ] || [ "$(word reached "$a")" = no ]; then
      step=audit reason="last audit: $a_status"
    elif [ "$(word unfixed "$a")" != - ]; then
      step=fix reason="unfixed: php$(word unfixed "$a" | sed 's/,/, php/g')"
    elif [ "$(word restart_needed "$a")" != - ]; then
      step=fix reason="restart needed: php$(word restart_needed "$a" | sed 's/,/, php/g')"
    elif [ "$(word unmitigated "$a")" != - ]; then
      step=ensure reason="not mitigated: $(word unmitigated "$a")"
      [ "$(word overrides "$a")" = - ] || reason+=", pool override: $(word overrides "$a") (the operator removes it)"
    else
      step=done reason="every branch fixed and restarted, every web SAPI mitigated"
    fi
  fi
  echo "$target: $step - $reason"
done
