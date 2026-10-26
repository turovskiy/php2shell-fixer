#!/usr/bin/env bash
# Renders saved run logs as a markdown report, one section per host.
# Reads only the "@p2s" records, so the report says exactly what the logged run found.
# Usage: report.sh <log>...
# Exit:  0; 1 when a log is unreadable or holds no host record; 2 on bad usage.
set -uo pipefail

[ $# -gt 0 ] || { echo "usage: report.sh <log>..." >&2; exit 2; }

rc=0
rows=0
flush() { # close the current host section
  [ -n "${cur_host:-}" ] && [ "$rows" -eq 0 ] && printf 'No PHP-FPM branch installed.\n'
  return 0
}

echo "# PHP2Shell report"
for log in "$@"; do
  if [ ! -r "$log" ]; then
    echo "unreadable log: $log" >&2
    rc=1
    continue
  fi
  hosts=0
  cur_host=""
  while IFS= read -r line; do
    [[ $line == '@p2s '* ]] || continue
    declare -A r=()
    read -ra toks <<<"${line#@p2s }"
    for t in "${toks[@]}"; do r[${t%%=*}]=${t#*=}; done
    if [ "${r[schema]:-}" != 1 ]; then
      echo "skipped record with schema ${r[schema]:-none} in $log" >&2
      unset r
      continue
    fi
    case ${r[kind]:-} in
      host)
        flush
        cur_host=${r[host]}
        rows=0
        hosts=$((hosts + 1))
        printf '\n## %s (%s)\n\nLog: `%s`\n\n' "${r[host]}" "${r[os]}" "$(basename "$log")"
        ;;
      branch)
        if [ "$rows" -eq 0 ]; then
          echo '| Branch | SAPI | Installed | Origin | Service | CVEs in changelog | Verdict | Reason |'
          echo '|---|---|---|---|---|---|---|---|'
        fi
        v=${r[verdict]}
        [ "$v" = fixed ] || v="**$v**"
        printf '| %s | %s | `%s` | %s | %s | %s | %s | %s |\n' "${r[branch]}" "${r[sapi]}" "${r[installed]}" \
          "${r[origin]}" "${r[active]}" "${r[cve_changelog]}" "$v" "${r[reason]}"
        rows=$((rows + 1))
        ;;
    esac
    unset r
  done <"$log"
  flush
  if [ "$hosts" -eq 0 ]; then
    echo "no host record in $log (did the run reach the host?)" >&2
    rc=1
  fi
done
exit "$rc"
