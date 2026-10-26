#!/usr/bin/env bash
# Renders saved run logs as a markdown report, one section per host: a table of PHP-FPM branches (audit)
# and a table of the upload_progress mitigation per web SAPI (audit and ensure), overrides listed below it.
# Reads only the "@p2s" records, so the report says exactly what the logged run found.
# Usage: report.sh <log>...
# Exit:  0; 1 when a log is unreadable or holds no host record; 2 on bad usage.
set -uo pipefail

[ $# -gt 0 ] || { echo "usage: report.sh <log>..." >&2; exit 2; }

rc=0
branches=() mitigations=() overrides=()
flush() { # print the current host section
  [ -n "${cur_host:-}" ] || return 0
  if [ ${#branches[@]} -gt 0 ]; then
    echo '| Branch | SAPI | Installed | Origin | Service | CVEs in changelog | Verdict | Reason | Target | apt lists |'
    echo '|---|---|---|---|---|---|---|---|---|---|'
    printf '%s\n' "${branches[@]}"
  fi
  if [ ${#mitigations[@]} -gt 0 ]; then
    [ ${#branches[@]} -eq 0 ] || echo
    echo '| Branch | SAPI | 99-security.ini | Action | upload_progress | Overrides enabling it | Mitigation |'
    echo '|---|---|---|---|---|---|---|'
    printf '%s\n' "${mitigations[@]}"
  fi
  if [ ${#overrides[@]} -gt 0 ]; then
    echo
    echo 'Pool overrides of `session.upload_progress.enabled`:'
    echo
    printf '%s\n' "${overrides[@]}"
  fi
  [ ${#branches[@]} -gt 0 ] || [ ${#mitigations[@]} -gt 0 ] || echo 'No PHP-FPM or PHP-CGI installed.'
  branches=() mitigations=() overrides=()
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
        hosts=$((hosts + 1))
        printf '\n## %s (%s)\n\nLog: `%s`\n\n' "${r[host]}" "${r[os]}" "$(basename "$log")"
        ;;
      branch)
        v=${r[verdict]}
        [ "$v" = fixed ] || v="**$v**"
        # Logs written before targets and list dates existed carry neither field.
        case ${r[target]:-} in
          '') tgt=- ;;
          none) tgt="none (${r[target_reason]:-})" ;;
          *) tgt="\`${r[target]}\`" ;;
        esac
        case ${r[lists_stale]:-} in
          '') lists=- ;;
          yes) lists="**${r[lists_updated]%%T*}, older than the fixes**" ;;
          *) lists=${r[lists_updated]%%T*} ;;
        esac
        branches+=("$(printf '| %s | %s | `%s` | %s | %s | %s | %s | %s | %s | %s |' "${r[branch]}" "${r[sapi]}" \
          "${r[installed]}" "${r[origin]}" "${r[active]}" "${r[cve_changelog]}" "$v" "${r[reason]}" "$tgt" "$lists")")
        ;;
      mitigation)
        m=${r[state]}
        [ "$m" = mitigated ] || m="**$m**"
        mitigations+=("$(printf '| %s | %s | %s | %s | %s | %s | %s |' "${r[branch]}" "${r[sapi]}" "${r[ini]}" \
          "${r[action]}" "${r[upload_progress]}" "${r[overrides]}" "$m")")
        ;;
      override)
        o="- php${r[branch]} pool \`${r[pool]}\`: \`${r[file]}:${r[line]}\` ${r[directive]} = ${r[value]}"
        [ "${r[enables]}" = yes ] && o+=" - **re-enables it**"
        overrides+=("$o")
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
