#!/usr/bin/env bash
# Renders saved run logs as a markdown report, one section per host: a table of PHP-FPM branches (audit),
# a table of the upload_progress mitigation per web SAPI (audit and ensure) with overrides below it, and
# the host facts (audit): sites and pools, held packages, PPA sources, unattended-upgrades.
# Reads only the "@p2s" records, so the report says exactly what the logged run found.
# Usage: report.sh <log>...
# Exit:  0; 1 when a log is unreadable or holds no host record; 2 on bad usage.
set -uo pipefail

[ $# -gt 0 ] || { echo "usage: report.sh <log>..." >&2; exit 2; }

rc=0
branches=() mitigations=() overrides=() sites=() pools=() holds=() sources=() origins=() facts=()
dec() { local v=${1//%20/ }; echo "${v//%25/%}"; }   # values were encoded with p2s_enc
flush() { # print the current host section
  [ -n "${cur_host:-}" ] || return 0
  if [ ${#branches[@]} -gt 0 ]; then
    echo '| Branch | SAPI | Installed | Origin | Service | Restart | CVEs in changelog | Verdict | Reason | Target | apt lists |'
    echo '|---|---|---|---|---|---|---|---|---|---|---|'
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
  if [ ${#facts[@]} -gt 0 ]; then
    printf '\n### Host facts\n\n'
    printf '%s\n' "${facts[@]}"
  fi
  if [ ${#sites[@]} -gt 0 ]; then
    printf '\n| Site | fastcgi_pass | Branch | Pool |\n|---|---|---|---|\n'
    printf '%s\n' "${sites[@]}"
  fi
  if [ ${#pools[@]} -gt 0 ]; then
    printf '\n| Branch | Pool | Listen | Sites | Used |\n|---|---|---|---|---|\n'
    printf '%s\n' "${pools[@]}"
  fi
  if [ ${#holds[@]} -gt 0 ]; then
    printf '\nHeld PHP packages (apt will not upgrade them): %s\n' "${holds[*]}"
  fi
  if [ ${#sources[@]} -gt 0 ]; then
    printf '\n| PPA source | URI | Suite | Release info |\n|---|---|---|---|\n'
    printf '%s\n' "${sources[@]}"
  fi
  if [ ${#origins[@]} -gt 0 ]; then
    printf '\nunattended-upgrades origins: %s\n' "${origins[*]}"
  fi
  branches=() mitigations=() overrides=() sites=() pools=() holds=() sources=() origins=() facts=()
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
        # Logs written before the restart check carry no restart field.
        case ${r[restart]:-} in
          '') rs=- ;;
          needed) rs="**needed** (started ${r[started]%%T*}, installed ${r[installed_at]%%T*})" ;;
          *) rs=${r[restart]} ;;
        esac
        branches+=("$(printf '| %s | %s | `%s` | %s | %s | %s | %s | %s | %s | %s | %s |' "${r[branch]}" "${r[sapi]}" \
          "${r[installed]}" "${r[origin]}" "${r[active]}" "$rs" "${r[cve_changelog]}" "$v" "${r[reason]}" "$tgt" "$lists")")
        ;;
      mitigation)
        m=${r[state]}
        [ "$m" = mitigated ] || m="**$m**"
        mitigations+=("$(printf '| %s | %s | %s | %s | %s | %s | %s |' "${r[branch]}" "${r[sapi]}" "${r[ini]}" \
          "${r[action]}" "${r[upload_progress]}" "${r[overrides]}" "$m")")
        ;;
      webserver)
        facts+=("- Web servers: nginx ${r[nginx]}, apache2 ${r[apache2]}")
        ;;
      vhost)
        sites+=("$(printf '| %s | `%s` | %s | %s |' "$(dec "${r[names]}")" "$(dec "${r[pass]}")" "${r[branch]}" "${r[pool]}")")
        ;;
      pool)
        case ${r[used]} in
          no) u="**unused: stop candidate**" ;;
          unknown) u="unknown (Apache or no readable nginx config)" ;;
          *) u=${r[used]} ;;
        esac
        pools+=("$(printf '| %s | %s | `%s` | %s | %s |' "${r[branch]}" "${r[pool]}" "$(dec "${r[listen]}")" "${r[sites]}" "$u")")
        ;;
      hold)
        holds+=("\`${r[package]}\`")
        ;;
      source)
        case ${r[release_info]} in
          changed) ri="**changed: ${r[changed]}** - apt-get update refuses this source until the change is accepted" ;;
          *) ri=${r[release_info]} ;;
        esac
        sources+=("$(printf '| `%s` | %s | %s | %s |' "${r[file]}" "${r[uri]}" "${r[suite]}" "$ri")")
        ;;
      autoupdate)
        a="- unattended-upgrades: periodic ${r[periodic]}, ${r[origins]} origin(s), ondrej PPA covered: ${r[ppa_covered]}"
        [ "${r[ppa_covered]}" = no ] && a+=" - **PPA PHP is not updated automatically**"
        facts+=("$a")
        ;;
      uu_origin)
        origins+=("\`$(dec "${r[value]}")\`")
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
