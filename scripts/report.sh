#!/usr/bin/env bash
# Renders saved run logs as a markdown report, one section per host: a table of PHP-FPM and mod_php
# (SAPI apache2) branches (audit), a table of the upload_progress mitigation per web SAPI (audit and ensure)
# with pool and Apache overrides below it, a table of patched SAPIs with the HTTP probe (fix), what the
# auto-update keeper did (autoupdate: each branch's apt candidate before and after the pins, the pins, the
# unattended-upgrades origin and its dry run), and the host facts (audit): sites and pools, held packages,
# PPA sources, unattended-upgrades.
# Reads only the "@p2s" records, so the report says exactly what the logged run found. Of several logs for
# one host and mode, only the newest counts; a host the run could not reach gets a section saying so.
# Usage: report.sh --latest     every run.sh log in ${P2S_CACHE:-$XDG_CACHE_HOME/php2shell}
#        report.sh <log>...
# Exit:  0; 1 when a log is unreadable or holds neither a host nor a run record; 2 on bad usage.
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/logs.sh
. "$HERE/lib/logs.sh"
CACHE=${P2S_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/php2shell}

case ${1:-} in
  '') echo "usage: report.sh --latest | report.sh <log>..." >&2; exit 2 ;;
  --latest) mapfile -t logs < <(p2s_cache_logs "$CACHE") ;;
  *) logs=("$@") ;;
esac

rc=0
for log in "${logs[@]}"; do
  [ -r "$log" ] || { echo "unreadable log: $log" >&2; rc=1; }
done
branches=() mitigations=() overrides=() sites=() pools=() holds=() sources=() origins=() facts=() patches=() probes=()
keeps=() klines=()
dec() { local v=${1//%20/ }; echo "${v//%25/%}"; }   # values were encoded with p2s_enc
flush() { # print the current host section
  [ -n "${cur_host:-}" ] || return 0
  [ -z "${run_mode:-}" ] || printf 'Run: %s, started %s, %s\n\n' "$run_mode" "$run_started" "${run_status:-no end record}"
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
    echo 'Pool and Apache overrides of `session.upload_progress.enabled`:'
    echo
    printf '%s\n' "${overrides[@]}"
  fi
  if [ ${#patches[@]} -gt 0 ]; then
    [ ${#branches[@]} -eq 0 ] || echo
    echo '| Branch | SAPI | Before | After | Target | Fixed | Restart | Modules | Result |'
    echo '|---|---|---|---|---|---|---|---|---|'
    printf '%s\n' "${patches[@]}"
  fi
  if [ ${#probes[@]} -gt 0 ]; then
    echo
    printf '%s\n' "${probes[@]}"
  fi
  if [ ${#keeps[@]} -gt 0 ] || [ ${#klines[@]} -gt 0 ]; then
    [ ${#branches[@]} -eq 0 ] && [ ${#mitigations[@]} -eq 0 ] && [ ${#patches[@]} -eq 0 ] && [ ${#probes[@]} -eq 0 ] || echo
    echo '### Auto-updates'
    if [ ${#keeps[@]} -gt 0 ]; then
      printf '\n| Branch | Origin | Package | Installed | Candidate before | Candidate now | Pin | Result |\n'
      echo '|---|---|---|---|---|---|---|---|'
      printf '%s\n' "${keeps[@]}"
    fi
    if [ ${#klines[@]} -gt 0 ]; then
      echo
      printf '%s\n' "${klines[@]}"
    fi
  fi
  # A preflight stop leaves no branch rows, but the host has PHP: say nothing rather than "no PHP". A keeper
  # run is about apt, not about the SAPIs.
  [ ${#branches[@]} -gt 0 ] || [ ${#mitigations[@]} -gt 0 ] || [ ${#patches[@]} -gt 0 ] || [ "$mode_seen" = fix ] \
    || [ "$mode_seen" = autoupdate ] || echo 'No PHP-FPM or PHP-CGI installed.'
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
  branches=() mitigations=() overrides=() sites=() pools=() holds=() sources=() origins=() facts=() patches=() probes=()
  keeps=() klines=()
}

echo "# PHP2Shell report"
while IFS=$'\t' read -r _ _ _ log; do
  [ -n "$log" ] || continue
  hosts=0
  cur_host="" run_mode="" run_started="" run_status="" run_target="" mode_seen=""
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
      run)
        run_target=${r[target]} run_mode=${r[mode]} run_started=${r[started]} mode_seen=${r[mode]}
        ;;
      run_end)
        run_status="exit ${r[exit]} (${r[status]})"
        ;;
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
      preflight)
        if [ "${r[result]}" = failed ]; then
          f="- **Preflight stopped the patch: ${r[reason]}**"
          [ -z "${r[packages]:-}" ] || f+=", held: \`${r[packages]}\`"
          [ -z "${r[fields]:-}" ] || f+=", changed Release fields: ${r[fields]}"
          facts+=("$f")
        else
          facts+=("- Backup before the patch: \`${r[backup]}\`")
        fi
        ;;
      fix)
        case ${r[state]} in fixed) fs=fixed ;; *) fs="**${r[state]}**" ;; esac
        tg=${r[target]}
        [ "$tg" = none ] || [ "$tg" = - ] || tg="\`$tg\`"
        # Fix logs from before mod_php support carry no sapi field: those runs patched FPM only.
        patches+=("$(printf '| %s | %s | `%s` | `%s` | %s | %s | %s | %s | %s |' "${r[branch]}" "${r[sapi]:-fpm}" "${r[before]}" \
          "${r[after]}" "$tg" "${r[fixed]}" "${r[restart]}" "${r[modules]}" "$fs")")
        ;;
      probe)
        pr="- \`${r[name]}\`: ${r[before]} -> ${r[after]}"
        [ "${r[before]}" = "${r[after]}" ] || pr+=" - **changed**"
        probes+=("$pr")
        ;;
      probe_summary)
        case ${r[state]} in
          no-sites) probes+=("- HTTP probe: no sites found, nothing compared") ;;
          changed) probes+=("- HTTP probe: **a status code changed**") ;;
          *) probes+=("- HTTP probe: every status code unchanged") ;;
        esac
        ;;
      ensure_hook)
        case ${r[state]} in
          present) h="present" ;;
          *) h="**${r[state]}** - a PHP branch installed later would not get the mitigation" ;;
        esac
        [ -z "${r[action]:-}" ] || h="${r[action]}, now $h"
        facts+=("- apt hook keeping the mitigation in place: $h")
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
      ppa)
        klines+=("- PPA source: ${r[uri]} ${r[suite]}, Origin \`$(dec "${r[origin]}")\`, Label \`$(dec "${r[label]}")\`")
        ;;
      pin)
        klines+=("- Pin for php${r[branch]}: \`${r[file]}\` (${r[action]})")
        ;;
      policy)
        case ${r[state]} in
          kept) ks=kept ;;
          *)
            if [ "${r[moved]}" != - ] || [ "${r[unheld]:--}" = - ]; then ks="**${r[state]}**: ${r[moved]} would move"
            else ks="**${r[state]}**: PPA builds of ${r[unheld]} not held off"
            fi ;;
        esac
        pn=${r[pin]}
        [ "$pn" = - ] || pn="\`$pn\`"
        keeps+=("$(printf '| %s | %s | %s | `%s` | `%s` (%s) | `%s` (%s) | %s | %s |' "${r[branch]}" "${r[origin]}" "${r[package]}" \
          "${r[installed]}" "${r[before]}" "${r[before_origin]:--}" "${r[candidate]}" "${r[candidate_origin]}" "$pn" "$ks")")
        ;;
      uu_entry)
        case ${r[action]} in
          written) u="written to \`${r[file]}\`" ;;
          present) u="already accepted" ;;
          removed) u="**removed again** after the failed dry run" ;;
          *) u=${r[action]} ;;
        esac
        klines+=("- unattended-upgrades origin \`$(dec "${r[value]}")\`: $u")
        ;;
      uu_dryrun)
        case ${r[result]} in
          ok) u="ok, accepts ${r[origins_allowed]}" ;;
          origin-missing) u="**the PPA origin is not among the accepted ones**" ;;
          distro-from-ppa) u="**would upgrade ${r[from_ppa]//,/, } of a distro-built branch from the PPA**" ;;
          *) u="**failed** (exit ${r[exit]})" ;;
        esac
        klines+=("- unattended-upgrade --dry-run: $u")
        ;;
      keeper)
        case ${r[state]} in
          configured) u="configured" ;;
          unchanged) u="already in place, nothing written" ;;
          no-ppa) u="no ondrej/sury PPA on this host, nothing written" ;;
          refused) u="**refused** (php${r[branches]//,/, php}): the origin entry was not written" ;;
          dryrun-failed) u="**the dry run failed**: the origin entry was taken out again" ;;
          *) u="**${r[state]}** (${r[reason]:-})" ;;
        esac
        case ${r[periodic]:-} in
          0 | unset) u+=" - **unattended-upgrades does not run** (APT::Periodic::Unattended-Upgrade ${r[periodic]})" ;;
        esac
        klines+=("- Auto-update keeper: $u")
        ;;
      override)
        if [ "${r[sapi]:-}" = apache2 ]; then o="- php${r[branch]} Apache: "; else o="- php${r[branch]} pool \`${r[pool]}\`: "; fi
        o+="\`${r[file]}:${r[line]}\` ${r[directive]} = ${r[value]}"
        [ "${r[enables]}" = yes ] && o+=" - **re-enables it**"
        overrides+=("$o")
        ;;
    esac
    unset r
  done <"$log"
  if [ "$hosts" -eq 0 ] && [ -n "$run_target" ]; then
    # The run never reached the host: say so, with ssh's own last word.
    printf '\n## %s (%s)\n\nLog: `%s`\n\n' "$run_target" "${run_status:-no end record}" "$(basename "$log")"
    printf 'Run: %s, started %s. Last output: `%s`\n' "$run_mode" "$run_started" "$(grep -v '^@p2s ' "$log" | tail -1)"
  elif [ "$hosts" -eq 0 ]; then
    echo "no host record in $log (did the run reach the host?)" >&2
    rc=1
  fi
  flush
done < <(p2s_newest_logs "${logs[@]}")
exit "$rc"
