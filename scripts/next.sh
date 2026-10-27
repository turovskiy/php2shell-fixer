#!/usr/bin/env bash
# The next step per host, read from the newest saved log of each mode, so an interrupted session resumes
# where it stopped. Steps: audit, fix, ensure, autoupdate, verify (audit again after a write), manual (a branch
# whose release gets no free fix, or PHP outside dpkg: only the operator can close it), done.
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
# Who updates each PHP of a foreign word (cpanel:/opt/cpanel/ea-php83/root/usr/sbin/php-fpm,...), "; "-joined.
foreign_text() {
  local e es out=""
  IFS=, read -ra es <<<"$1"
  for e in "${es[@]}"; do
    [ -z "$out" ] || out+="; "
    out+="${e#*:}: "
    case ${e%%:*} in
      cpanel) out+="cPanel's ea-php packages, updated through EasyApache 4 or the system package manager" ;;
      plesk) out+="Plesk's PHP handler, updated through the Plesk installer" ;;
      litespeed) out+="LiteSpeed's lsphp packages, from its repository" ;;
      local) out+="a local build: rebuild it from a fixed PHP release" ;;
      *) out+="not from dpkg; find who installed it and how it is updated" ;;
    esac
  done
  echo "$out"
}
# What closes each branch of a nofix word (8.3:fix-only-in-esm,7.4/apache2:no-fix-for-release), "; "-joined.
nofix_text() {
  local e es out=""
  IFS=, read -ra es <<<"$1"
  for e in "${es[@]}"; do
    [ -z "$out" ] || out+="; "
    case ${e#*:} in
      fix-only-in-esm) out+="php${e%%:*}: fixed only in Ubuntu Pro ESM and no ESM source is enabled; attach Ubuntu Pro (ESM Infra, the Legacy add-on on 16.04 and 14.04), then audit again" ;;
      *) out+="php${e%%:*}: the distro ships no fix for this release; Debian ELTS or TuxCare, the sury build of the branch, or a move to a supported release or branch" ;;
    esac
  done
  echo "$out"
}

# One host at a time: its newest audit, and its newest write run (ensure, fix, autoupdate) if that is newer.
for target in $(cut -f1 <<<"$newest" | sort -u); do
  rows=$(awk -F'\t' -v t="$target" '$1 == t' <<<"$newest")
  audit=$(awk -F'\t' '$2 == "audit"' <<<"$rows")
  write=$(awk -F'\t' '$2 == "ensure" || $2 == "fix" || $2 == "autoupdate"' <<<"$rows" | sort -t "$(printf '\t')" -k3,3r | head -1)
  a_stamp=$(cut -f3 <<<"$audit")
  if [ -z "$audit" ]; then
    step=audit reason="no audit yet"
  else
    a=$(p2s_log_summary "$(cut -f4 <<<"$audit")")
    a_status=$(word status "$a")
    if [ -n "$write" ] && [[ $(cut -f3 <<<"$write") > $a_stamp ]]; then
      w=$(p2s_log_summary "$(cut -f4 <<<"$write")")
      w_mode=$(cut -f2 <<<"$write")
      st=$(word status "$w")
      # A patch whose only open ends are branches no patch can close (mitigated, HTTP unchanged) is finished:
      # the audit sorts out what remains.
      if [ "$w_mode" = fix ] && [ "$st" = exit-3 ] && [ "$(word unfixed "$w")" = - ] && [ "$(word nofix "$w")" != - ] \
        && [ "$(word unmitigated "$w")" = - ] && [ "$(word probe "$w")" != changed ]; then
        st=ok
      fi
      case $st in
        ok | none) step=verify reason="$w_mode finished after the last audit; audit again to confirm" ;;
        *)
          step=$w_mode
          reason="last $w_mode: $(word status "$w")"
          [ "$(word unfixed "$w")" = - ] || reason+=", unfixed: php$(word unfixed "$w" | sed 's/,/, php/g')"
          [ "$(word unmitigated "$w")" = - ] || reason+=", not mitigated: $(word unmitigated "$w")"
          [ "$(word overrides "$w")" = - ] || reason+=", pool override: $(word overrides "$w") (the operator removes it)"
          [ "$(word apache_overrides "$w")" = - ] || reason+=", Apache override: $(word apache_overrides "$w") (the operator removes it)"
          [ "$(word refused "$w")" = - ] || reason+=", refused: php$(word refused "$w" | sed 's/,/, php/g') would change origin"
          [ "$(word loose_pins "$w")" = - ] || reason+=", pin that does not hold: $(word loose_pins "$w")"
          [ "$(word keeper "$w")" != dryrun-failed ] || reason+=", the unattended-upgrade --dry-run check failed and the origin entry was taken out again"
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
      [ "$(word nofix "$a")" = - ] || reason+="; no free fix: $(nofix_text "$(word nofix "$a")")"
      [ "$(word overrides "$a")" = - ] || reason+=", pool override: $(word overrides "$a") (the operator removes it)"
      [ "$(word apache_overrides "$a")" = - ] || reason+=", Apache override: $(word apache_overrides "$a") (the operator removes it)"
    elif [ "$(word hook "$a")" = missing ] || [ "$(word hook "$a")" = outdated ]; then
      step=ensure reason="mitigated, but the apt hook that keeps it in place is $(word hook "$a")"
    elif [ "$(word foreign "$a")" != - ]; then
      step=manual reason="PHP outside dpkg, which this plugin neither judges nor patches: $(foreign_text "$(word foreign "$a")")"
      [ "$(word nofix "$a")" = - ] || reason+="; no free fix: $(nofix_text "$(word nofix "$a")")"
    elif [ "$(word nofix "$a")" != - ]; then
      step=manual reason="mitigated, but no patch can close it here: $(nofix_text "$(word nofix "$a")")"
    elif [ "$(word ppa "$a")" = yes ] && [ "$(word ppa_covered "$a")" = no ]; then
      step=autoupdate reason="the ondrej PPA is configured, but unattended-upgrades does not install PHP updates from it"
    else
      step='done' reason="every branch fixed and restarted, every web SAPI mitigated"
    fi
  fi
  echo "$target: $step - $reason"
done
