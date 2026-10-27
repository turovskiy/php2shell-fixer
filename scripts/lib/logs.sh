# shellcheck shell=bash
# Saved run logs (run.sh), read locally by report.sh and next.sh: which host and mode a log belongs to,
# the newest log per host and mode, and what a log found.

# "target<TAB>mode<TAB>stamp" of a log, from its run record. Logs written before run records existed fall
# back to the file name <target>-<mode>-<stamp>.log; anything else is its own target with mode unknown.
p2s_log_meta() { # $1 log
  local line b
  line=$(grep -m1 '^@p2s schema=1 kind=run ' "$1" 2>/dev/null)
  if [ -n "$line" ]; then
    sed -nE 's/.* target=([^ ]+) mode=([^ ]+) started=([^ ]+).*/\1\t\2\t\3/p' <<<"$line"
    return
  fi
  b=$(basename "$1" .log)
  if [[ $b =~ ^(.+)-(audit|ensure|fix|autoupdate)-([0-9]{8}T[0-9.]+Z)(-[0-9]+)?$ ]]; then
    printf '%s\t%s\t%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
  else
    printf '%s\tunknown\t0\n' "$b"
  fi
}

# Logs run.sh wrote into a cache dir, one path per line. The dir may hold other files (hand-written logs from
# before the plugin), so only names of the form <host>-<mode>-<UTC stamp>.log count.
p2s_cache_logs() { # $1 dir
  local f
  for f in "$1"/*.log; do
    [[ ${f##*/} =~ -(audit|ensure|fix|autoupdate)-[0-9]{8}T[0-9.]+Z(-[0-9]+)?\.log$ ]] && echo "$f"
  done
}

# The newest readable log per host and mode, one "target<TAB>mode<TAB>stamp<TAB>path" per line, ordered by
# host, then mode. Stamps are UTC with a fixed layout, so text order is time order.
p2s_newest_logs() { # $@ logs
  local f
  for f in "$@"; do
    [ -r "$f" ] || continue
    printf '%s\t%s\n' "$(p2s_log_meta "$f")" "$f"
  done | sort -t "$(printf '\t')" -k1,1 -k2,2 -k3,3r | awk -F'\t' '!seen[$1 FS $2]++'
}

# What a log found, as one line of key=value words:
# status (ok | exit-<n> | unreachable | timeout | none for a log without run_end), exit, reached (a host
# record exists), unfixed and restart_needed (branches; a SAPI other than FPM is named, 8.3/apache2), nofix
# (unfixed branches whose release gets no free fix, as branch:reason; not in unfixed, a patch cannot close them),
# unmitigated (branch/sapi:state), overrides (file:line of pool overrides that re-enable upload progress),
# apache_overrides (the same for Apache config), hook (the apt hook's state: present, missing, outdated),
# ppa (yes when the log names an ondrej/sury PPA source), ppa_covered (the audit's unattended-upgrades check),
# keeper (the auto-update keeper's end state), refused (branches the keeper refused), loose_pins (pins that did
# not hold a branch), probe (the patch's HTTP probe: unchanged, changed, no-sites). "-" stands for none.
p2s_log_summary() { # $1 log
  awk '
    function add(v, x) { return v == "" ? x : (index("," v ",", "," x ",") ? v : v "," x) }
    function gap(t) { return t == "no-fix-for-release" || t == "fix-only-in-esm" }
    function bs() { return (r["sapi"] == "" || r["sapi"] == "fpm") ? r["branch"] : r["branch"] "/" r["sapi"] }
    /^@p2s schema=1 / {
      delete r
      for (i = 3; i <= NF; i++) { k = $i; sub(/=.*/, "", k); v = $i; sub(/^[^=]*=/, "", v); r[k] = v }
      if (r["kind"] == "host") reached = "yes"
      else if (r["kind"] == "run_end") { status = r["status"]; ex = r["exit"] }
      else if (r["kind"] == "branch") {
        if (r["verdict"] != "fixed" && gap(r["target_reason"])) nf = add(nf, bs() ":" r["target_reason"])
        else if (r["verdict"] != "fixed") unf = add(unf, bs())
        if (r["restart"] == "needed") rn = add(rn, bs())
      }
      else if (r["kind"] == "fix" && r["fixed"] == "no" && gap(r["target_reason"])) nf = add(nf, bs() ":" r["target_reason"])
      else if (r["kind"] == "fix" && r["fixed"] == "no") unf = add(unf, bs())
      else if (r["kind"] == "mitigation" && r["state"] != "mitigated") um = add(um, r["branch"] "/" r["sapi"] ":" r["state"])
      else if (r["kind"] == "override" && r["enables"] == "yes") {
        if (r["sapi"] == "apache2") aov = add(aov, r["file"] ":" r["line"])
        else ov = add(ov, r["file"] ":" r["line"])
      }
      else if (r["kind"] == "ensure_hook") hook = r["state"]
      else if (r["kind"] == "probe_summary") probe = r["state"]
      else if (r["kind"] == "source" || r["kind"] == "ppa") ppa = "yes"
      else if (r["kind"] == "autoupdate") cov = r["ppa_covered"]
      else if (r["kind"] == "keeper") { keeper = r["state"]; if (r["branches"] != "") ref = r["branches"] }
      else if (r["kind"] == "policy" && r["state"] == "pin-ineffective") lp = add(lp, r["pin"])
    }
    END {
      printf "status=%s exit=%s reached=%s unfixed=%s restart_needed=%s unmitigated=%s overrides=%s apache_overrides=%s hook=%s",
        (status == "" ? "none" : status), (ex == "" ? "-" : ex), (reached == "" ? "no" : reached),
        (unf == "" ? "-" : unf), (rn == "" ? "-" : rn), (um == "" ? "-" : um), (ov == "" ? "-" : ov),
        (aov == "" ? "-" : aov), (hook == "" ? "-" : hook)
      printf " ppa=%s ppa_covered=%s keeper=%s refused=%s loose_pins=%s nofix=%s", (ppa == "" ? "no" : ppa),
        (cov == "" ? "-" : cov), (keeper == "" ? "-" : keeper), (ref == "" ? "-" : ref), (lp == "" ? "-" : lp),
        (nf == "" ? "-" : nf)
      printf " probe=%s\n", (probe == "" ? "-" : probe)
    }' "$1"
}
