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
  if [[ $b =~ ^(.+)-(audit|ensure|fix)-([0-9]{8}T[0-9.]+Z)(-[0-9]+)?$ ]]; then
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
    [[ ${f##*/} =~ -(audit|ensure|fix)-[0-9]{8}T[0-9.]+Z(-[0-9]+)?\.log$ ]] && echo "$f"
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
# record exists), unfixed and restart_needed (branches), unmitigated (branch/sapi:state), overrides
# (file:line of pool overrides that re-enable upload progress). "-" stands for none.
p2s_log_summary() { # $1 log
  awk '
    function add(v, x) { return v == "" ? x : v "," x }
    /^@p2s schema=1 / {
      delete r
      for (i = 3; i <= NF; i++) { k = $i; sub(/=.*/, "", k); v = $i; sub(/^[^=]*=/, "", v); r[k] = v }
      if (r["kind"] == "host") reached = "yes"
      else if (r["kind"] == "run_end") { status = r["status"]; ex = r["exit"] }
      else if (r["kind"] == "branch") {
        if (r["verdict"] != "fixed") unf = add(unf, r["branch"])
        if (r["restart"] == "needed") rn = add(rn, r["branch"])
      }
      else if (r["kind"] == "mitigation" && r["state"] != "mitigated") um = add(um, r["branch"] "/" r["sapi"] ":" r["state"])
      else if (r["kind"] == "override" && r["enables"] == "yes") ov = add(ov, r["file"] ":" r["line"])
    }
    END {
      printf "status=%s exit=%s reached=%s unfixed=%s restart_needed=%s unmitigated=%s overrides=%s\n",
        (status == "" ? "none" : status), (ex == "" ? "-" : ex), (reached == "" ? "no" : reached),
        (unf == "" ? "-" : unf), (rn == "" ? "-" : rn), (um == "" ? "-" : um), (ov == "" ? "-" : ov)
    }' "$1"
}
