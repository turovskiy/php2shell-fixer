# Host facts that decide how to patch: which site runs on which FPM pool (and which sites Apache serves),
# whether FPM restarted after the last PHP install, held packages, the ondrej/sury sources and their Release
# info, unattended-upgrades. Read-only. Sourced after p2s.sh; used by audit.sh, fix.sh and autoupdate.sh.

# Sites from "nginx -T" output (effective config: symlinked and included files count). Prints one
# "names|pass" line per fastcgi_pass in a server block, names comma-joined ("-" without server_name).
# A pass naming an upstream is resolved to that upstream's servers.
p2s_nginx_sites() { # $1 nginx -T output
  awk '
    function handle(st,   w, k, j) {
      gsub(/^[ \t]+|[ \t]+$/, "", st)
      if (st == "") return
      if (st ~ /\{$/) {
        sub(/[ \t]*\{$/, "", st); split(st, w, /[ \t]+/)
        depth++
        if (w[1] == "server" && !insrv && !inup) { insrv = depth; names = ""; np = 0 }
        else if (w[1] == "upstream") { inup = depth; upname = w[2] }
        return
      }
      if (st == "}") {
        if (depth == insrv) {
          for (j = 1; j <= np; j++) site[++ns] = (names == "" ? "-" : names) "|" pass[j]
          insrv = 0
        }
        if (depth == inup) inup = 0
        depth--
        return
      }
      sub(/;$/, "", st); k = split(st, w, /[ \t]+/)
      if (insrv && w[1] == "server_name") { for (j = 2; j <= k; j++) names = names (names == "" ? "" : ",") w[j] }
      else if (insrv && w[1] == "fastcgi_pass") pass[++np] = w[2]
      else if (inup && w[1] == "server") up[upname] = up[upname] (up[upname] == "" ? "" : " ") w[2]
    }
    {
      sub(/#.*/, "")
      line = $0
      gsub(/\{/, " {\n", line); gsub(/\}/, "\n}\n", line); gsub(/;/, ";\n", line)
      n = split(line, parts, "\n")
      for (i = 1; i <= n; i++) handle(parts[i])
    }
    END {
      for (i = 1; i <= ns; i++) {
        split(site[i], f, "|")
        if (f[2] in up) { k = split(up[f[2]], s, " "); for (j = 1; j <= k; j++) print f[1] "|" s[j] }
        else print site[i]
      }
    }' <<<"$1"
}

# Vhosts from "apachectl -S" output (Apache's own vhost dump, so symlinked and included sites count), one
# "name|port|address" per line, sorted, each once: name-based vhosts ("port 443 namevhost <name>", "default
# server <name>") under their "<address>:<port> is a NameVirtualHost" line, their aliases, and single vhosts
# ("*:80 <name> (<file>:<line>)"). The address is "-" for any (* or _default_). Wildcard aliases are skipped.
p2s_apache_sites() { # $1 apachectl -S output
  awk '
    function at(ap) { port = ap; sub(/^.*:/, "", port); addr = ap; sub(/:[^:]*$/, "", addr)
      if (addr == "*" || addr == "_default_") addr = "-" }
    $1 ~ /:[0-9]+$/ && $2 == "is" && $3 == "a" { at($1); next }
    $1 == "port" && $3 == "namevhost" { port = $2; print $4 "|" port "|" addr; next }
    $1 == "default" && $2 == "server" { print $3 "|" port "|" addr; next }
    $1 == "alias" { print $2 "|" port "|" addr; next }
    $1 ~ /:[0-9]+$/ && $3 ~ /^\(/ { at($1); print $2 "|" port "|" addr }' <<<"$1" | sort -u
}

# Do an FPM listen address and an nginx fastcgi_pass point at the same socket?
# Unix sockets compare by path (/var/run is /run); TCP by port when either side is loopback or any.
p2s_listen_matches() { # $1 pool listen, $2 fastcgi_pass
  local l=${1#unix:} p=${2#unix:}
  l=${l/#\/var\/run\//\/run\/}
  p=${p/#\/var\/run\//\/run\/}
  if [[ $l == /* || $p == /* ]]; then
    [ "$l" = "$p" ]
    return
  fi
  local lh lp ph pp
  if [[ $l == *:* ]]; then lh=${l%:*} lp=${l##*:}; else lh="" lp=$l; fi
  ph=${p%:*} pp=${p##*:}
  [ "$lp" = "$pp" ] || return 1
  [ "$lh" = "$ph" ] && return 0
  case $lh in '' | '*' | 0.0.0.0 | '[::]') return 0 ;; esac   # pool listens on every address
  case "$lh $ph" in
    127.0.0.1\ 127.0.0.1 | 127.0.0.1\ localhost | localhost\ 127.0.0.1 | '[::1] [::1]' | '[::1] localhost' | 'localhost [::1]') return 0 ;;
  esac
  return 1
}

# FPM pools of a branch, one "pool|listen" per line, from php-fpm.conf and pool.d/*.conf.
p2s_fpm_pools() { # $1 branch
  local f
  for f in "$(p2s_path "/etc/php/$1/fpm/php-fpm.conf")" "$(p2s_path "/etc/php/$1/fpm/pool.d")"/*.conf; do
    [ -f "$f" ] || continue
    awk '
      /^[[:space:]]*\[[^]]+\][[:space:]]*$/ { pool = $0; gsub(/[][[:space:]]/, "", pool); next }
      pool != "" && pool != "global" && /^[[:space:]]*listen[[:space:]]*=/ {
        v = $0; sub(/^[^=]*=[[:space:]]*/, "", v); sub(/[[:space:]]*(;.*)?$/, "", v); gsub(/"/, "", v)
        print pool "|" v
      }' "$f"
  done
}

# Enabled apt sources of the ondrej/sury PPA, one "file|uri|suite" per line (one-line and deb822 format).
p2s_php_sources() {
  local f
  for f in "$(p2s_path /etc/apt/sources.list)" "$(p2s_path /etc/apt/sources.list.d)"/*.list \
    "$(p2s_path /etc/apt/sources.list.d)"/*.sources; do
    [ -f "$f" ] || continue
    case $f in
      *.sources)
        awk -v file="${f#"${P2S_ROOT:-}"}" '
          function out() { if (types ~ /(^| )deb( |$)/ && enabled != "no") for (i = 1; i <= nu; i++) for (j = 1; j <= ns; j++) print file "|" u[i] "|" s[j]; nu = ns = 0; types = ""; enabled = "" }
          /^[[:space:]]*$/ { out(); next }
          /^Types:/ { types = $0; sub(/^Types:[[:space:]]*/, "", types) }
          /^Enabled:/ { enabled = tolower($2) }
          /^URIs:/ { nu = split(substr($0, index($0, ":") + 1), u, /[[:space:]]+/); if (u[1] == "") { for (i = 1; i < nu; i++) u[i] = u[i + 1]; nu-- } }
          /^Suites:/ { ns = split(substr($0, index($0, ":") + 1), s, /[[:space:]]+/); if (s[1] == "") { for (i = 1; i < ns; i++) s[i] = s[i + 1]; ns-- } }
          END { out() }' "$f"
        ;;
      *)
        awk -v file="${f#"${P2S_ROOT:-}"}" '
          /^[[:space:]]*deb[[:space:]]/ {
            i = 2; if ($i ~ /^\[/) { while ($i !~ /\]$/) i++; i++ }
            print file "|" $i "|" $(i + 1)
          }' "$f"
        ;;
    esac
  done | awk -F'|' '$2 ~ /(ondrej|sury)/'
}

# Name apt gives the cached InRelease of a source: https://ppa.launchpadcontent.net/ondrej/php/ubuntu + noble
# -> ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_noble_InRelease
p2s_inrelease_name() { # $1 uri, $2 suite
  local u=${1#*://}
  u=${u%/}
  echo "${u//\//_}_dists_$2_InRelease"
}

# The Release fields apt refuses to see change without consent, one "Field: value" per line.
p2s_release_info() { # $1 InRelease text
  grep -E '^(Origin|Label|Suite|Codename):' <<<"$1" | sort
}

# Has a source's Release info changed since apt cached it? apt-get update refuses such a source until someone
# accepts the change. The fresh InRelease goes into a temp file that is removed again; nothing else is
# written. Prints "<same|changed|unknown> <changed fields, comma-joined, or ->", then for a change the
# differing lines ("  cached: Label: ...", "  remote: Label: ..."). unknown: no cached InRelease, no
# apt-helper, or the fetch failed.
p2s_release_check() { # $1 uri, $2 suite
  local cached helper dest old new info=unknown changed=- diffs=""
  cached=$(p2s_path /var/lib/apt/lists)/$(p2s_inrelease_name "$1" "$2")
  helper=$(p2s_path /usr/lib/apt/apt-helper)
  if [ -f "$cached" ] && [ -x "$helper" ] && dest=$(mktemp); then
    if timeout 30 "$helper" -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 \
      download-file "${1%/}/dists/$2/InRelease" "$dest" </dev/null >/dev/null 2>&1; then
      old=$(p2s_release_info "$(cat "$cached")")
      new=$(p2s_release_info "$(cat "$dest")")
      if [ "$old" = "$new" ]; then
        info=same
      else
        info=changed
        changed=$(diff <(echo "$old") <(echo "$new") | sed -nE 's/^[<>] ([A-Za-z]+):.*/\1/p' | sort -u | paste -sd, -)
        diffs=$(diff <(echo "$old") <(echo "$new") | sed -nE 's/^< /  cached: /p; s/^> /  remote: /p')
      fi
    fi
    rm -f "$dest"
  fi
  echo "$info $changed"
  [ -z "$diffs" ] || printf '%s\n' "$diffs"
}

# Encode a value for a record: records split on spaces.
p2s_enc() {
  local v=${1//%/%25}
  echo "${v// /%20}"
}
