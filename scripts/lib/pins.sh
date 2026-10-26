# Auto-update keeper: apt pins that hold distro-built PHP branches off the ondrej/sury PPA, and the PPA origin in
# the origins unattended-upgrades accepts. Sourced after p2s.sh and hostfacts.sh; used by autoupdate.sh.

# One pin file per branch. apt reads a preferences.d file only when its name has no extension or the extension
# "pref" (apt_preferences(5)), and "php2shell-php8.3" has one: ".3". Without ".pref" apt would skip it silently.
P2S_PIN_DIR=/etc/apt/preferences.d
p2s_pin_file() { echo "$P2S_PIN_DIR/php2shell-php$1.pref"; }   # $1 branch
# The origin entry. apt.conf.d takes names with no extension or ".conf"; this one has none.
P2S_UU_CONF=/etc/apt/apt.conf.d/51php2shell-ppa-origins

# The PPA's PHP sources with what the cached Release file says about them, one "uri|suite|site|origin|label"
# per line ("-" when apt has no cached Release file for the source). Origin and Label may hold spaces. Only
# ondrej/php and packages.sury.org/php: the same people's nginx and Apache PPAs ship no PHP, and accepting
# their origin would let unattended-upgrades move nginx or Apache to them.
p2s_ppa_releases() {
  local file uri suite site lists cached origin label
  lists=$(p2s_path /var/lib/apt/lists)
  while IFS='|' read -r file uri suite; do
    [ -n "$uri" ] || continue
    uri=${uri%/}
    case $uri in */ondrej/php | */ondrej/php/* | *://packages.sury.org/php | *://packages.sury.org/php/*) ;; *) continue ;; esac
    site=${uri#*://}
    site=${site%%/*}
    cached=$lists/$(p2s_inrelease_name "$uri" "$suite")
    [ -f "$cached" ] || cached=${cached%_InRelease}_Release
    origin=$(sed -nE 's/^Origin: (.*)$/\1/p' "$cached" 2>/dev/null | head -1)
    label=$(sed -nE 's/^Label: (.*)$/\1/p' "$cached" 2>/dev/null | head -1)
    echo "$uri|$suite|$site|${origin:--}|${label:--}"
  done <<<"$(p2s_php_sources)" | sort -u
}

# Installed packages of every PHP branch, one "branch|package|version" per line: php8.3, php8.3-*,
# libapache2-mod-php8.3. Not the unversioned php-* packages.
p2s_php_packages() {
  dpkg-query -W -f='${db:Status-Abbrev}|${binary:Package}|${Version}\n' 'php*' 'libapache2-mod-php*' </dev/null 2>/dev/null \
    | awk -F'|' '$1 !~ /^ii/ { next }
      match($2, /^php[0-9]+\.[0-9]+(-|$)/) { b = substr($2, 4, RLENGTH - 3); sub(/-$/, "", b); print b "|" $2 "|" $3; next }
      $2 ~ /^libapache2-mod-php[0-9]+\.[0-9]+$/ { b = $2; sub(/^libapache2-mod-php/, "", b); print b "|" $2 "|" $3 }'
}

# A package's state in apt-cache policy now: "<installed> <candidate> <ppa> <installed origin> <candidate
# origin>", ppa being yes when a PPA source offers any build of it, "(none)" for no installed build or no
# candidate. A build's origin is that of the first source listed under it (p2s_url_origin), from its version
# string (p2s_origin) when no source there says ppa or distro, as for a build only in /var/lib/dpkg/status.
p2s_policy_state() { # $1 package
  local out inst cand ppa=no io="" co="" v pr uri dist o
  out=$(apt-cache policy "$1" </dev/null 2>/dev/null)
  inst=$(sed -nE 's/^  Installed: (.*)$/\1/p' <<<"$out" | head -1)
  cand=$(sed -nE 's/^  Candidate: (.*)$/\1/p' <<<"$out" | head -1)
  inst=${inst:-(none)} cand=${cand:-(none)}
  # Version lines (" *** <version> <priority>" for the installed one) each followed by their source lines.
  while IFS='|' read -r v pr uri dist; do
    [ -n "$uri" ] || continue
    o=$(p2s_url_origin "$uri" "$dist")
    [ "$o" = ppa ] && ppa=yes
    [ "$o" != other ] || continue
    [ "$v" = "$inst" ] && [ -z "$io" ] && io=$o
    [ "$v" = "$cand" ] && [ -z "$co" ] && co=$o
  done < <(awk '/^ \*\*\* [^ ]+ -?[0-9]+$|^     [^ ]+ -?[0-9]+$/ { v = $(NF - 1); pr = $NF; next }
    v != "" && /^ +-?[0-9]+ [a-z+]+:\/\// { print v "|" pr "|" $2 "|" $3 }' <<<"$out")
  echo "$inst $cand $ppa ${io:-$(p2s_origin "$inst")} ${co:-$(p2s_origin "$cand")}"
}

# The pin the keeper writes for a branch, one stanza per PPA site.
p2s_pin_content() { # $1 branch, then the PPA sites
  local b=$1 site
  shift
  for site in "$@"; do
    [ "$site" = "$1" ] || echo
    echo "Explanation: Managed by php2shell-fixer. PHP $b here is a distro build; the $site PPA must not replace it."
    echo "Explanation: Rollback: rm $(p2s_pin_file "$b")"
    echo "Package: php$b php$b-* libapache2-mod-php$b"
    echo "Pin: origin $site"
    echo "Pin-Priority: -1"
  done
}

# Does a Pin line point at a PPA source? $1 pin, $2 site, $3 origin, $4 label, $5 suite.
p2s_pin_targets() {
  local pin=$1 kv k v kvs hit=no
  case $pin in
    origin\ *) v=${pin#origin }; [ "${v//\"/}" = "$2" ] ;;
    release\ *)
      IFS=, read -ra kvs <<<"${pin#release }"
      for kv in "${kvs[@]}"; do
        k=${kv%%=*} v=${kv#*=}
        k=${k// /} v=${v//\"/}
        case $k in
          o | origin) [ "$v" = "$3" ] && hit=yes ;;
          l | label) [ "$v" = "$4" ] && hit=yes ;;
          a | archive | n | codename) [ "$v" = "$5" ] ;;
          *) false ;;
        esac || return 1
      done
      [ "$hit" = yes ] ;;
    *) false ;;
  esac
}

# A pin already in place that keeps a branch off one PPA source: a stanza with a negative priority whose Pin
# targets the source and whose Package patterns cover every installed package of the branch. Recognised by
# content in /etc/apt/preferences and every file in preferences.d, whatever its name; whether apt applies it
# is for apt-cache policy to say. Prints the file, or nothing.
p2s_pin_existing() { # $1 site, $2 origin, $3 label, $4 suite, then the branch's packages
  local site=$1 origin=$2 label=$3 suite=$4 f pk pin pr pats p pkg covered
  shift 4
  for f in "$(p2s_path /etc/apt/preferences)" "$(p2s_path "$P2S_PIN_DIR")"/*; do
    [ -f "$f" ] || continue
    while IFS=$'\t' read -r pk pin pr; do
      [[ $pr =~ ^-[0-9]+$ ]] && p2s_pin_targets "$pin" "$site" "$origin" "$label" "$suite" || continue
      read -ra pats <<<"$pk"
      for pkg in "$@"; do
        covered=no
        for p in "${pats[@]}"; do
          if [[ $p == /*/ ]]; then [[ $pkg =~ ${p:1:-1} ]] && covered=yes
          elif [[ $pkg == $p ]]; then covered=yes
          fi
        done
        [ "$covered" = yes ] || continue 2
      done
      echo "${f#"${P2S_ROOT:-}"}"
      return
    done < <(awk 'function out() { if (pk != "" && pin != "" && pr != "") print pk "\t" pin "\t" pr; pk = pin = pr = "" }
      /^[[:space:]]*$/ { out(); next }
      /^Package:/ { pk = $0; sub(/^Package:[[:space:]]*/, "", pk) }
      /^Pin:/ { pin = $0; sub(/^Pin:[[:space:]]*/, "", pin) }
      /^Pin-Priority:/ { pr = $2 }
      END { out() }' "$f")
  done
}

# The origins unattended-upgrades accepts, as apt sees them after merging every apt.conf.d file: one
# "allowed <origin:archive>" or "pattern <key=value,...>" per line.
p2s_uu_origins() {
  apt-config dump </dev/null 2>/dev/null | sed -nE \
    -e 's/^Unattended-Upgrade::Allowed-Origins:: "([^"]*)";$/allowed \1/p' \
    -e 's/^Unattended-Upgrade::Origins-Pattern:: "([^"]*)";$/pattern \1/p'
}

# Does an accepted origin already cover a PPA source? $1 line from p2s_uu_origins, $2 origin, $3 suite,
# $4 the host's codename (for ${distro_codename}).
p2s_uu_covers() {
  local kind=${1%% *} v=${1#* } o a kv k kvs hit=no
  v=${v//\$\{distro_codename\}/$4}
  if [ "$kind" = allowed ]; then
    o=${v%:*} a=${v##*:}
    [ "$o" = "$2" ] && [ "$a" = "$3" ]
    return
  fi
  IFS=, read -ra kvs <<<"$v"
  for kv in "${kvs[@]}"; do
    k=${kv%%=*} v=${kv#*=}
    case $k in
      o | origin) [ "$v" = "$2" ] && hit=yes ;;
      a | archive | suite | n | codename) [ "$v" = "$3" ] ;;
      *) true ;;
    esac || return 1
  done
  [ "$hit" = yes ]
}

# The host's release codename (noble) from os-release, or nothing.
p2s_codename() {
  sed -nE 's/^VERSION_CODENAME="?([^"]*)"?$/\1/p' "$(p2s_path /etc/os-release)" 2>/dev/null | head -1
}
