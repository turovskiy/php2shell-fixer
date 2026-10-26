# One PHP branch judged on the host: its installed build, the builds apt offers, and the target. Shared
# by audit.sh (reports it) and fix.sh (installs the target), so the patcher has no selection logic of its own.
# Sourced after p2s.sh. Candidate .debs go into $P2S_TMP, which the caller creates and removes.
# Every command here reads /dev/null: the program itself arrives on stdin (ssh host 'bash -s').

# Does the build apt would install name both CVEs? $1 package, $2 version.
# Prints yes | no | missing (no changelog in the .deb) | download-failed. Installs nothing.
p2s_candidate_cve() {
  local d log="" deb=""
  d=$(mktemp -d "$P2S_TMP/deb.XXXXXX") || { echo download-failed; return; }
  if ! (cd "$d" && apt-get download -q "$1=$2" </dev/null >/dev/null 2>&1); then
    echo download-failed
  else
    for deb in "$d"/*.deb; do
      [ -f "$deb" ] || continue
      log=$(dpkg-deb --fsys-tarfile "$deb" </dev/null 2>/dev/null \
        | tar -xO --wildcards './usr/share/doc/*/changelog.Debian.gz' 2>/dev/null | zcat 2>/dev/null)
    done
    if [ -z "${deb:-}" ] || [ ! -f "$deb" ]; then echo download-failed
    elif [ -z "$log" ]; then echo missing
    elif p2s_changelog_has_cves "$log"; then echo yes
    else echo no
    fi
  fi
  rm -rf "$d"
}

# Does the installed changelog of a branch name both CVEs? yes | no | missing
p2s_installed_cve() { # $1 branch
  local changelog
  changelog=$(p2s_path "/usr/share/doc/php$1-common/changelog.Debian.gz")
  if [ ! -f "$changelog" ]; then echo missing
  elif p2s_changelog_has_cves "$(zcat "$changelog" 2>/dev/null)"; then echo yes
  else echo no
  fi
}

# Installed packages of a versioned branch that serve the web through a service, one
# "branch|sapi|package|version" per line: PHP-FPM (8.3|fpm|php8.3-fpm|...) and mod_php
# (8.3|apache2|libapache2-mod-php8.3|...). Not the php-fpm metapackage, not removed ones.
p2s_branch_packages() {
  dpkg-query -W -f='${db:Status-Abbrev}|${binary:Package}|${Version}\n' 'php*-fpm' 'libapache2-mod-php*' </dev/null 2>/dev/null \
    | awk -F'|' '$1 !~ /^ii/ { next }
      $2 ~ /^php[0-9]+\.[0-9]+-fpm$/ { b = $2; sub(/^php/, "", b); sub(/-fpm$/, "", b); print b "|fpm|" $2 "|" $3 }
      $2 ~ /^libapache2-mod-php[0-9]+\.[0-9]+$/ { b = $2; sub(/^libapache2-mod-php/, "", b); print b "|apache2|" $2 "|" $3 }'
}

# Did the SAPI's service restart after the branch's packages were last installed? A running pool or Apache
# keeps the build it started with. Prints "<started> <installed> <ok|needed|not-running|unknown>", times as
# UTC ISO. Install time is the newest dpkg file list of the branch (php8.3-*.list, plus
# libapache2-mod-php8.3.list for mod_php), so an extension upgrade counts.
p2s_restart_state() { # $1 branch, $2 service state from is-active, $3 sapi (fpm when absent)
  local sapi=${3:-fpm} started s_epoch="" f t i_epoch="" state
  started=$(systemctl show -p ActiveEnterTimestamp --value "$(p2s_sapi_unit "$1" "$sapi")" </dev/null 2>/dev/null)
  # date -d "" means today 00:00, so an empty or n/a start time must not reach it.
  case $started in '' | n/a) ;; *) s_epoch=$(date -u -d "$started" +%s 2>/dev/null) ;; esac
  local lists=("$(p2s_path /var/lib/dpkg/info)/php$1-"*.list)
  [ "$sapi" = apache2 ] && lists+=("$(p2s_path "/var/lib/dpkg/info/libapache2-mod-php$1.list")")
  for f in "${lists[@]}"; do
    [ -f "$f" ] || continue
    t=$(stat -c %Y "$f")
    if [ -z "$i_epoch" ] || [ "$t" -gt "$i_epoch" ]; then i_epoch=$t; fi
  done
  if [ "$2" != active ]; then state=not-running
  elif [ -z "$s_epoch" ] || [ -z "$i_epoch" ]; then state=unknown
  elif [ "$s_epoch" -ge "$i_epoch" ]; then state=ok
  else state=needed
  fi
  echo "$(if [ "$2" = active ]; then p2s_iso "$s_epoch"; else echo -; fi) $(p2s_iso "$i_epoch") $state"
}

# When the apt lists of one origin last changed: the newest Packages list of that origin, as UTC ISO time,
# or "unknown". Candidates are only as fresh as these lists.
p2s_lists_date() { # $1 origin
  local f t newest=""
  for f in "$(p2s_path /var/lib/apt/lists)"/*_Packages*; do
    [ -f "$f" ] && [ "$(p2s_list_origin "$f")" = "$1" ] || continue
    t=$(stat -c %Y "$f")
    if [ -z "$newest" ] || [ "$t" -gt "$newest" ]; then newest=$t; fi
  done
  p2s_iso "$newest"
}

# Judge one branch through one of its SAPI packages. $1 host, $2 branch, $3 installed version, $4 the SAPI's
# package (php8.3-fpm when absent), $5 its sapi (fpm when absent). Sets BR_ORIGIN, BR_CVE, BR_VERDICT,
# BR_REASON, BR_TARGET, BR_TREASON, BR_LISTS, BR_STALE, and the arrays BR_CHUMAN (lines for people) and
# BR_CRECORDS (one "candidate" record per build apt offers). A candidate's changelog is fetched once per run,
# however many SAPIs of the branch ask (P2S_CVE_SEEN).
p2s_branch_eval() {
  local host=$1 branch=$2 ver=$3 pkg=${4:-php$2-fpm} sapi=${5:-fpm} policy offered cv co ccve cverdict creason cands=()
  declare -gA P2S_CVE_SEEN
  # Origins come from the sources apt-cache policy lists under each build: Debian's plain 8.4.11-1 is told
  # from a third-party build only by its deb.debian.org source.
  policy=$(apt-cache policy "$pkg" </dev/null 2>/dev/null)
  BR_ORIGIN=$(p2s_build_origin "$policy" "$ver")
  BR_CVE=$(p2s_installed_cve "$branch")
  read -r BR_VERDICT BR_REASON <<<"$(p2s_verdict "$branch" "$ver" "$BR_ORIGIN" "$BR_CVE")"
  BR_CHUMAN=() BR_CRECORDS=()
  # Every build apt offers for the branch. Only an unfixed branch gets its candidates judged, and only
  # those of its own origin that are newer than the installed build: the rest cannot become the target.
  offered=$(apt-cache madison "$pkg" </dev/null 2>/dev/null | awk -F'|' '{gsub(/ /, "", $2)} $2 != "" && !seen[$2]++ {print $2}')
  while IFS= read -r cv; do
    [ -n "$cv" ] || continue
    co=$(p2s_build_origin "$policy" "$cv")
    if [ "$BR_VERDICT" = unfixed ] && [ "$co" = "$BR_ORIGIN" ] && dpkg --compare-versions "$cv" gt "$ver"; then
      ccve=${P2S_CVE_SEEN[$branch=$cv]:-}
      [ -n "$ccve" ] || { ccve=$(p2s_candidate_cve "php$branch-common" "$cv"); P2S_CVE_SEEN[$branch=$cv]=$ccve; }
      read -r cverdict creason <<<"$(p2s_verdict "$branch" "$cv" "$co" "$ccve")"
    else
      ccve=not-checked cverdict=- creason=not-assessed
    fi
    cands+=("$cv|$co|$cverdict")
    BR_CHUMAN+=("  offered $cv ($co): CVEs in changelog: $ccve -> $cverdict ($creason)")
    BR_CRECORDS+=("$(p2s_record kind=candidate host="$host" branch="$branch" version="$cv" origin="$co" \
      cve_changelog="$ccve" verdict="$cverdict" reason="$creason" sapi="$sapi")")
  done <<<"$offered"
  read -r BR_TARGET BR_TREASON <<<"$(p2s_target "$ver" "$BR_ORIGIN" "$BR_VERDICT" "${cands[@]}")"
  BR_LISTS=$(p2s_lists_date "$BR_ORIGIN")
  BR_STALE=$(p2s_lists_stale "$BR_LISTS")
}
