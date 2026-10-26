# Auto-update keeper: PHP from the ondrej/sury PPA keeps getting security updates from unattended-upgrades, and
# a distro-built branch never moves to the PPA. Only on a host with the PPA configured; anywhere else it writes
# nothing. The order is the safety:
# 1. every distro-built branch the PPA also ships is pinned off the PPA (Pin-Priority -1,
#    /etc/apt/preferences.d/php2shell-php<X.Y>.pref);
# 2. each installed PHP package's apt-cache policy candidate must keep the origin of its installed build. When
#    one would move, the run stops and names the branch: the pins stay (they only hold a branch where it is),
#    the origin entry is not written;
# 3. the PPA origin goes into the origins unattended-upgrades accepts (/etc/apt/apt.conf.d/51php2shell-ppa-origins),
#    and unattended-upgrade --dry-run must list it; when it does not, that entry is taken out again.
# A pin or origin entry already in place is recognised by content, whatever its file name, and not written
# twice. A pin apt does not apply (a preferences.d name with another extension than .pref) shows in step 2.
# Runs as the tail of the bundle from run.sh (after versions.sh, p2s.sh, hostfacts.sh, branch.sh, pins.sh):
# run.sh autoupdate <host>
# Exit: 0 configured, already in place, or no PPA on the host; 1 not root, a PPA source without a cached
#       Release file, a candidate that would change origin (refused), or a dry run that does not accept the
#       PPA origin (its entry removed again).
set -u
export LC_ALL=C

host=$(hostname </dev/null)
echo "== php2shell autoupdate: $host ($(p2s_os))"
p2s_record kind=host host="$host" os="$(p2s_os)"
if [ "$(id -u </dev/null)" != 0 ]; then
  echo "STOP: autoupdate must run as root"
  exit 1
fi

P2S_ROLLBACK=()
au_end() { # $1 exit code, then the fields of the keeper record
  local rc=$1
  shift
  p2s_record kind=keeper host="$host" "$@"
  echo "== summary $host"
  if [ ${#P2S_ROLLBACK[@]} -gt 0 ]; then
    echo "rollback:"
    printf '  %s\n' "${P2S_ROLLBACK[@]}"
  fi
  echo "exit $rc"
  exit "$rc"
}

releases=$(p2s_ppa_releases)
if [ -z "$releases" ]; then
  echo "no ondrej/sury PHP PPA source: nothing to keep, nothing written"
  au_end 0 state=no-ppa
fi

# The Release file says which Origin unattended-upgrades must accept; without it apt has no lists of the source.
missing="" sites=() entries=()
while IFS='|' read -r uri suite site origin label; do
  p2s_record kind=ppa host="$host" uri="$uri" suite="$suite" origin="$(p2s_enc "$origin")" label="$(p2s_enc "$label")"
  echo "PPA $uri $suite: Origin $origin, Label $label"
  [ "$origin" != - ] || missing+=" $uri ($suite)"
  [[ " ${sites[*]} " == *" $site "* ]] || sites+=("$site")
  [[ " ${entries[*]} " == *" $origin:$suite "* ]] || entries+=("$origin:$suite")
done <<<"$releases"
if [ -n "$missing" ]; then
  echo "STOP: apt has no cached Release file for:$missing. Run apt-get update on the host, then this again."
  au_end 1 state=stopped reason=no-cached-release
fi

# Every PHP branch, the package that stands for it (its FPM, its mod_php, its common package), what apt would
# install before anything changes, and whether the PPA offers any of its packages.
all=$(p2s_php_packages)
branches=$(awk -F'|' 'NF && !seen[$1]++ {print $1}' <<<"$all")
declare -A b_rep b_inst b_origin b_before b_ppa b_pin
for b in $branches; do
  pkgs=$(awk -F'|' -v b="$b" '$1 == b {print $2}' <<<"$all")
  rep=""
  for p in "php$b-fpm" "libapache2-mod-php$b" "php$b-common"; do
    grep -qxF "$p" <<<"$pkgs" && { rep=$p; break; }
  done
  [ -n "$rep" ] || rep=$(head -1 <<<"$pkgs")
  b_rep[$b]=$rep
  b_inst[$b]=$(awk -F'|' -v p="$rep" '$2 == p {print $3}' <<<"$all")
  b_origin[$b]=$(p2s_origin "${b_inst[$b]}")
  b_ppa[$b]=no b_pin[$b]=-
  for p in $pkgs; do
    read -r _ cand ppa <<<"$(p2s_policy "$p")"
    [ "$p" = "$rep" ] && b_before[$b]=$cand
    [ "$ppa" = yes ] && b_ppa[$b]=yes
  done
done

echo "== 1. pins: distro-built branches off the PPA"
for b in $branches; do
  [ "${b_origin[$b]}" = distro ] && [ "${b_ppa[$b]}" = yes ] || continue
  # shellcheck disable=SC2046
  set -- $(awk -F'|' -v b="$b" '$1 == b {print $2}' <<<"$all")
  need=() found=()
  for site in "${sites[@]}"; do
    f=""
    while IFS='|' read -r uri suite s origin label; do
      [ "$s" = "$site" ] || continue
      f=$(p2s_pin_existing "$site" "$origin" "$label" "$suite" "$@")
      [ -z "$f" ] || break
    done <<<"$releases"
    if [ -n "$f" ]; then
      [[ " ${found[*]} " == *" $f "* ]] || found+=("$f")
    else
      need+=("$site")
    fi
  done
  if [ ${#need[@]} -eq 0 ]; then
    b_pin[$b]=$(IFS=,; echo "${found[*]}")
    p2s_record kind=pin host="$host" branch="$b" file="${b_pin[$b]}" action=present
    echo "php$b: already pinned off the PPA in ${b_pin[$b]}"
    continue
  fi
  f=$(p2s_pin_file "$b")
  pf=$(p2s_path "$f")
  prev=""
  [ -e "$pf" ] && prev=$(cat "$pf")
  if mkdir -p "${pf%/*}" && p2s_pin_content "$b" "${need[@]}" >"$pf"; then
    b_pin[$b]=$f
    p2s_record kind=pin host="$host" branch="$b" file="$f" action=written
    echo "php$b: pinned off the PPA (${need[*]}) in $f"
    if [ -n "$prev" ]; then
      echo "previous $f:"
      printf '%s\n' "$prev" | sed 's/^/  | /'
      P2S_ROLLBACK+=("restore the previous $f (content above)")
    else
      P2S_ROLLBACK+=("rm $f   # pin of php$b")
    fi
  else
    echo "STOP: could not write $f"
    au_end 1 state=stopped reason=pin-write-failed
  fi
done

echo "== 2. candidates: every package keeps the origin of its installed build"
refused=()
for b in $branches; do
  moved=() cand=""
  for p in $(awk -F'|' -v b="$b" '$1 == b {print $2}' <<<"$all"); do
    read -r inst c _ <<<"$(p2s_policy "$p")"
    [ "$p" = "${b_rep[$b]}" ] && cand=$c
    [ "$c" != "(none)" ] && [ "$inst" != "(none)" ] && [ "$(p2s_origin "$c")" != "$(p2s_origin "$inst")" ] && moved+=("$p")
  done
  corigin=$(p2s_origin "$cand")
  state=kept
  if [ ${#moved[@]} -gt 0 ]; then
    refused+=("$b")
    if [ "${b_pin[$b]}" = - ]; then state=would-change; else state=pin-ineffective; fi
  fi
  p2s_record kind=policy host="$host" branch="$b" origin="${b_origin[$b]}" package="${b_rep[$b]}" installed="${b_inst[$b]}" \
    before="${b_before[$b]:-(none)}" candidate="$cand" candidate_origin="$corigin" \
    moved="$(if [ ${#moved[@]} -gt 0 ]; then IFS=,; echo "${moved[*]}"; else echo -; fi)" pin="${b_pin[$b]}" state="$state" \
    before_origin="$(p2s_origin "${b_before[$b]:-(none)}")"
  echo "php$b (${b_origin[$b]}): ${b_rep[$b]} candidate ${b_before[$b]:-(none)} before, $cand ($corigin) now: $state"
  [ "$state" = kept ] && continue
  echo "STOP: php$b: apt would move ${moved[*]} from the ${b_origin[$b]} build to $corigin ($cand)"
  if [ "$state" = pin-ineffective ]; then
    echo "  the pin in ${b_pin[$b]} does not hold it: apt does not apply that file, or another preferences entry"
    echo "  outranks it (apt-cache policy ${b_rep[$b]} shows the priorities)"
    IFS=, read -ra pfs <<<"${b_pin[$b]}"
    for f in "${pfs[@]}"; do
      n=${f##*/}
      if [[ $f == "$P2S_PIN_DIR"/* && $n == *.* && $n != *.pref ]]; then
        echo "  apt reads a preferences.d file only without an extension or with .pref, and skips $f; rename it:"
        echo "    mv $f ${f%.*}.pref"
      fi
    done
  fi
done
if [ ${#refused[@]} -gt 0 ]; then
  echo "Refused: the unattended-upgrades origin entry is not written while a branch would change origin."
  [ ${#P2S_ROLLBACK[@]} -eq 0 ] || echo "The pins written above stay: they only hold distro branches where they are."
  au_end 1 state=refused branches="$(IFS=,; echo "${refused[*]}")"
fi

echo "== 3. unattended-upgrades: the PPA origin"
codename=$(p2s_codename)
origins=$(p2s_uu_origins)
need=()
for e in "${entries[@]}"; do
  covered=no
  while IFS= read -r line; do
    [ -n "$line" ] && p2s_uu_covers "$line" "${e%:*}" "${e##*:}" "${codename:-${e##*:}}" && { covered=yes; break; }
  done <<<"$origins"
  if [ "$covered" = yes ]; then
    p2s_record kind=uu_entry host="$host" value="$(p2s_enc "$e")" file=- action=present
    echo "origin $e: already accepted"
  else
    need+=("$e")
  fi
done
uc=$(p2s_path "$P2S_UU_CONF")
uprev="" uwrote=no
if [ ${#need[@]} -gt 0 ]; then
  keep=()
  if [ -e "$uc" ]; then
    uprev=$(cat "$uc")
    mapfile -t keep < <(grep -oE '"[^"]*"' "$uc" | tr -d '"')
  fi
  write=()
  for e in "${keep[@]}" "${need[@]}"; do
    [[ " ${write[*]} " == *" $e "* ]] || write+=("$e")
  done
  if mkdir -p "${uc%/*}" && {
    echo '// Managed by php2shell-fixer: unattended-upgrades installs updates from the ondrej/sury PPA.'
    echo "// Distro-built PHP branches are pinned off the PPA in $P2S_PIN_DIR/php2shell-php<X.Y>.pref."
    echo "// Rollback: rm $P2S_UU_CONF"
    printf 'Unattended-Upgrade::Allowed-Origins {'
    printf ' "%s";' "${write[@]}"
    printf ' };\n'
  } >"$uc"; then
    uwrote=yes
    for e in "${need[@]}"; do
      p2s_record kind=uu_entry host="$host" value="$(p2s_enc "$e")" file="$P2S_UU_CONF" action=written
      echo "origin $e: written to $P2S_UU_CONF"
    done
    if [ -n "$uprev" ]; then
      echo "previous $P2S_UU_CONF:"
      printf '%s\n' "$uprev" | sed 's/^/  | /'
      P2S_ROLLBACK+=("restore the previous $P2S_UU_CONF (content above)")
    else
      P2S_ROLLBACK+=("rm $P2S_UU_CONF   # PPA origin for unattended-upgrades")
    fi
  else
    echo "STOP: could not write $P2S_UU_CONF"
    au_end 1 state=stopped reason=origin-write-failed
  fi
fi

# unattended-upgrades prints the origins it accepts; each PPA origin has to be among them.
dry=$(unattended-upgrade --dry-run -v </dev/null 2>&1)
drc=$?
allowed=$(sed -nE 's/^Allowed origins are: //p' <<<"$dry" | tail -1 | tr ' ' ',')
seen=() result=ok
for e in "${entries[@]}"; do
  o=${e%:*}
  if [[ ",$allowed," == *",o=$o,"* || ",$allowed," == *",origin=$o,"* ]]; then
    [[ " ${seen[*]} " == *" $o "* ]] || seen+=("$o")
  else
    result=origin-missing
  fi
done
[ "$drc" = 0 ] || result=failed
p2s_record kind=uu_dryrun host="$host" result="$result" exit="$drc" \
  origins_allowed="$(if [ ${#seen[@]} -gt 0 ]; then IFS=,; echo "${seen[*]}"; else echo -; fi)"
echo "unattended-upgrade --dry-run: $result (exit $drc)"
if [ "$result" != ok ]; then
  tail -5 <<<"$dry" | sed 's/^/  | /'
  if [ "$uwrote" = yes ]; then
    if [ -n "$uprev" ]; then printf '%s\n' "$uprev" >"$uc"; else rm -f "$uc"; fi
    unset 'P2S_ROLLBACK[-1]'
    for e in "${need[@]}"; do
      p2s_record kind=uu_entry host="$host" value="$(p2s_enc "$e")" file="$P2S_UU_CONF" action=removed
    done
    echo "STOP: the dry run does not accept the PPA origin; $P2S_UU_CONF is back as it was"
  else
    echo "STOP: the dry run does not accept the PPA origin"
  fi
  au_end 1 state=dryrun-failed
fi

periodic=$(apt-config dump </dev/null 2>/dev/null | sed -nE 's/^APT::Periodic::Unattended-Upgrade "([^"]*)";$/\1/p' | tail -1)
case ${periodic:-0} in
  0) echo "NOTE: APT::Periodic::Unattended-Upgrade is ${periodic:-unset}: unattended-upgrades does not run on its own" ;;
esac
if [ ${#P2S_ROLLBACK[@]} -gt 0 ]; then
  au_end 0 state=configured periodic="${periodic:-unset}"
else
  au_end 0 state=unchanged periodic="${periodic:-unset}"
fi
