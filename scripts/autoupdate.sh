# Auto-update keeper: PHP from the ondrej/sury PPA keeps getting security updates from unattended-upgrades, and
# a distro-built branch never moves to the PPA. Only on a host with the PPA configured; anywhere else it writes
# nothing. The order is the safety:
# 0. each PPA source's Release info (Origin, Label, Suite, Codename) must be what apt cached; a changed one
#    stops the run before anything is written and prints the apt-get update command that accepts it;
# 1. every distro-built branch the PPA also ships is pinned off the PPA (Pin-Priority -1,
#    /etc/apt/preferences.d/php2shell-php<X.Y>.pref);
# 2. each installed PHP package's apt-cache policy candidate must keep the origin of its installed build, an
#    origin being the source apt-cache policy lists under the build (PPA site or distro mirror), and every
#    PPA build of a pinned branch must show a negative priority there, even one that sorts below the
#    installed build today. When either fails, the run stops and names the branch: the pins stay (they
#    only hold a branch where it is), the origin entry is not written;
# 3. the PPA origin goes into the origins unattended-upgrades accepts (/etc/apt/apt.conf.d/51php2shell-ppa-origins),
#    and unattended-upgrade --dry-run must list it and must not upgrade a package of a distro-built branch it
#    did not upgrade before the entry (that one would come from the PPA); otherwise the entry is taken out.
# A pin or origin entry already in place is recognised by content, whatever its file name, and not written
# twice. A pin apt does not apply (a preferences.d name with another extension than .pref) shows in step 2.
# Runs as the tail of the bundle from run.sh (after versions.sh, p2s.sh, hostfacts.sh, pins.sh):
# run.sh autoupdate <host>
# Exit: 0 configured, already in place, or no PPA on the host; 1 not root, a PPA source without a cached
#       Release file (no-cached-release) or with changed Release info (release-info-changed), a pin or the
#       origin entry that could not be written (pin-write-failed, origin-write-failed) or an old file not
#       backed up (backup-failed), a candidate that would change origin or a pin that holds nothing
#       (refused), a dry run that does not accept the PPA origin or takes a distro branch from it
#       (dryrun-failed, its entry removed again), or a signal before the dry run's verdict (interrupted,
#       its entry put back).
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

# A source whose Release info changed since apt cached it gets no updates until someone accepts the change, and
# its Origin or Label may be what the pins and the origin entry would name: stop before writing anything.
fields=""
while IFS='|' read -r uri suite _; do
  rc=$(p2s_release_check "$uri" "$suite")
  read -r info changed <<<"$(head -1 <<<"$rc")"
  [ "$info" = changed ] || continue
  echo "PPA $uri $suite: Release info changed ($changed)"
  tail -n +2 <<<"$rc"
  fields+=",$changed"
done <<<"$releases"
if [ -n "$fields" ]; then
  fields=$(tr ',' '\n' <<<"${fields#,}" | sort -u)
  echo "STOP: a PPA source changed its Release info; apt-get update refuses it until you accept the change."
  echo "Check the change is expected, then accept it with:"
  echo "  apt-get update $(for f in $fields; do printf -- '--allow-releaseinfo-change-%s ' "${f,,}"; done)"
  echo "and run this again."
  au_end 1 state=stopped reason=release-info-changed fields="$(paste -sd, - <<<"$fields")"
fi

# Every PHP branch, the package that stands for it (its FPM, its mod_php, its common package), the origin of
# its installed build and what apt would install before anything changes, both by the source apt-cache policy
# lists (a version string alone does not tell a plain Debian revision from a sury build), and whether the PPA
# offers any of its packages.
all=$(p2s_php_packages)
branches=$(awk -F'|' 'NF && !seen[$1]++ {print $1}' <<<"$all")
declare -A b_pkg b_inst b_origin b_before b_borigin b_ppa b_pin
for b in $branches; do
  pkgs=$(awk -F'|' -v b="$b" '$1 == b {print $2}' <<<"$all")
  pkg=""
  for p in "php$b-fpm" "libapache2-mod-php$b" "php$b-common"; do
    grep -qxF "$p" <<<"$pkgs" && { pkg=$p; break; }
  done
  [ -n "$pkg" ] || pkg=$(head -1 <<<"$pkgs")
  b_pkg[$b]=$pkg
  b_inst[$b]=$(awk -F'|' -v p="$pkg" '$2 == p {print $3}' <<<"$all")
  b_ppa[$b]=no b_pin[$b]=-
  for p in $pkgs; do
    read -r _ cand ppa io co <<<"$(p2s_policy_state "$p")"
    [ "$p" = "$pkg" ] && b_origin[$b]=$io b_before[$b]=$cand b_borigin[$b]=$co
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
  bk=""
  if [ -e "$pf" ] && ! bk=$(p2s_backup "$f"); then
    echo "STOP: could not back up $f to $P2S_BACKUP_DIR before overwriting it"
    au_end 1 state=stopped reason=backup-failed
  fi
  if p2s_write_file "$f" "$(p2s_pin_content "$b" "${need[@]}")"; then
    b_pin[$b]=$f
    p2s_record kind=pin host="$host" branch="$b" file="$f" action=written
    echo "php$b: pinned off the PPA (${need[*]}) in $f"
    if [ -n "$bk" ]; then
      echo "previous $f, kept as $bk:"
      sed 's/^/  | /' "$(p2s_path "$bk")"
      P2S_ROLLBACK+=("cp $bk $f   # the previous pin file")
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
  moved=() unheld=() cand="" corigin=other
  for p in $(awk -F'|' -v b="$b" '$1 == b {print $2}' <<<"$all"); do
    read -r inst c _ io co held <<<"$(p2s_policy_state "$p")"
    [ "$p" = "${b_pkg[$b]}" ] && cand=$c corigin=$co
    [ "$c" != "(none)" ] && [ "$inst" != "(none)" ] && [ "$co" != "$io" ] && moved+=("$p")
    # A pinned branch's PPA builds must all show the pin's negative priority. One that does not is held by
    # nothing: it is not the candidate today only because it sorts lower, and the next PPA upload moves it.
    [ "${b_pin[$b]}" != - ] && [ "$held" = no ] && unheld+=("$p")
  done
  state=kept
  if [ ${#moved[@]} -gt 0 ] || [ ${#unheld[@]} -gt 0 ]; then
    refused+=("$b")
    if [ "${b_pin[$b]}" = - ]; then state=would-change; else state=pin-ineffective; fi
  fi
  p2s_record kind=policy host="$host" branch="$b" origin="${b_origin[$b]}" package="${b_pkg[$b]}" installed="${b_inst[$b]}" \
    before="${b_before[$b]:-(none)}" candidate="$cand" candidate_origin="$corigin" \
    moved="$(if [ ${#moved[@]} -gt 0 ]; then IFS=,; echo "${moved[*]}"; else echo -; fi)" pin="${b_pin[$b]}" state="$state" \
    before_origin="${b_borigin[$b]:-other}" unheld="$(if [ ${#unheld[@]} -gt 0 ]; then IFS=,; echo "${unheld[*]}"; else echo -; fi)"
  echo "php$b (${b_origin[$b]}): ${b_pkg[$b]} candidate ${b_before[$b]:-(none)} before, $cand ($corigin) now: $state"
  [ "$state" = kept ] && continue
  if [ ${#moved[@]} -gt 0 ]; then
    echo "STOP: php$b: apt would move ${moved[*]} from the ${b_origin[$b]} build to $corigin ($cand)"
  else
    echo "STOP: php$b: apt-cache policy shows the PPA builds of ${unheld[*]} at a priority of 0 or more, not held off"
  fi
  if [ "$state" = pin-ineffective ]; then
    echo "  the pin in ${b_pin[$b]} does not hold it: apt does not apply that file, or another preferences entry"
    echo "  outranks it (apt-cache policy ${b_pkg[$b]} shows the priorities)"
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
uprev="" ubk="" uwrote=no pre_up=""
# The packages a dry run would upgrade, one per line, from its "Packages that will be upgraded:" line.
au_upgrades() { sed -nE 's/^Packages that will be upgraded: //p' <<<"$1" | tail -1 | tr ' ' '\n' | grep .; }
if [ ${#need[@]} -gt 0 ]; then
  # What unattended-upgrades would upgrade before the PPA is accepted: a package it upgrades only afterwards
  # comes from the PPA.
  pre_up=$(au_upgrades "$(unattended-upgrade --dry-run -v </dev/null 2>&1)")
  keep=()
  if [ -e "$uc" ]; then
    uprev=$(cat "$uc")
    mapfile -t keep < <(grep -oE '"[^"]*"' "$uc" | tr -d '"')
    if ! ubk=$(p2s_backup "$P2S_UU_CONF"); then
      echo "STOP: could not back up $P2S_UU_CONF to $P2S_BACKUP_DIR before overwriting it"
      au_end 1 state=stopped reason=backup-failed
    fi
  fi
  write=()
  for e in "${keep[@]}" "${need[@]}"; do
    [[ " ${write[*]} " == *" $e "* ]] || write+=("$e")
  done
  # From here until the dry run's verdict the entry is unchecked. A dropped ssh session (SIGHUP) or a kill
  # puts the file back as it was first, then reports; SIGPIPE is ignored, the session's output being gone.
  au_interrupted() {
    trap '' PIPE
    rm -f "$uc$P2S_NEW_SUFFIX"
    if [ -n "$ubk" ]; then p2s_restore_file "$ubk" "$P2S_UU_CONF"; else rm -f "$uc"; fi
    for e in "${need[@]}"; do
      p2s_record kind=uu_entry host="$host" value="$(p2s_enc "$e")" file="$P2S_UU_CONF" action=removed
    done
    echo "STOP: interrupted before the dry run's verdict; $P2S_UU_CONF is back as it was"
    p2s_record kind=keeper host="$host" state=interrupted reason=signal
    exit 1
  }
  trap au_interrupted HUP INT TERM
  if p2s_write_file "$P2S_UU_CONF" "$(
    echo '// Managed by php2shell-fixer: unattended-upgrades installs updates from the ondrej/sury PPA.'
    echo "// Distro-built PHP branches are pinned off the PPA in $P2S_PIN_DIR/php2shell-php<X.Y>.pref."
    echo "// Rollback: rm $P2S_UU_CONF"
    printf 'Unattended-Upgrade::Allowed-Origins {'
    printf ' "%s";' "${write[@]}"
    printf ' };'
  )"; then
    uwrote=yes
    for e in "${need[@]}"; do
      p2s_record kind=uu_entry host="$host" value="$(p2s_enc "$e")" file="$P2S_UU_CONF" action=written
      echo "origin $e: written to $P2S_UU_CONF"
    done
    if [ -n "$ubk" ]; then
      echo "previous $P2S_UU_CONF, kept as $ubk:"
      printf '%s\n' "$uprev" | sed 's/^/  | /'
      P2S_ROLLBACK+=("cp $ubk $P2S_UU_CONF   # the previous origin entry")
    else
      P2S_ROLLBACK+=("rm $P2S_UU_CONF   # PPA origin for unattended-upgrades")
    fi
  else
    trap - HUP INT TERM
    echo "STOP: could not write $P2S_UU_CONF"
    au_end 1 state=stopped reason=origin-write-failed
  fi
fi

# unattended-upgrades prints the origins it accepts; each PPA origin has to be among them. And it prints the
# packages it would upgrade: one of a distro-built branch that it takes only now the PPA is accepted would
# move that branch to the PPA, whatever the pins say.
dry=$(unattended-upgrade --dry-run -v </dev/null 2>&1)
drc=$?
from_ppa=()
if [ "$uwrote" = yes ]; then
  while read -r p; do
    ! grep -qxF "$p" <<<"$pre_up" || continue
    b=$(awk -F'|' -v p="$p" '$2 == p {print $1; exit}' <<<"$all")
    [ -n "$b" ] && [ "${b_origin[$b]}" = distro ] && from_ppa+=("$p")
  done < <(au_upgrades "$dry")
fi
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
[ "$result" != ok ] || [ ${#from_ppa[@]} -eq 0 ] || result=distro-from-ppa
[ "$drc" = 0 ] || result=failed
trap - HUP INT TERM   # the verdict is in: from here on the entry is kept or taken out below
p2s_record kind=uu_dryrun host="$host" result="$result" exit="$drc" \
  origins_allowed="$(if [ ${#seen[@]} -gt 0 ]; then IFS=,; echo "${seen[*]}"; else echo -; fi)" \
  from_ppa="$(if [ ${#from_ppa[@]} -gt 0 ]; then IFS=,; echo "${from_ppa[*]}"; else echo -; fi)"
echo "unattended-upgrade --dry-run: $result (exit $drc)"
if [ "$result" != ok ]; then
  tail -5 <<<"$dry" | sed 's/^/  | /'
  why="the dry run does not accept the PPA origin"
  [ "$result" != distro-from-ppa ] || why="with the PPA origin accepted, unattended-upgrades would upgrade ${from_ppa[*]} of a distro-built branch from the PPA"
  if [ "$uwrote" = yes ]; then
    if [ -n "$ubk" ]; then p2s_restore_file "$ubk" "$P2S_UU_CONF"; else rm -f "$uc"; fi
    unset 'P2S_ROLLBACK[-1]'
    for e in "${need[@]}"; do
      p2s_record kind=uu_entry host="$host" value="$(p2s_enc "$e")" file="$P2S_UU_CONF" action=removed
    done
    echo "STOP: $why; $P2S_UU_CONF is back as it was"
  else
    echo "STOP: $why"
  fi
  au_end 1 state=dryrun-failed
fi

periodic=$(apt-config dump </dev/null 2>/dev/null | sed -nE 's/^APT::Periodic::Unattended-Upgrade "([^"]*)";$/\1/p' | tail -1)
case ${periodic:-0} in
  0) echo "NOTE: APT::Periodic::Unattended-Upgrade is ${periodic:-unset}: unattended-upgrades does not run on its own" ;;
esac
if [ ${#P2S_ROLLBACK[@]} -gt 0 ]; then
  au_end 0 state=configured periodic="$(p2s_enc "${periodic:-unset}")"
else
  au_end 0 state=unchanged periodic="$(p2s_enc "${periodic:-unset}")"
fi
