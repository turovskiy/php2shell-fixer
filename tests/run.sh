#!/usr/bin/env bash
# Self-test for the audit, verdict and report. Touches no real host: ssh, hostname, dpkg-query, systemctl
# and the package tools are stubs that log every call, and each host is a fake root in a temp dir.
# Run: bash tests/run.sh   (from anywhere)
set -uo pipefail

T=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
S=$(dirname "$T")/scripts
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  ✓ %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  ✗ %s\n' "$1"; [[ -n ${2:-} ]] && printf '%s\n' "$2" | sed 's/^/      /'; }
has()  { grep -qF -- "$2" <<<"$1" && ok "$3" || bad "$3" "$1"; }
hasnt(){ grep -qF -- "$2" <<<"$1" && bad "$3" "$1" || ok "$3"; }
eq()   { [[ "$1" == "$2" ]] && ok "$3" || bad "$3" "expected: $2
got:      $1"; }

# Hosts: fixture copies with gzipped changelogs, as dpkg leaves them.
mkdir -p "$WORK/hosts"
cp -r "$T/fixtures/hosts/." "$WORK/hosts/"
# web-a php7.4: a changelog far longer than a pipe buffer, with the CVE lines near its end.
LONG=$WORK/hosts/web-a/root/usr/share/doc/php7.4-common/changelog.Debian
mkdir -p "$(dirname "$LONG")"
{
  echo 'php7.4 (1:7.4.33-31+ubuntu24.04.1+deb.sury.org+1) noble; urgency=medium'
  for i in $(seq 1 1300); do echo "  * Backported upstream fix number $i for the 7.4 branch, no security impact"; done
  echo '  * Fix CVE-2026-109618 and CVE-2026-109619 (PHP2Shell)'
  for i in $(seq 1 100); do echo "  * Older entry $i"; done
} >"$LONG"
# web-b php8.1: the CVE lines in the top entry of a changelog several pipe buffers long. A reader that stops
# early ("zcat | head | grep -q" under pipefail) kills zcat with SIGPIPE and reads a match as a failure.
TOP=$WORK/hosts/web-b/root/usr/share/doc/php8.1-common/changelog.Debian
mkdir -p "$(dirname "$TOP")"
{
  echo 'php8.1 (8.1.34-9+ubuntu24.04.1+deb.sury.org+1) noble; urgency=medium'
  echo '  * Fix CVE-2026-109618 and CVE-2026-109619 (PHP2Shell)'
  for i in $(seq 1 2000); do echo "  * Older entry $i: backported upstream fix for the 8.1 branch, no security impact"; done
} >"$TOP"
find "$WORK/hosts" -name changelog.Debian -exec gzip -n {} \;
# web-z: a CLI-only host that answers slowly, for the per-host timeout.
cp -r "$WORK/hosts/web-c" "$WORK/hosts/web-z"
echo 3 >"$WORK/hosts/web-z/sleep"
# Candidate packages: debs/<package>=<version>/ becomes the tar that "dpkg-deb --fsys-tarfile" would print.
# apt lists: names as apt writes them, dates set here since git keeps no mtimes. web-a has none at all.
lists() { # lists <host> <date> <list file>...
  local h=$1 t=$2 f; shift 2
  mkdir -p "$WORK/hosts/$h/root/var/lib/apt/lists"
  for f in "$@"; do touch -d "$t" "$WORK/hosts/$h/root/var/lib/apt/lists/$f"; done
}
lists web-b '2026-10-24 06:00:00 UTC' ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_noble_main_binary-amd64_Packages \
  archive.ubuntu.com_ubuntu_dists_noble-updates_universe_binary-amd64_Packages \
  security.ubuntu.com_ubuntu_dists_noble-security_universe_binary-amd64_Packages
lists web-b '2024-04-24 06:00:00 UTC' archive.ubuntu.com_ubuntu_dists_noble_universe_binary-amd64_Packages
lists web-d '2026-09-30 06:00:00 UTC' ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_noble_main_binary-amd64_Packages
lists web-d '2026-10-25 06:00:00 UTC' mirrors.digitalocean.com_ubuntu_dists_noble-security_main_binary-amd64_Packages
lists web-e '2026-10-22 06:00:00 UTC' security.ubuntu.com_ubuntu_dists_jammy-security_main_binary-amd64_Packages.lz4
# dpkg file lists: their mtime is the install time the restart check compares with the service start.
dpkglists() { # dpkglists <host> <date> <package>...
  local h=$1 t=$2 p; shift 2
  mkdir -p "$WORK/hosts/$h/root/var/lib/dpkg/info"
  for p in "$@"; do touch -d "$t" "$WORK/hosts/$h/root/var/lib/dpkg/info/$p.list"; done
}
dpkglists web-j '2026-10-22 06:00:00 UTC' php8.3-fpm php8.3-common
dpkglists web-j '2026-10-24 06:00:00 UTC' php8.4-fpm
dpkglists web-j '2026-10-24 07:00:00 UTC' php8.4-opcache
dpkglists web-l '2026-10-22 06:00:00 UTC' libapache2-mod-php8.3 php8.3-common
# apt-helper is called by absolute path, so it goes into the fake root of every host with remote/ fixtures:
# "download-file URL DEST" copies remote/<URL with / and : as _> to DEST.
apthelper() { # apthelper <host dir>
  mkdir -p "$1/root/usr/lib/apt"
  printf '%s\n' '#!/usr/bin/env bash' 'echo "apt-helper $*" >>"$STUB_LOG"' \
    'for a; do case $a in http*) url=$a ;; esac; done; dest=${!#}' \
    'src=$P2S_STUB/remote/$(printf %s "$url" | tr "/:" "__")' \
    '[ -f "$src" ] || { echo "E: Failed to fetch $url  404  Not Found" >&2; exit 100; }' \
    'cp "$src" "$dest"' >"$1/root/usr/lib/apt/apt-helper"
  chmod +x "$1/root/usr/lib/apt/apt-helper"
}
for h in "$WORK"/hosts/*/; do
  [ -d "$h/remote" ] && apthelper "$h"
done

for d in "$WORK"/hosts/*/debs/*/; do
  [ -d "$d" ] || continue
  key=$(basename "$d")
  mkdir -p "$WORK/pkg/$key/usr/share/doc/${key%%=*}"
  cp "$d/changelog.Debian.gz" "$WORK/pkg/$key/usr/share/doc/${key%%=*}/"
  tar -C "$WORK/pkg/$key" -cf "${d%/}.tar" ./usr
done

# Patcher hosts: web-m as is, and copies of it with one thing going wrong each.
derive() { # derive <new host> <file> <content>
  cp -r "$WORK/hosts/web-m" "$WORK/hosts/$1"
  printf '%s\n' "$3" >"$WORK/hosts/$1/$2"
}
derive web-o fail-t-php-fpm8.3 ''                  # config test fails after the change
derive web-p fail-restart-php8.3-fpm ''            # pool does not come back after its restart
derive web-q holds.txt php8.3-fpm                  # held package
derive web-r fail-update-label ''                  # the PPA changed its Release Label
derive web-t http.txt 'shop.example.com 200 502'   # the site answers differently afterwards
derive web-s slow-install 3                        # connection drops mid-upgrade; next run reads the result
echo 1 >"$WORK/hosts/web-s/drop-after"
derive web-u slow-install 5                        # connection drops; next run attaches to the running unit
echo 1 >"$WORK/hosts/web-u/drop-after"
# web-x's Apache listens on 127.0.0.1:8080 behind nginx: its vhosts answer plain http there and nowhere else.
# Written here, not in the fixture: fixtures carry only package archive URLs.
printf '%s\n' 'api.example.com 200 200' 'http://shop.example.com:8080 200 200 127.0.0.1' \
  'http://www.shop.example.com:8080 301 301 127.0.0.1' 'http://blog.example.org:8080 200 200 127.0.0.1' >"$WORK/hosts/web-x/http.txt"
# mod_php hosts: web-w is web-l with an Apache config that fails its configtest.
cp -r "$WORK/hosts/web-l" "$WORK/hosts/web-w"
: >"$WORK/hosts/web-w/fail-configtest"
for h in "$WORK"/hosts/*/root; do mkdir -p "$h/root"; done   # /root, where the patcher keeps its backup
# web-y (Ubuntu 8.3 + PPA 8.4 with the ondrej PPA configured) runs the auto-update keeper several times, each
# from this pristine copy with one thing added.
cp -r "$WORK/hosts/web-y" "$WORK/web-y.pristine"

# Stubs, first on PATH. ssh runs the streamed program locally against the named host's fake root.
REAL_DPKG=$(command -v dpkg)
mkdir -p "$WORK/bin"
export STUB_LOG=$WORK/calls.log P2S_TEST_HOSTS=$WORK/hosts P2S_CACHE=$WORK/cache P2S_ALLOW_TMP_CACHE=1
stub() { # stub <name> <body>: a logging stub
  printf '#!/usr/bin/env bash\necho "%s $*" >>"$STUB_LOG"\n%s\n' "$1" "$2" >"$WORK/bin/$1"
  chmod +x "$WORK/bin/$1"
}
# ssh [-o opt]... <host> 'bash -s': the host is the second-to-last argument. A host with a "sleep" file
# waits that many seconds first, to exercise the per-host timeout. A host with a "drop-after" file loses the
# connection after that many seconds: like sshd on a dropped session, the whole session's process group
# gets SIGHUP and then SIGKILL, children included (255). Only what left the session survives.
stub ssh 'h=${@: -2:1}
d=$P2S_TEST_HOSTS/$h
[ -d "$d" ] || { echo "ssh: Could not resolve hostname $h: Name or service not known" >&2; exit 255; }
[ -f "$d/sleep" ] && sleep "$(cat "$d/sleep")"
if [ -f "$d/drop-after" ]; then
  P2S_ROOT=$d/root P2S_STUB=$d STUB_HOST=$h setsid bash -s <&0 &
  pid=$!
  sleep "$(cat "$d/drop-after")"
  kill -HUP -- "-$pid" 2>/dev/null; sleep 0.2; kill -9 -- "-$pid" 2>/dev/null
  echo "Connection to $h closed by remote host." >&2
  exit 255
fi
P2S_ROOT=$d/root P2S_STUB=$d STUB_HOST=$h exec bash -s'
stub hostname 'echo "$STUB_HOST"'
# dpkg-query -W -f=<format> <package>...: fixture lines are "<status>|<package>|<version>[|<source>]".
# A ${source:Package} format prints "<status>|<package>|<source>", the source defaulting to php<X.Y> as for
# the packages built from PHP itself; another format naming the package prints the fixture as is; a
# ${Version} format prints the versions of the named packages.
stub dpkg-query 'fmt="" pats=()
for a; do case $a in -W) ;; -f=*) fmt=${a#-f=} ;; *) pats+=("$a") ;; esac; done
case $fmt in
  *source:Package*)
    awk -F"|" -v OFS="|" "{s = \$4; if (s == \"\") { s = \$2; sub(/^libapache2-mod-/, \"\", s); sub(/-.*/, \"\", s) } print \$1, \$2, s}" "$P2S_STUB/dpkg-query.txt" ;;
  *binary:Package*) cut -d"|" -f1-3 "$P2S_STUB/dpkg-query.txt" ;;
  *)
    for p in "${pats[@]}"; do
      v=$(awk -F"|" -v p="$p" "\$2 == p {print \$3}" "$P2S_STUB/dpkg-query.txt")
      [ -n "$v" ] || continue
      case $fmt in *n) printf "%s\n" "$v" ;; *) printf "%s" "$v" ;; esac
    done ;;
esac'
stub systemctl 'if [ "$1" = is-active ]; then
  case $2 in
    php2shell-fix-*)   # a transient patch unit is active while the process systemd-run started lives
      f=$P2S_STUB/units/$2.pid
      [ -f "$f" ] && kill -0 "$(cat "$f")" 2>/dev/null && { echo active; exit 0; }
      echo inactive; exit 3 ;;
  esac
  grep -qxF "${2%.service}" "$P2S_STUB/active.txt" && { echo active; exit 0; }
  echo inactive; exit 3
fi
# restart: fail-restart-<unit> in the fixture leaves the unit down afterwards
if [ "$1" = restart ]; then
  u=${2%.service}
  if [ -e "$P2S_STUB/fail-restart-$u" ]; then sed -i "/^$u\$/d" "$P2S_STUB/active.txt"
  else grep -qxF "$u" "$P2S_STUB/active.txt" || echo "$u" >>"$P2S_STUB/active.txt"; fi
  exit 0
fi
[ "$1" = reload ] && [ -e "$P2S_STUB/fail-reload" ] && exit 1
# show -p ActiveEnterTimestamp --value <unit>: start time from started.txt ("<unit> <time>"), empty if absent
[ "$1" = show ] && [ -f "$P2S_STUB/started.txt" ] && sed -n "s/^${!#} //p" "$P2S_STUB/started.txt"
exit 0'
stub dpkg "exec $REAL_DPKG \"\$@\""
# apt as the auto-update keeper sees it: preferences, candidates, apt.conf.d, unattended-upgrades. Shared by the
# apt-cache, apt-config and unattended-upgrade stubs; not on PATH, so it logs nothing itself.
export P2S_REAL_DPKG=$REAL_DPKG P2S_STUBLIB=$WORK/stublib
mkdir -p "$P2S_STUBLIB"
cat >"$P2S_STUBLIB/apt.sh" <<'EOF'
# The files apt reads as preferences: /etc/apt/preferences, then preferences.d/* in name order. As in
# apt_preferences(5), a preferences.d file counts only when its name has no extension or the extension "pref"
# and holds only letters, digits, "_", "-" and "."; apt ignores every other name. "php8.3" has an extension.
stub_prefs_files() {
  local f n
  [ -f "$P2S_ROOT/etc/apt/preferences" ] && echo "$P2S_ROOT/etc/apt/preferences"
  for f in "$P2S_ROOT"/etc/apt/preferences.d/*; do
    [ -f "$f" ] || continue
    n=${f##*/}
    [[ $n =~ ^[A-Za-z0-9_.-]+$ ]] || continue
    [[ $n != *.* || $n == *.pref ]] && echo "$f"
  done
}
# Stanzas in the order apt reads them, one "packages<TAB>pin<TAB>priority" per line.
stub_prefs_stanzas() {
  local f
  stub_prefs_files | while read -r f; do
    awk 'function out() { if (pk != "" && pin != "" && pr != "") print pk "\t" pin "\t" pr; pk = pin = pr = "" }
      /^[[:space:]]*$/ { out(); next }
      /^Package:/ { pk = $0; sub(/^Package:[[:space:]]*/, "", pk) }
      /^Pin:/ { pin = $0; sub(/^Pin:[[:space:]]*/, "", pin) }
      /^Pin-Priority:/ { pr = $2 }
      END { out() }' "$f"
  done
}
# A field of the cached Release file of a source: $1 uri, $2 suite, $3 field.
stub_release_field() {
  local u=${1#*://}
  u=${u%/}
  sed -nE "s/^$3: (.*)\$/\\1/p" "$P2S_ROOT/var/lib/apt/lists/${u//\//_}_dists_$2_InRelease" 2>/dev/null | head -1
}
# Does a Pin line match a build from a source? $1 pin, $2 version, $3 uri, $4 suite.
stub_pin_matches() {
  local pin=$1 ver=$2 uri=$3 suite=$4 site kv k v kvs
  site=${uri#*://}
  site=${site%%/*}
  case $pin in
    origin\ *) v=${pin#origin }; [ "${v//\"/}" = "$site" ] ;;
    version\ *) [[ $ver == ${pin#version } ]] ;;
    release\ *)
      IFS=, read -ra kvs <<<"${pin#release }"
      for kv in "${kvs[@]}"; do
        k=${kv%%=*} v=${kv#*=}
        k=${k// /} v=${v//\"/}
        case $k in
          o | origin) [ "$(stub_release_field "$uri" "$suite" Origin)" = "$v" ] ;;
          l | label) [ "$(stub_release_field "$uri" "$suite" Label)" = "$v" ] ;;
          a | archive | n | codename) [ "$suite" = "$v" ] ;;
          *) false ;;
        esac || return 1
      done ;;
    *) false ;;
  esac
}
# Priority of one build from one source: the first stanza whose Package and Pin match it, else 500.
stub_priority() { # $1 package, $2 version, $3 uri, $4 suite
  local pk pin pr pats p
  while IFS=$'\t' read -r pk pin pr; do
    read -ra pats <<<"$pk"
    for p in "${pats[@]}"; do
      if [[ $p == /*/ ]]; then [[ $1 =~ ${p:1:-1} ]] || continue
      else [[ $1 == $p ]] || continue
      fi
      stub_pin_matches "$pin" "$2" "$3" "$4" && { echo "$pr"; return; }
      break
    done
  done < <(stub_prefs_stanzas)
  echo 500
}
# Priority of a source itself: the first "Package: *" stanza whose Pin matches it, else 500. A pin for named
# packages changes a version's priority, never its source's.
stub_file_priority() { # $1 uri, $2 suite
  local pk pin pr
  while IFS=$'\t' read -r pk pin pr; do
    [ "$pk" = "*" ] && [[ $pin != version\ * ]] && stub_pin_matches "$pin" - "$1" "$2" && { echo "$pr"; return; }
  done < <(stub_prefs_stanzas)
  echo 500
}
# apt-cache policy <package>, laid out as apt >= 1.1 prints it: the builds from madison/<package>.txt, each on a
# version line with its own priority (a package pin shows here), "***" marking the installed one, and under it
# one line per source with that source's priority, plus /var/lib/dpkg/status under the installed build. The
# installed build comes from dpkg-query.txt. The candidate is the build with the highest priority (never a
# negative one), the higher version on a tie; a build older than the installed one does not replace it below
# priority 1000.
stub_policy() {
  local pkg=$1 inst v src uri dist pr best="" bestp="" r order=()
  local -A prio srcs
  inst=$(awk -F'|' -v p="$pkg" '$1 ~ /^ii/ && $2 == p {print $3}' "$P2S_STUB/dpkg-query.txt")
  while IFS='|' read -r _ v src; do
    v=${v// /}
    [ -n "$v" ] || continue
    read -r uri dist _ <<<"$src"
    pr=$(stub_priority "$pkg" "$v" "$uri" "${dist%%/*}")
    [ -n "${srcs[$v]+x}" ] || order+=("$v")
    srcs[$v]+="$(stub_file_priority "$uri" "${dist%%/*}")|$uri|$dist"$'\n'
    if [ -z "${prio[$v]:-}" ] || [ "$pr" -gt "${prio[$v]}" ]; then prio[$v]=$pr; fi
  done 2>/dev/null <"$P2S_STUB/madison/$pkg.txt"
  [ -n "$inst" ] || [ ${#order[@]} -gt 0 ] || { echo "N: Unable to locate package $pkg" >&2; return; }
  if [ -n "$inst" ]; then
    [ -n "${srcs[$inst]+x}" ] || order+=("$inst")
    if [ -z "${prio[$inst]:-}" ] || [ "${prio[$inst]}" -lt 100 ]; then prio[$inst]=100; fi
  fi
  for v in "${!prio[@]}"; do
    [ "${prio[$v]}" -ge 0 ] || continue
    if [ -z "$best" ] || [ "${prio[$v]}" -gt "$bestp" ] \
      || { [ "${prio[$v]}" = "$bestp" ] && "$P2S_REAL_DPKG" --compare-versions "$v" gt "$best"; }; then
      best=$v bestp=${prio[$v]}
    fi
  done
  if [ -n "$inst" ] && [ -n "$best" ] && [ "$bestp" -lt 1000 ] && "$P2S_REAL_DPKG" --compare-versions "$best" lt "$inst"; then
    best=$inst
  fi
  echo "$pkg:"
  echo "  Installed: ${inst:-(none)}"
  echo "  Candidate: ${best:-(none)}"
  echo "  Version table:"
  for v in "${order[@]}"; do
    if [ "$v" = "$inst" ]; then printf ' *** %s %s\n' "$v" "${prio[$v]}"; else printf '     %s %s\n' "$v" "${prio[$v]}"; fi
    while IFS='|' read -r pr uri dist; do
      [ -n "$uri" ] && printf '       %4s %s %s amd64 Packages\n' "$pr" "$uri" "$dist"
    done <<<"${srcs[$v]:-}"
    [ "$v" != "$inst" ] || printf '        100 /var/lib/dpkg/status\n'
  done
}
# apt-config dump: the host's apt-config.txt, then the unattended-upgrades origin lists of every apt.conf.d file
# apt reads (no extension or ".conf", same name rule as preferences.d).
stub_aptconf_dump() {
  local f n
  [ -f "$P2S_STUB/apt-config.txt" ] && cat "$P2S_STUB/apt-config.txt"
  for f in "$P2S_ROOT"/etc/apt/apt.conf.d/*; do
    [ -f "$f" ] || continue
    n=${f##*/}
    [[ $n =~ ^[A-Za-z0-9_.-]+$ ]] && [[ $n != *.* || $n == *.conf ]] || continue
    sed 's#//.*##' "$f" | tr '\n' ' ' \
      | grep -oE 'Unattended-Upgrade::(Allowed-Origins|Origins-Pattern)[[:space:]]*\{([^}"]|"[^"]*")*\}' \
      | while read -r key rest; do
        grep -oE '"[^"]*"' <<<"$rest" | while read -r v; do printf '%s:: %s;\n' "$key" "$v"; done
      done
  done
}
EOF
# apt-cache madison <package>: the host's madison/<package>.txt. apt-cache policy <package>...: see stub_policy;
# it drains stdin as apt-get does, so a call without </dev/null swallows the rest of the streamed program.
stub apt-cache 'if [ "$1" = madison ]; then
  [ -f "$P2S_STUB/madison/$2.txt" ] && cat "$P2S_STUB/madison/$2.txt"
  exit 0
fi
[ "$1" = policy ] || exit 0
cat >/dev/null
shift
. "$P2S_STUBLIB/apt.sh"
for p; do stub_policy "$p"; done'
# unattended-upgrade --dry-run: prints the origins it accepts, as unattended-upgrades does, from the merged apt
# config with ${distro_id} and ${distro_codename} filled in, then the packages it would upgrade: those of
# uu-upgrades.txt ("<Release Origin> <package>", what this unattended-upgrades would take from which origin)
# whose origin it accepts, on one "Packages that will be upgraded:" line. fail-uu makes it fail.
stub unattended-upgrade 'cat >/dev/null
[ -e "$P2S_STUB/fail-uu" ] && { echo "E: unattended-upgrade: apt_pkg.Error: E:Unable to parse package file"; exit 1; }
. "$P2S_STUBLIB/apt.sh"
code=$(sed -nE "s/^VERSION_CODENAME=\"?([^\"]*)\"?$/\1/p" "$P2S_ROOT/etc/os-release")
allowed=$(stub_aptconf_dump | sed -nE "s/^Unattended-Upgrade::Allowed-Origins:: \"([^:\"]*):([^\"]*)\";$/o=\1,a=\2/p; s/^Unattended-Upgrade::Origins-Pattern:: \"([^\"]*)\";$/\1/p" \
  | sed "s/\${distro_id}/Ubuntu/g; s/\${distro_codename}/$code/g" | paste -sd, - | sed "s/,o=/, o=/g; s/,origin=/, origin=/g")
echo "Starting unattended upgrades script"
echo "Allowed origins are: $allowed"
up=()
while read -r o p; do
  case ", $allowed," in *", o=$o,"* | *", origin=$o,"*) up+=("$p") ;; esac
done 2>/dev/null <"$P2S_STUB/uu-upgrades.txt"
if [ ${#up[@]} -gt 0 ]; then echo "Packages that will be upgraded: ${up[*]}"
else echo "No packages found that can be upgraded unattended and no pending auto-removals"; fi'
# "apt-get download pkg=ver" leaves a .deb naming its fixture; a version without a fixture is not found.
# apt-get and dpkg-deb drain stdin, as a prompting tool would: the audit itself arrives on stdin, so a call
# without </dev/null swallows the rest of the program (or the remaining branches) and records go missing.
# "apt-get update" fails on fail-update-label (a PPA changed its Label) or fail-update. "apt-get install
# pkg=ver..." installs into the fixture: dpkg-query.txt gets the new versions, php*-common brings the
# candidate changelog, modules-after.txt replaces modules.txt; slow-install and fail-install shape the run.
stub apt-get 'cat >/dev/null
if [ "$1" = download ]; then
  key=${!#}
  [ -f "$P2S_STUB/debs/$key.tar" ] || { echo "E: Version ${key#*=} for ${key%%=*} was not found" >&2; exit 100; }
  echo "$key" >"${key%%=*}_${key#*=}_amd64.deb"
  exit 0
fi
case " $* " in
  *" update "*)
    if [ -e "$P2S_STUB/fail-update-label" ] && [[ " $* " != *" --allow-releaseinfo-change"* ]]; then
      printf "E: Repository \"https://ppa.launchpadcontent.net/ondrej/php/ubuntu noble InRelease\" changed its \x27Label\x27 value from \"***** The main PPA *****\" to \"PPA for PHP\"\n"
      echo "N: This must be accepted explicitly before updates for this repository can be applied."
      exit 100
    fi
    [ -e "$P2S_STUB/fail-update" ] && { echo "E: Could not get lock /var/lib/apt/lists/lock"; exit 100; }
    exit 0 ;;
  *" install "*)
    [ -f "$P2S_STUB/slow-install" ] && sleep "$(cat "$P2S_STUB/slow-install")"
    [ -e "$P2S_STUB/fail-install" ] && { echo "E: Sub-process /usr/bin/dpkg returned an error code (1)"; exit 100; }
    for a; do
      case $a in
        php*=* | libapache2-mod-php*=*)
          p=${a%%=*} v=${a#*=}
          awk -F"|" -v OFS="|" -v p="$p" -v v="$v" "\$2 == p {\$3 = v} {print}" "$P2S_STUB/dpkg-query.txt" >"$P2S_STUB/dpkg-query.new"
          mv "$P2S_STUB/dpkg-query.new" "$P2S_STUB/dpkg-query.txt"
          mkdir -p "$P2S_ROOT/var/lib/dpkg/info"; touch "$P2S_ROOT/var/lib/dpkg/info/$p.list"
          case $p in *-common) [ -f "$P2S_STUB/debs/$a.tar" ] && tar -xf "$P2S_STUB/debs/$a.tar" -C "$P2S_ROOT" ;; esac ;;
      esac
    done
    [ -f "$P2S_STUB/modules-after.txt" ] && cp "$P2S_STUB/modules-after.txt" "$P2S_STUB/modules.txt"
    exit 0 ;;
esac'
stub dpkg-deb 'cat >/dev/null
[ "$1" = --fsys-tarfile ] && exec cat "$P2S_STUB/debs/$(cat "$2").tar"'
stub apt 'exit 0'
stub apt-mark '[ "$1" = showhold ] && [ -f "$P2S_STUB/holds.txt" ] && cat "$P2S_STUB/holds.txt"
exit 0'
stub apt-config '[ "$1" = dump ] || exit 0
. "$P2S_STUBLIB/apt.sh"
stub_aptconf_dump'
# nginx -T as nginx prints it: every loaded file behind a "# configuration file" header, sites-enabled
# entries read through their symlinks. A host without /etc/nginx has no nginx (127).
stub nginx '[ -d "$P2S_ROOT/etc/nginx" ] || { echo "nginx: command not found" >&2; exit 127; }
echo "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok" >&2
for f in "$P2S_ROOT/etc/nginx/nginx.conf" "$P2S_ROOT"/etc/nginx/sites-enabled/*; do
  [ -f "$f" ] || continue
  echo "# configuration file ${f#"$P2S_ROOT"}:"; cat "$f"; echo
done'
stub id 'echo "${STUB_UID:-0}"'
# systemd-run --unit=<name> [--options] <command>: starts the command in its own session, as systemd would
# outside the ssh session, and keeps its pid for "systemctl is-active <name>".
stub systemd-run 'unit=""
while [ $# -gt 0 ]; do case $1 in --unit=*) unit=${1#--unit=} ;; --*) ;; *) break ;; esac; shift; done
mkdir -p "$P2S_STUB/units"
setsid "$@" </dev/null >/dev/null 2>&1 &
echo $! >"$P2S_STUB/units/$unit.pid"'
# curl ... --resolve <name>:<port>:<addr> <scheme>://<name>[:<port>]/: http.txt holds "<site> <code before>
# <code after> [<address>]", <site> being the name for https on 443 and "<scheme>://<name>:<port>" otherwise; an
# address there is the one the vhost listens on, and nothing answers at another. As in curl, a --resolve entry
# counts only for the URL's own name and port, and these .example names resolve nowhere else (exit 6). The
# first call per site answers the first code, later calls the second. A site not listed answers 000 (exit 7).
stub curl 'url=${!#} res="" prev=""
for a; do [ "$prev" = --resolve ] && res=$a; prev=$a; done
scheme=${url%%://*} hp=${url#*://}; hp=${hp%%/*}
name=${hp%%:*} port=${hp#"${hp%%:*}"}; port=${port#:}
[ -n "$port" ] || { [ "$scheme" = https ] && port=443 || port=80; }
case $res in "$name:$port:"*) addr=${res#"$name:$port:"} ;; *) printf 000; exit 6 ;; esac
key=$name; [ "$scheme:$port" = https:443 ] || key=$scheme://$name:$port
line=$(awk -v k="$key" "\$1 == k" "$P2S_STUB/http.txt" 2>/dev/null)
[ -n "$line" ] || { printf 000; exit 7; }
listen=$(awk "{print \$4}" <<<"$line")
[ -z "$listen" ] || [ "$listen" = "$addr" ] || { printf 000; exit 7; }
mark=$P2S_STUB/.curl-${key//[\/:]/_}
if [ -e "$mark" ]; then awk "{printf \"%s\", \$3}" <<<"$line"
else : >"$mark"; awk "{printf \"%s\", \$2}" <<<"$line"; fi'
stub journalctl 'u=${2%.service}
echo "systemd[1]: $u.service: Main process exited, code=exited, status=78/CONFIG"
echo "systemd[1]: Failed to start $u.service - The PHP FastCGI Process Manager."'
# SAPI binaries: the effective upload_progress comes from the fake root's ini files, last assignment wins
# (php.ini, then conf.d in order). A host without /etc/php/<X.Y>/<sapi> behaves as if the binary failed.
# The CLI binary php<X.Y> reads its php.ini from "-c <file>" and its conf.d from PHP_INI_SCAN_DIR, as PHP
# does, so it answers for mod_php when given Apache's ini; without them it reads its own cli/ dir.
# fail-t-<binary> in the host fixture makes the config test fail (FPM: exit 78; CGI: an ini error on stderr).
SAPI_STUB='n=${0##*/}
case $n in
  php-fpm*) s=fpm b=${n#php-fpm} ;;
  php-cgi*) s=cgi b=${n#php-cgi} ;;
  *) s=cli b=${n#php} ;;
esac
d=$P2S_ROOT/etc/php/$b/$s ini=$d/php.ini scan=$d/conf.d
if [ "$s" = cli ]; then
  scan=${PHP_INI_SCAN_DIR:-$scan}
  [ "${1:-}" = -c ] && { ini=$2 d=$(dirname "$2"); shift 2; }
fi
case $1 in
  -t)
    [ -e "$P2S_STUB/fail-t-$n" ] && { echo "ERROR: failed to load configuration file $d/conf.d/99-security.ini" >&2; exit 78; }
    echo "NOTICE: configuration file $d/../php-fpm.conf test is successful" >&2 ;;
  -m)
    if [ -f "$P2S_STUB/modules.txt" ]; then cat "$P2S_STUB/modules.txt"; else printf "[PHP Modules]\nCore\nopcache\nsession\n"; fi ;;
  -v)
    [ -e "$P2S_STUB/fail-t-$n" ] && echo "PHP:  syntax error, unexpected \"=\" in $d/conf.d/99-security.ini on line 3" >&2
    echo "PHP $b.0 (cgi-fcgi)" ;;
  -i)
    [ -d "$d" ] || exit 1
    v=On
    for f in "$ini" "$scan"/*.ini; do
      [ -f "$f" ] || continue
      x=$(sed -nE "s/^[[:space:]]*session\.upload_progress\.enabled[[:space:]]*=[[:space:]]*\"?([^\";[:space:]]+).*/\1/p" "$f" | tail -1)
      [ -n "$x" ] || continue
      case ${x,,} in 0 | off | false | no) v=Off ;; *) v=On ;; esac
    done
    if [ "$s" = cgi ]; then echo "<tr><td class=\"e\">session.upload_progress.enabled</td><td class=\"v\">$v</td><td class=\"v\">$v</td></tr>"
    else echo "session.upload_progress.enabled => $v => $v"; fi ;;
esac'
for b in 7.4 8.1 8.2 8.3 8.4 8.5; do stub "php-fpm$b" "$SAPI_STUB"; stub "php-cgi$b" "$SAPI_STUB"; stub "php$b" "$SAPI_STUB"; done
# apachectl: absent (127) without /etc/apache2 in the fake root; "configtest" fails on fail-configtest in the
# host fixture; "-S" prints the host's apachectl-S.txt, the vhost dump as Apache prints it.
stub apachectl '[ -d "$P2S_ROOT/etc/apache2" ] || { echo "apachectl: command not found" >&2; exit 127; }
case $1 in
  configtest)
    if [ -e "$P2S_STUB/fail-configtest" ]; then
      echo "AH00526: Syntax error on line 4 of /etc/apache2/sites-enabled/shop.conf:" >&2
      echo "Action '"'"'configtest'"'"' failed." >&2
      exit 1
    fi
    echo "Syntax OK" >&2 ;;
  -S) cat "$P2S_STUB/apachectl-S.txt" 2>/dev/null ;;
esac
exit 0'
export PATH="$WORK/bin:$PATH"
# The audit's temp dir on the "host": must be empty again after every run.
export TMPDIR=$WORK/hosttmp
mkdir -p "$TMPDIR"

# Calls an audit may make; anything else in the stub log is a write or a package operation.
READ_ONLY='^(ssh (-o [^ ]+ )*[^ ]+ bash -s|hostname ?|dpkg-query .*|systemctl is-active [^ ]+|systemctl show -p ActiveEnterTimestamp --value [^ ]+|dpkg --compare-versions .*|apt-cache madison [^ ]+|apt-get download -q [^ ]+|dpkg-deb --fsys-tarfile [^ ]+|php-(fpm|cgi)[0-9.]+ -i|php[0-9.]+ -c [^ ]+ -i|apt-mark showhold|apt-config dump|nginx -T|apt-helper .* download-file [^ ]+ [^ ]+)$'
fingerprint() { (cd "$WORK/hosts" && find . -type f -exec md5sum {} + | sort); }

echo "▸ verdict (installed build)"
# shellcheck source=../scripts/lib/versions.sh
. "$S/lib/versions.sh"
# shellcheck source=../scripts/lib/p2s.sh
. "$S/lib/p2s.sh"
# shellcheck source=../scripts/lib/mitigation.sh
. "$S/lib/mitigation.sh"
# shellcheck source=../scripts/lib/hostfacts.sh
. "$S/lib/hostfacts.sh"
vd() { p2s_verdict "$1" "$2" "$(p2s_origin "$2")" "$3"; }
eq "$(vd 8.3 8.3.6-0ubuntu0.24.04.12 no)" "unfixed below-threshold" "Ubuntu 8.3 .12 unfixed"
eq "$(vd 8.3 8.3.6-0ubuntu0.24.04.13 yes)" "fixed distro-threshold" "Ubuntu 8.3 .13 fixed"
eq "$(vd 7.4 1:7.4.33-24+ubuntu24.04.1+deb.sury.org+1 no)" "unfixed no-cve-in-changelog" "sury 7.4.33-24 unfixed"
eq "$(vd 7.4 1:7.4.33-31+ubuntu24.04.1+deb.sury.org+1 yes)" "fixed changelog" "sury 7.4.33-31 fixed by changelog"
eq "$(vd 8.4 8.4.17-1+ubuntu24.04.1+deb.sury.org+1 no)" "unfixed below-threshold" "sury 8.4.17 unfixed"
eq "$(vd 8.4 8.4.27-1+ubuntu24.04.1+deb.sury.org+1 no)" "fixed upstream-threshold" "sury 8.4.27 fixed"
eq "$(vd 8.1 8.1.33-1+ubuntu24.04.1+deb.sury.org+1 no)" "unfixed no-cve-in-changelog" "sury 8.1.33 unfixed"
eq "$(vd 8.1 8.1.34-9+ubuntu24.04.1+deb.sury.org+1 yes)" "fixed changelog" "sury 8.1.34-9 fixed by changelog"
eq "$(vd 8.1 8.1.2-1ubuntu2.28 no)" "fixed distro-threshold" "Ubuntu 8.1 .28 fixed"
eq "$(vd 8.1 8.1.2-1ubuntu2.27 no)" "unfixed below-threshold" "Ubuntu 8.1 .27 unfixed"
eq "$(vd 8.2 8.2.29-1~deb12u1 no)" "unfixed below-threshold" "Debian 8.2.29 without CVE lines unfixed"
eq "$(vd 8.2 8.2.29-1~deb12u2 yes)" "fixed changelog" "Debian backport fixed by changelog"
eq "$(vd 8.5 8.5.12-1+ubuntu24.04.1+deb.sury.org+1 no)" "fixed upstream-threshold" "sury 8.5.12 fixed"
eq "$(vd 8.0 1:8.0.30-9+ubuntu24.04.1+deb.sury.org+1 missing)" "unfixed no-cve-in-changelog" "missing changelog is not a fix"
eq "$(p2s_origin 8.3.6-0ubuntu0.24.04.13) $(p2s_origin 1:7.4.33-31+ubuntu24.04.1+deb.sury.org+1) $(p2s_origin 8.2.29-1~deb12u1) $(p2s_origin 8.3.36-1)" \
  "distro ppa distro other" "origin: Ubuntu, sury, Debian, other"
eq "$(p2s_origin 8.3.27-1+0~20251023.80+debian13~1.gbp1a2b3c) $(p2s_origin 8.4.11-1)" "ppa other" \
  "origin: sury's Debian build (+debian13) is the PPA's; a plain Debian revision stays other"
eq "$(p2s_url_origin https://ppa.launchpadcontent.net/ondrej/php/ubuntu noble/main) \
$(p2s_url_origin https://packages.sury.org/php/ trixie/main) \
$(p2s_url_origin http://security.ubuntu.com/ubuntu noble-security/universe) \
$(p2s_url_origin http://deb.debian.org/debian trixie/main) \
$(p2s_url_origin http://security.debian.org/debian-security trixie-security/main) \
$(p2s_url_origin https://repo.example.com/php noble/main)" \
  "ppa ppa distro distro distro other" "source origin: by URL and suite, as apt names the list files"
p2s_changelog_has_cves "  - debian/patches/CVE-2026-109618_109619.patch" && ok "Ubuntu patch name counts as both CVEs" \
  || bad "Ubuntu patch name counts as both CVEs"
p2s_changelog_has_cves "  - CVE-2026-109618 only" && bad "one CVE alone is not a fix" || ok "one CVE alone is not a fix"

echo "▸ target"
SU81=8.1.32-1+ubuntu22.04.1+deb.sury.org+1
eq "$(p2s_target 8.1.2-1ubuntu2.27 distro unfixed "$SU81|ppa|unfixed" "8.1.2-1ubuntu2.28|distro|fixed")" \
  "8.1.2-1ubuntu2.28 fixed-candidate" "Ubuntu .27: higher sury 8.1.32 skipped, target Ubuntu .28"
eq "$(p2s_target 8.1.2-1ubuntu2.27 distro unfixed "8.1.34-9+ubuntu22.04.1+deb.sury.org+1|ppa|fixed")" \
  "none fixed-distro-build-not-in-cached-lists" "Ubuntu .27: even a fixed PPA build is not a target"
eq "$(p2s_target 8.1.2-1ubuntu2.28 distro fixed "$SU81|ppa|-")" \
  "none installed-fixed" "Ubuntu .28 already fixed: no target"
eq "$(p2s_target 8.1.33-1+ubuntu24.04.1+deb.sury.org+1 ppa unfixed "8.1.34-9+ubuntu24.04.1+deb.sury.org+1|ppa|fixed")" \
  "8.1.34-9+ubuntu24.04.1+deb.sury.org+1 fixed-candidate" "sury 8.1.33: target the fixed 8.1.34-9"
eq "$(p2s_target 8.4.17-1+ubuntu24.04.1+deb.sury.org+1 ppa unfixed "8.4.20-1+ubuntu24.04.1+deb.sury.org+1|ppa|unfixed")" \
  "none no-fixed-build-in-cached-lists" "sury 8.4.17: unfixed 8.4.20 is not a target"
eq "$(p2s_target 8.4.17-1 ppa unfixed "8.4.27-1|ppa|fixed" "8.4.28-1|ppa|fixed" "8.4.26-1|ppa|unfixed")" \
  "8.4.28-1 fixed-candidate" "highest fixed build wins"
eq "$(p2s_target 8.4.17-1 ppa unfixed "8.4.27-1|ppa|-")" "none no-fixed-build-in-cached-lists" "unassessed build is not a target"
eq "$(p2s_target 8.4.17-1 ppa unfixed)" "none no-fixed-build-in-cached-lists" "nothing offered: no target"

echo "▸ apt lists"
eq "$(p2s_list_origin /var/lib/apt/lists/ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_noble_main_binary-amd64_Packages) \
$(p2s_list_origin packages.sury.org_php_dists_bookworm_main_binary-amd64_Packages) \
$(p2s_list_origin mirrors.digitalocean.com_ubuntu_dists_noble-security_main_binary-amd64_Packages) \
$(p2s_list_origin deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages) \
$(p2s_list_origin nginx.org_packages_mainline_ubuntu_noble_Release)" \
  "ppa ppa distro distro other" "list origin: ondrej PPA, sury, Ubuntu mirror, Debian, other"
eq "$(p2s_lists_stale 2026-10-20T23:59:59Z) $(p2s_lists_stale 2026-10-21T00:00:00Z) $(p2s_lists_stale unknown)" \
  "yes no unknown" "lists before the fix day are stale, from it on are not"

echo "▸ host facts: parsing"
NG='# configuration file /etc/nginx/sites-enabled/a:
upstream php84 { server unix:/run/php/php8.4-fpm.sock; server 127.0.0.1:9084; }
server {
  server_name a.example.com b.example.com; # comment { not a block
  location ~ \.php$ { fastcgi_pass unix:/var/run/php/php8.3-fpm.sock; }
  location /x { fastcgi_pass php84; }
}
server { listen 80; server_name static.example.net; }
server { location ~ \.php$ { fastcgi_pass 127.0.0.1:9000; } }'
eq "$(p2s_nginx_sites "$NG")" "$(printf '%s\n' 'a.example.com,b.example.com|unix:/var/run/php/php8.3-fpm.sock' \
  'a.example.com,b.example.com|unix:/run/php/php8.4-fpm.sock' 'a.example.com,b.example.com|127.0.0.1:9084' '-|127.0.0.1:9000')" \
  "nginx: passes per server, upstream resolved, static site skipped, no server_name -> -"
yes_no() { "$@" && echo yes || echo no; }
eq "$(yes_no p2s_listen_matches /run/php/php8.3-fpm.sock unix:/var/run/php/php8.3-fpm.sock) \
$(yes_no p2s_listen_matches /run/php/php8.3-fpm.sock unix:/run/php/php8.4-fpm.sock) \
$(yes_no p2s_listen_matches 9000 127.0.0.1:9000) \
$(yes_no p2s_listen_matches 127.0.0.1:9000 localhost:9000) \
$(yes_no p2s_listen_matches 127.0.0.1:9000 127.0.0.1:9001) \
$(yes_no p2s_listen_matches 10.0.0.5:9000 127.0.0.1:9000)" \
  "yes no yes yes no no" "listen vs fastcgi_pass: /var/run is /run, bare port, loopback names, port and address mismatch"
AS='AH00558: apache2: Could not reliably determine the server'"'"'s fully qualified domain name
VirtualHost configuration:
*:443                  is a NameVirtualHost
         default server shop.example.com (/etc/apache2/sites-enabled/shop.conf:1)
         port 443 namevhost shop.example.com (/etc/apache2/sites-enabled/shop.conf:1)
                 alias www.shop.example.com
                 wild alias *.shop.example.com
         port 443 namevhost blog.example.org (/etc/apache2/sites-enabled/blog.conf:1)
*:80                   static.example.net (/etc/apache2/sites-enabled/static.conf:1)
127.0.0.1:8080         is a NameVirtualHost
         default server loop.example.org (/etc/apache2/sites-enabled/loop.conf:1)
         port 8080 namevhost loop.example.org (/etc/apache2/sites-enabled/loop.conf:1)
[2001:db8::1]:443      v6.example.com (/etc/apache2/sites-enabled/v6.conf:1)
ServerRoot: "/etc/apache2"
Main DocumentRoot: "/var/www/html"
User: name="www-data" id=33'
eq "$(p2s_apache_sites "$AS")" "$(printf '%s\n' 'blog.example.org|443|-' 'loop.example.org|8080|127.0.0.1' 'shop.example.com|443|-' \
  'static.example.net|80|-' 'v6.example.com|443|[2001:db8::1]' 'www.shop.example.com|443|-')" \
  "apachectl -S: name-based vhosts, aliases and single vhosts with port and address, once each; wildcards and settings skipped"
eq "$(p2s_inrelease_name https://ppa.launchpadcontent.net/ondrej/php/ubuntu/ noble)" \
  "ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_noble_InRelease" "cached InRelease name, trailing slash ignored"
eq "$(p2s_release_info "$(printf 'Origin: X\nLabel: A B\nDate: now\nSuite: noble\n')")" "$(printf 'Label: A B\nOrigin: X\nSuite: noble')" \
  "Release info: only the fields apt guards"
eq "$(p2s_enc 'a b%c')" "a%20b%25c" "record values: spaces and % encoded"

echo "▸ audit: records"
BEFORE=$(fingerprint)
: >"$STUB_LOG"
A=$(bash "$S/run.sh" audit web-a); code=$?
eq "$code" 0 "web-a: exit 0"
has "$A" "@p2s schema=1 kind=host host=web-a os=ubuntu-24.04" "web-a: host record"
has "$A" "@p2s schema=1 kind=branch host=web-a branch=8.3 sapi=fpm installed=8.3.6-0ubuntu0.24.04.13 origin=distro active=active cve_changelog=yes verdict=fixed reason=distro-threshold" \
  "web-a: Ubuntu 8.3 .13 fixed"
[ "$(zcat "$LONG.gz" | wc -c)" -gt 65536 ] && ok "long changelog is larger than a pipe buffer" || bad "long changelog is larger than a pipe buffer"
has "$A" "branch=7.4 sapi=fpm installed=1:7.4.33-31+ubuntu24.04.1+deb.sury.org+1 origin=ppa active=active cve_changelog=yes verdict=fixed reason=changelog" \
  "web-a: 7.4 fixed by CVE lines past the pipe buffer"
hasnt "$A" "branch=8.2" "web-a: removed package (rc) skipped"
hasnt "$A" "installed=2:8.3+93ubuntu2" "web-a: php-fpm metapackage skipped"
has "$A" "log: $P2S_CACHE/web-a-audit-" "web-a: log path printed"
LOG_A=$(ls "$P2S_CACHE"/web-a-audit-*.log 2>/dev/null | head -1)
[ -n "$LOG_A" ] && has "$(cat "$LOG_A")" "kind=branch host=web-a branch=8.3" "web-a: records saved in the log" \
  || bad "web-a: records saved in the log"

B=$(bash "$S/run.sh" audit web-b)
has "$B" "branch=8.4 sapi=fpm installed=8.4.17-1+ubuntu24.04.1+deb.sury.org+1 origin=ppa active=active cve_changelog=no verdict=unfixed reason=below-threshold" \
  "web-b: sury 8.4.17 unfixed"
has "$B" "branch=8.3 sapi=fpm installed=8.3.6-0ubuntu0.24.04.12 origin=distro active=inactive cve_changelog=no verdict=unfixed reason=below-threshold" \
  "web-b: Ubuntu 8.3 .12 unfixed, service inactive"
[ "$(zcat "$TOP.gz" | wc -c)" -gt $((2 * 65536)) ] && ok "top-entry changelog is several pipe buffers long" \
  || bad "top-entry changelog is several pipe buffers long"
has "$B" "branch=8.1 sapi=fpm installed=8.1.34-9+ubuntu24.04.1+deb.sury.org+1 origin=ppa active=active cve_changelog=yes verdict=fixed reason=changelog" \
  "web-b: 8.1 fixed by CVE lines in the top entry of a long changelog (SIGPIPE)"

C=$(bash "$S/run.sh" audit web-c); code=$?
eq "$code" 0 "web-c: exit 0 without PHP-FPM"
has "$C" "@p2s schema=1 kind=host host=web-c os=debian-12" "web-c: Debian host record"
hasnt "$C" "kind=branch" "web-c: no branch records (CLI only)"

echo "▸ audit: candidates and targets"
has "$B" "branch=8.3 sapi=fpm installed=8.3.6-0ubuntu0.24.04.12 origin=distro active=inactive cve_changelog=no verdict=unfixed reason=below-threshold target=8.3.6-0ubuntu0.24.04.13 target_reason=fixed-candidate" \
  "web-b: Ubuntu .12 with sury 8.3.35 above it targets Ubuntu .13"
has "$B" "kind=candidate host=web-b branch=8.3 version=8.3.6-0ubuntu0.24.04.13 origin=distro cve_changelog=yes verdict=fixed reason=distro-threshold" \
  "web-b: Ubuntu .13 candidate judged from its own changelog"
has "$B" "kind=candidate host=web-b branch=8.3 version=8.3.35-1+ubuntu24.04.1+deb.sury.org+1 origin=ppa cve_changelog=not-checked verdict=- reason=not-assessed" \
  "web-b: sury 8.3.35 recorded with its origin, not assessed"
eq "$(grep -c 'kind=candidate host=web-b branch=8.3 ' <<<"$B")" 3 "web-b: every offered 8.3 build recorded once (duplicate .13 merged)"
has "$B" "branch=8.4 sapi=fpm installed=8.4.17-1+ubuntu24.04.1+deb.sury.org+1 origin=ppa active=active cve_changelog=no verdict=unfixed reason=below-threshold target=none target_reason=no-fixed-build-in-cached-lists" \
  "web-b: PPA candidate below threshold without CVE lines -> no target"
has "$B" "kind=candidate host=web-b branch=8.4 version=8.4.20-1+ubuntu24.04.1+deb.sury.org+1 origin=ppa cve_changelog=no verdict=unfixed reason=below-threshold" \
  "web-b: the unfixed 8.4.20 candidate and its reason"
has "$B" "branch=8.1 sapi=fpm installed=8.1.34-9+ubuntu24.04.1+deb.sury.org+1 origin=ppa active=active cve_changelog=yes verdict=fixed reason=changelog target=none target_reason=installed-fixed" \
  "web-b: fixed 8.1 needs no target"

D=$(bash "$S/run.sh" audit web-d); code=$?
eq "$code" 0 "web-d: exit 0"
has "$D" "branch=8.1 sapi=fpm installed=8.1.33-1+ubuntu24.04.1+deb.sury.org+1 origin=ppa active=active cve_changelog=no verdict=unfixed reason=no-cve-in-changelog target=8.1.34-9+ubuntu24.04.1+deb.sury.org+1 target_reason=fixed-candidate" \
  "web-d: sury 8.1.33 targets 8.1.34-9"
has "$D" "kind=candidate host=web-d branch=8.1 version=8.1.34-9+ubuntu24.04.1+deb.sury.org+1 origin=ppa cve_changelog=yes verdict=fixed reason=changelog" \
  "web-d: 8.1.34-9 fixed by its changelog"
has "$D" "kind=candidate host=web-d branch=7.4 version=1:7.4.33-31+ubuntu24.04.1+deb.sury.org+1 origin=ppa cve_changelog=download-failed verdict=unfixed reason=no-cve-in-changelog" \
  "web-d: failed download recorded"
has "$D" "branch=7.4 sapi=fpm installed=1:7.4.33-24+ubuntu24.04.1+deb.sury.org+1 origin=ppa active=active cve_changelog=no verdict=unfixed reason=no-cve-in-changelog target=none target_reason=no-fixed-build-in-cached-lists" \
  "web-d: failed download -> no target, audit goes on"
has "$D" "target=none target_reason=no-fixed-build-in-cached-lists lists_updated=2026-09-30T06:00:00Z lists_stale=yes" \
  "web-d: PPA lists from before the fixes flagged as stale"
has "$B" "branch=8.4 sapi=fpm installed=8.4.17-1+ubuntu24.04.1+deb.sury.org+1" "web-b: 8.4 branch present"
has "$B" "target_reason=no-fixed-build-in-cached-lists lists_updated=2026-10-24T06:00:00Z lists_stale=no" \
  "web-b: fresh PPA lists: no fix in them is a real 'not offered yet'"
has "$B" "target=8.3.6-0ubuntu0.24.04.13 target_reason=fixed-candidate lists_updated=2026-10-24T06:00:00Z lists_stale=no" \
  "web-b: distro lists dated by the newest list, not the 2024 release pocket"
has "$A" "lists_updated=unknown lists_stale=unknown" "web-a: no apt lists -> unknown"

E=$(bash "$S/run.sh" audit web-e)
has "$E" "branch=8.1 sapi=fpm installed=8.1.2-1ubuntu2.28 origin=distro active=active cve_changelog=yes verdict=fixed reason=distro-threshold target=none target_reason=installed-fixed" \
  "web-e: Ubuntu .28 stays, higher sury 8.1.32 is not a target"
has "$E" "kind=candidate host=web-e branch=8.1 version=8.1.32-1+ubuntu22.04.1+deb.sury.org+1 origin=ppa" "web-e: sury 8.1.32 recorded"

eq "$(grep '^apt-get ' "$STUB_LOG" | sort)" "$(printf '%s\n' \
  'apt-get download -q php7.4-common=1:7.4.33-31+ubuntu24.04.1+deb.sury.org+1' \
  'apt-get download -q php8.1-common=8.1.34-9+ubuntu24.04.1+deb.sury.org+1' \
  'apt-get download -q php8.3-common=8.3.6-0ubuntu0.24.04.13' \
  'apt-get download -q php8.4-common=8.4.20-1+ubuntu24.04.1+deb.sury.org+1')" \
  "downloads: only newer same-origin builds of unfixed branches"
eq "$(find "$TMPDIR" -mindepth 1 | head -3)" "" "no candidate download left behind"

bash "$S/run.sh" audit no-such-host >/dev/null 2>&1; code=$?
eq "$code" 255 "unreachable host: ssh exit code passed through"

echo "▸ audit: host facts"
J=$(bash "$S/run.sh" audit web-j); code=$?
eq "$code" 0 "web-j: exit 0"
has "$J" "kind=webserver host=web-j nginx=present apache2=inactive" "web-j: nginx present, Apache not running"
has "$J" "kind=vhost host=web-j names=shop.example.com,www.shop.example.com pass=unix:/var/run/php/php8.3-fpm.sock branch=8.3 pool=www" \
  "web-j: symlinked site mapped to php8.3 www"
has "$J" "kind=vhost host=web-j names=blog.example.org pass=unix:/run/php/php8.4-fpm.sock branch=8.4 pool=www" \
  "web-j: site behind an upstream mapped to php8.4 www"
hasnt "$J" "names=static.example.net" "web-j: static site has no pool"
has "$J" "kind=pool host=web-j branch=8.3 pool=www listen=/run/php/php8.3-fpm.sock sites=1 used=yes" "web-j: 8.3 www used"
has "$J" "kind=pool host=web-j branch=8.3 pool=legacy listen=/run/php/php8.3-legacy.sock sites=0 used=no" "web-j: 8.3 legacy unused"
hasnt "$J" "pool=global" "web-j: [global] in php-fpm.conf is not a pool"
has "$J" "branch=8.3 sapi=fpm installed=8.3.6-0ubuntu0.24.04.13" "web-j: 8.3 branch present"
has "$J" "started=2026-10-20T06:00:00Z installed_at=2026-10-22T06:00:00Z restart=needed" "web-j: 8.3 started before install -> restart needed"
has "$J" "started=2026-10-25T06:00:00Z installed_at=2026-10-24T07:00:00Z restart=ok" "web-j: 8.4 started after the newest package (opcache) -> ok"
has "$J" "kind=hold host=web-j package=php8.3-fpm" "web-j: held php package"
hasnt "$J" "package=nginx" "web-j: non-PHP hold left out"
has "$J" "kind=source host=web-j file=/etc/apt/sources.list.d/ondrej-ubuntu-php-noble.sources uri=https://ppa.launchpadcontent.net/ondrej/php/ubuntu/ suite=noble release_info=changed changed=Label" \
  "web-j: deb822 PPA source, Label changed"
hasnt "$J" "ondrej/nginx" "web-j: commented-out source ignored"
has "$J" "kind=autoupdate host=web-j periodic=1 origins=3 ppa_covered=no" "web-j: unattended-upgrades on, PPA not covered"
has "$J" 'kind=uu_origin host=web-j value=${distro_id}:${distro_codename}-security' "web-j: origins recorded"
has "$D" "kind=webserver host=web-d nginx=absent" "web-d: no nginx"
has "$D" "kind=source host=web-d file=/etc/apt/sources.list.d/ondrej-php.list uri=https://ppa.launchpadcontent.net/ondrej/php/ubuntu suite=noble release_info=same changed=-" \
  "web-d: one-line source; only Date and Version differ -> same"
has "$D" "kind=source host=web-d file=/etc/apt/sources.list uri=https://packages.sury.org/php/ suite=noble release_info=unknown" \
  "web-d: sury source without a cached InRelease -> unknown"
hasnt "$D" "uri=http://archive.ubuntu.com" "web-d: distro sources are not PPA sources"
has "$D" "kind=autoupdate host=web-d periodic=1 origins=2 ppa_covered=yes" "web-d: PPA origin covered"
has "$D" "restart=unknown" "web-d: no start time -> restart unknown"
has "$D" "kind=pool host=web-d branch=8.1 pool=www listen=/run/php/php8.1-fpm.sock sites=0 used=unknown" \
  "web-d: no nginx -> a pool without sites is unknown, not a stop candidate"
K=$(bash "$S/run.sh" audit web-k)
has "$K" "kind=webserver host=web-k nginx=present apache2=active" "web-k: nginx and Apache"
has "$K" "kind=pool host=web-k branch=8.3 pool=www listen=/run/php/php8.3-fpm.sock sites=1 used=yes" "web-k: pool used by nginx"
has "$K" "kind=pool host=web-k branch=8.3 pool=api listen=127.0.0.1:9083 sites=0 used=unknown" \
  "web-k: Apache running -> a pool nginx does not use is unknown, not a stop candidate"
eq "$(find "$TMPDIR" -mindepth 1 | head -3)" "" "no InRelease download left behind"

echo "▸ audit: mitigation"
G=$(bash "$S/run.sh" audit web-g)
has "$G" "kind=mitigation host=web-g branch=8.3 sapi=fpm ini=legacy action=inspected upload_progress=Off overrides=0 state=mitigated" \
  "web-g: legacy fix.sh file counts as mitigated"
has "$G" "kind=mitigation host=web-g branch=8.3 sapi=cgi ini=foreign action=inspected upload_progress=On overrides=0 state=foreign" \
  "web-g: foreign 99-security.ini in CGI reported"
has "$A" "kind=mitigation host=web-a branch=8.3 sapi=fpm ini=absent action=inspected upload_progress=unknown overrides=0 state=unknown" \
  "web-a: SAPI without readable config -> unknown, not mitigated"
hasnt "$C" "kind=mitigation" "web-c: CLI only -> no mitigation records"

echo "▸ audit: mod_php"
L=$(bash "$S/run.sh" audit web-l); code=$?
eq "$code" 0 "web-l: exit 0"
has "$L" "kind=branch host=web-l branch=8.3 sapi=apache2 installed=8.3.6-0ubuntu0.24.04.12 origin=distro active=active cve_changelog=no verdict=unfixed reason=below-threshold target=8.3.6-0ubuntu0.24.04.13 target_reason=fixed-candidate" \
  "web-l: Apache with mod_php 8.3 recorded as SAPI apache2, with its verdict and target"
has "$L" "started=2026-10-20T06:00:00Z installed_at=2026-10-22T06:00:00Z restart=needed" \
  "web-l: Apache started before the mod_php install -> restart needed"
has "$L" "kind=candidate host=web-l branch=8.3 version=8.3.6-0ubuntu0.24.04.13 origin=distro cve_changelog=yes verdict=fixed reason=distro-threshold sapi=apache2" \
  "web-l: mod_php candidate judged from its changelog"
has "$L" "kind=mitigation host=web-l branch=8.3 sapi=apache2 ini=absent action=inspected upload_progress=On overrides=0 state=not-mitigated" \
  "web-l: upload_progress read with Apache's php.ini and conf.d"
hasnt "$L" "sapi=cli" "web-l: CLI is not a web SAPI"
hasnt "$L" "sapi=fpm" "web-l: no FPM on a mod_php-only host"

Va=$(bash "$S/run.sh" audit web-v)
has "$Va" "kind=branch host=web-v branch=7.4 sapi=apache2 installed=1:7.4.33-31+ubuntu24.04.1+deb.sury.org+1 origin=ppa active=not-loaded" \
  "web-v: mod_php 7.4 installed but not loaded by Apache -> not-loaded"
has "$Va" "branch=7.4 sapi=apache2 installed=1:7.4.33-31+ubuntu24.04.1+deb.sury.org+1" "web-v: 7.4 record present"
has "$Va" "kind=override host=web-v branch=8.3 sapi=apache2 file=/etc/apache2/sites-enabled/shop.conf line=6 pool=- directive=php_admin_flag value=on enables=yes" \
  "web-v: audit finds the Apache override through the sites-enabled symlink"
has "$Va" "kind=mitigation host=web-v branch=8.3 sapi=apache2 ini=absent action=inspected upload_progress=On overrides=1 state=override" \
  "web-v: audit reports the override state"

echo "▸ audit: read-only"
WRITES=$(grep -vE "$READ_ONLY" "$STUB_LOG")
eq "$WRITES" "" "no write command or package operation in the stub log"
eq "$(printf 'apt-get install -y php8.3-fpm\nsystemctl restart php8.3-fpm\ndpkg -i x.deb\n' | grep -cvE "$READ_ONLY")" 3 \
  "the read-only filter flags installs, restarts and dpkg -i"
eq "$(fingerprint)" "$BEFORE" "fake roots unchanged"

echo "▸ ensure"
INI=$(p2s_ini_content)
ini() { cat "$WORK/hosts/$1/root/etc/php/$2/conf.d/99-security.ini" 2>/dev/null; }
: >"$STUB_LOG"
F=$(bash "$S/run.sh" ensure web-f); code=$?
eq "$code" 0 "web-f fresh: exit 0"
eq "$(ini web-f 8.3/fpm)" "$INI" "web-f: 8.3 fpm ini written"
eq "$(ini web-f 8.3/cgi)" "$INI" "web-f: 8.3 cgi ini written"
eq "$(ini web-f 8.4/fpm)" "$INI" "web-f: 8.4 fpm ini written"
eq "$(ini web-f 8.3/cli)" "" "web-f: CLI conf.d untouched"
eq "$(grep -E '^systemctl (reload|restart|stop|start) ' "$STUB_LOG" | sort)" "$(printf 'systemctl reload php8.3-fpm\nsystemctl reload php8.4-fpm')" \
  "web-f: both pools reloaded once, nothing restarted"
has "$F" "kind=mitigation host=web-f branch=8.3 sapi=fpm ini=absent action=written upload_progress=Off overrides=0 state=mitigated" "web-f: 8.3 fpm record"
has "$F" "kind=mitigation host=web-f branch=8.3 sapi=cgi ini=absent action=written upload_progress=Off overrides=0 state=mitigated" "web-f: 8.3 cgi record (HTML -i output parsed)"
has "$F" "rm /etc/php/8.3/fpm/conf.d/99-security.ini && systemctl reload php8.3-fpm" "web-f: rollback line for the pool"
AFTER1=$(fingerprint)
: >"$STUB_LOG"
F2=$(bash "$S/run.sh" ensure web-f); code=$?
eq "$code" 0 "web-f second run: exit 0"
eq "$(fingerprint)" "$AFTER1" "web-f second run: no file changes"
eq "$(grep -cE '^systemctl (reload|restart) ' "$STUB_LOG")" 0 "web-f second run: no reload"
has "$F2" "branch=8.3 sapi=fpm ini=owned action=unchanged upload_progress=Off overrides=0 state=mitigated" "web-f second run: owned, unchanged"

LEGACY=$(ini web-g 8.3/fpm); FOREIGN=$(ini web-g 8.3/cgi)
: >"$STUB_LOG"
Gx=$(bash "$S/run.sh" ensure web-g); code=$?
eq "$code" 3 "web-g: foreign file -> exit 3"
eq "$(ini web-g 8.3/fpm)" "$LEGACY" "web-g: legacy file adopted as is"
eq "$(ini web-g 8.3/cgi)" "$FOREIGN" "web-g: foreign file unchanged"
has "$Gx" "branch=8.3 sapi=fpm ini=legacy action=adopted upload_progress=Off overrides=0 state=mitigated" "web-g: adopted record"
has "$Gx" "branch=8.3 sapi=cgi ini=foreign action=left-foreign upload_progress=On overrides=0 state=foreign" "web-g: foreign record"
eq "$(grep -cE '^systemctl reload ' "$STUB_LOG")" 0 "web-g: nothing written, nothing reloaded"

H=$(bash "$S/run.sh" ensure web-h); code=$?
eq "$code" 3 "web-h: pool override -> exit 3"
has "$H" "kind=override host=web-h branch=8.3 sapi=fpm file=/etc/php/8.3/fpm/pool.d/www.conf line=6 pool=www directive=php_admin_flag value=on enables=yes" \
  "web-h: override named with pool, file and line"
has "$H" "kind=override host=web-h branch=8.3 sapi=fpm file=/etc/php/8.3/fpm/pool.d/shop.conf line=5 pool=shop directive=php_admin_value value=0 enables=no" \
  "web-h: disabling override recorded, not counted"
hasnt "$H" "line=5 pool=www" "web-h: commented-out override ignored"
has "$H" "kind=mitigation host=web-h branch=8.3 sapi=fpm ini=absent action=written upload_progress=Off overrides=1 state=override" \
  "web-h: master Off but a pool re-enables it -> override"

: >"$STUB_LOG"
I=$(bash "$S/run.sh" ensure web-i); code=$?
eq "$code" 1 "web-i: config test fails -> exit 1"
eq "$(ini web-i 8.3/fpm)" "" "web-i: new ini removed"
eq "$(grep -E '^systemctl (reload|restart|stop) ' "$STUB_LOG")" "" "web-i: pool neither reloaded nor stopped"
has "$I" "action=test-failed" "web-i: test failure recorded"
has "$I" "ERROR: failed to load configuration file" "web-i: config test output shown"

echo "▸ ensure: mod_php"
: >"$STUB_LOG"
V=$(bash "$S/run.sh" ensure web-v); code=$?
eq "$code" 3 "web-v: Apache-level override -> exit 3"
eq "$(ini web-v 8.3/apache2)" "$INI" "web-v: 8.3 apache2 ini written"
eq "$(ini web-v 7.4/apache2)" "$INI" "web-v: ini written for an installed mod_php Apache does not load yet"
eq "$(ini web-v 8.3/cli)" "" "web-v: CLI conf.d untouched"
has "$V" "kind=override host=web-v branch=8.3 sapi=apache2 file=/etc/apache2/sites-enabled/shop.conf line=6 pool=- directive=php_admin_flag value=on enables=yes" \
  "web-v: Apache override named with file and line"
has "$V" "/etc/apache2/sites-enabled/shop.conf:6" "web-v: file and line in the human section too"
has "$V" "kind=override host=web-v branch=8.3 sapi=apache2 file=/etc/apache2/conf-enabled/uploads.conf line=2 pool=- directive=php_value value=0 enables=no" \
  "web-v: disabling override recorded, directive name in any case"
hasnt "$V" "line=5 pool=-" "web-v: commented-out Apache override ignored"
hasnt "$V" "old.conf" "web-v: a site that is not enabled is not scanned"
has "$V" "kind=mitigation host=web-v branch=8.3 sapi=apache2 ini=absent action=written upload_progress=Off overrides=1 state=override" \
  "web-v: ini Off but Apache re-enables it -> override"
has "$V" "kind=mitigation host=web-v branch=7.4 sapi=apache2 ini=absent action=written-not-running upload_progress=Off overrides=0 state=mitigated" \
  "web-v: 7.4 not loaded -> written, nothing reloaded for it, no Apache overrides counted"
eq "$(grep -E '^systemctl (reload|restart|stop|start) ' "$STUB_LOG")" "systemctl reload apache2" "web-v: Apache reloaded once, nothing restarted"
has "$V" "rm /etc/php/8.3/apache2/conf.d/99-security.ini && systemctl reload apache2" "web-v: rollback line reloads Apache"

BEFORE_ROOT=$(fingerprint)
NR=$(STUB_UID=1000 bash "$S/run.sh" ensure web-h); code=$?
eq "$code" 1 "not root: exit 1"
has "$NR" "STOP: ensure must run as root" "not root: says why"
eq "$(fingerprint)" "$BEFORE_ROOT" "not root: nothing changed"

H2=$(bash "$S/run.sh" audit web-h)
has "$H2" "kind=mitigation host=web-h branch=8.3 sapi=fpm ini=owned action=inspected upload_progress=Off overrides=1 state=override" \
  "audit after ensure: owned file, override still reported"

echo "▸ apt hook"
HK=$WORK/hosts/web-f/root/usr/local/sbin/php2shell-ensure
HC=$WORK/hosts/web-f/root/etc/apt/apt.conf.d/99php2shell-ensure
HL=$WORK/hosts/web-f/root/var/log/php2shell-ensure.log
[ -x "$HK" ] && ok "ensure installed the hook script, executable" || bad "ensure installed the hook script, executable"
has "$(cat "$HC" 2>/dev/null)" 'DPkg::Post-Invoke { "if [ -x /usr/local/sbin/php2shell-ensure ]; then timeout 120 /usr/local/sbin/php2shell-ensure || true; fi"; };' \
  "apt conf calls it after every dpkg run, never failing"
has "$F" "kind=ensure_hook host=web-f action=installed state=present" "first ensure: hook installed"
has "$F" "rm /etc/apt/apt.conf.d/99php2shell-ensure /usr/local/sbin/php2shell-ensure" "first ensure: rollback line for the hook"
has "$F2" "kind=ensure_hook host=web-f action=unchanged state=present" "second ensure: up-to-date hook left alone"
hasnt "$F2" "rm /etc/apt/apt.conf.d/99php2shell-ensure" "second ensure: no rollback line for an untouched hook"

# A branch apt installs later: the hook alone gives it the ini.
printf 'ii |php8.2-fpm|8.2.35-1+ubuntu24.04.1+deb.sury.org+1\n' >>"$WORK/hosts/web-f/dpkg-query.txt"
mkdir -p "$WORK/hosts/web-f/root/etc/php/8.2/fpm/conf.d"
echo php8.2-fpm >>"$WORK/hosts/web-f/active.txt"
P2S_STUB=$WORK/hosts/web-f STUB_HOST=web-f "$HK"; code=$?
eq "$code" 0 "hook run: exit 0"
eq "$(ini web-f 8.2/fpm)" "$INI" "hook run: the new 8.2 branch got its ini"
has "$(cat "$HL")" "kind=mitigation host=web-f branch=8.2 sapi=fpm ini=absent action=written upload_progress=Off" "hook run: logged"
eq "$(ini web-f 8.3/cgi)" "$INI" "hook run: existing SAPIs untouched and still mitigated"

# A hook that fails inside still exits 0, and apt's command line swallows any exit code anyway.
printf 'ii |php8.1-fpm|8.1.2-1ubuntu2.28\n' >>"$WORK/hosts/web-f/dpkg-query.txt"
mkdir -p "$WORK/hosts/web-f/root/etc/php/8.1/fpm/conf.d"
: >"$WORK/hosts/web-f/fail-t-php-fpm8.1"
P2S_STUB=$WORK/hosts/web-f STUB_HOST=web-f "$HK"; code=$?
eq "$code" 0 "hook run with a failing config test: still exit 0"
has "$(cat "$HL")" "ensure finished with exit 1" "hook failure logged"
eq "$(ini web-f 8.1/fpm)" "" "hook failure: the ini that broke the config test was rolled back"
printf '#!/bin/sh\nexit 7\n' >"$WORK/bin/failing-hook"; chmod +x "$WORK/bin/failing-hook"
CMD=$(sed -nE 's/.*Post-Invoke \{ "(.*)"; \};/\1/p' "$HC" | sed "s#/usr/local/sbin/php2shell-ensure#$WORK/bin/failing-hook#g")
bash -c "$CMD"; code=$?
eq "$code" 0 "apt's Post-Invoke command exits 0 even when the hook exits 7"

# Apache with mod_php installed later: the hook gives it the ini too.
printf 'ii |libapache2-mod-php8.3|8.3.6-0ubuntu0.24.04.13\n' >>"$WORK/hosts/web-f/dpkg-query.txt"
mkdir -p "$WORK/hosts/web-f/root/etc/php/8.3/apache2/conf.d" "$WORK/hosts/web-f/root/etc/apache2"
P2S_STUB=$WORK/hosts/web-f STUB_HOST=web-f "$HK"; code=$?
eq "$code" 0 "hook run with a new mod_php: exit 0"
eq "$(ini web-f 8.3/apache2)" "$INI" "hook run: the new mod_php got its ini"
has "$(cat "$HL")" "kind=mitigation host=web-f branch=8.3 sapi=apache2 ini=absent action=written-not-running upload_progress=Off" \
  "hook run: mod_php logged, Apache not running so nothing reloaded"

H1=$(bash "$S/run.sh" audit web-f)
has "$H1" "kind=ensure_hook host=web-f state=present" "audit: hook present"
has "$A" "kind=ensure_hook host=web-a state=missing" "audit: hook missing"
echo "# local edit" >>"$HK"
H2=$(bash "$S/run.sh" audit web-f)
has "$H2" "kind=ensure_hook host=web-f state=outdated" "audit: changed hook is outdated"
H3=$(bash "$S/run.sh" ensure web-f)
has "$H3" "kind=ensure_hook host=web-f action=updated state=present" "ensure: outdated hook rewritten"

echo "▸ fix"
state() { echo "$WORK/hosts/$1/root/var/lib/php2shell"; }
: >"$STUB_LOG"
M=$(bash "$S/run.sh" fix web-m); code=$?
eq "$code" 0 "web-m: fixed path, exit 0"
has "$M" "patch started as unit php2shell-fix-" "web-m: the patch runs in a transient unit"
INSTALL=$(grep -E '^apt-get .* install ' "$STUB_LOG")
for p in php8.3-cli php8.3-common php8.3-fpm php8.3-opcache; do
  has "$INSTALL" "$p=8.3.6-0ubuntu0.24.04.13" "web-m: $p pinned to the target"
done
has "$INSTALL" "--allow-downgrades" "web-m: install may move to the pinned version in either direction"
hasnt "$INSTALL" "php8.3-redis" "web-m: PECL extension from its own source is not pinned to the PHP version"
has "$(cat "$WORK/hosts/web-m/dpkg-query.txt")" "ii |php8.3-redis|6.0.2-1+ubuntu24.04.1+deb.sury.org+1|php-redis" "web-m: php8.3-redis keeps its own version"
hasnt "$INSTALL" "php8.5" "web-m: fixed 8.5 not reinstalled"
has "$M" "kind=fix host=web-m branch=8.3 before=8.3.6-0ubuntu0.24.04.12 after=8.3.6-0ubuntu0.24.04.13 target=8.3.6-0ubuntu0.24.04.13 fixed=yes restart=done modules=same state=fixed" \
  "web-m: 8.3 installed, fixed, restarted"
has "$M" "kind=fix host=web-m branch=8.5 before=8.5.12-1+ubuntu24.04.1+deb.sury.org+1 after=8.5.12-1+ubuntu24.04.1+deb.sury.org+1 target=none fixed=yes" \
  "web-m: 8.5 already fixed, nothing installed"
has "$(grep '^systemctl restart' "$STUB_LOG")" "systemctl restart php8.3-fpm" "web-m: 8.3 pool restarted"
hasnt "$(cat "$STUB_LOG")" "systemctl reload php8.3-fpm" "web-m: ensure leaves the reload to the restart"
has "$M" "kind=mitigation host=web-m branch=8.3 sapi=fpm ini=absent action=written upload_progress=Off overrides=0 state=mitigated" "web-m: ensure ran for 8.3"
eq "$(ls "$WORK/hosts/web-m/root/etc/php/8.5/fpm/conf.d/99-php2shell-backtraces.ini" 2>/dev/null)" "" "web-m: 8.5 fixed -> no backtraces ini"
has "$M" "kind=probe host=web-m name=shop.example.com before=200 after=200" "web-m: site probed before and after"
has "$M" "kind=probe_summary host=web-m state=unchanged" "web-m: HTTP unchanged"
eq "$(ls "$WORK/hosts/web-m/root/root/"etc-php-*.tgz 2>/dev/null | wc -l)" 1 "web-m: /etc/php backed up"
has "$M" "tar xzf /root/etc-php-" "web-m: rollback: restore the backup"
has "$M" "apt-get install --allow-downgrades php8.3-cli=8.3.6-0ubuntu0.24.04.12 php8.3-common=8.3.6-0ubuntu0.24.04.12" "web-m: rollback: back to the old build"
has "$M" "rm /etc/php/8.3/fpm/conf.d/99-security.ini && systemctl reload php8.3-fpm" "web-m: rollback: the ini"
has "$M" "kind=run_end target=web-m mode=fix exit=0 status=ok" "web-m: runner closes the log"

N=$(bash "$S/run.sh" fix web-n); code=$?
eq "$code" 3 "web-n: no fixed build offered -> exit 3"
hasnt "$(grep -E '^apt-get .* install ' "$STUB_LOG")" "php8.4" "web-n: nothing installed for 8.4"
has "$N" "kind=fix host=web-n branch=8.4 before=8.4.17-1+ubuntu24.04.1+deb.sury.org+1 after=8.4.17-1+ubuntu24.04.1+deb.sury.org+1 target=none fixed=no restart=done modules=same state=unfixed-mitigated" \
  "web-n: 8.4 unfixed but mitigated, pool restarted for the new ini"
has "$N" "kind=mitigation host=web-n branch=8.4 sapi=fpm ini=absent action=written upload_progress=Off" "web-n: mitigation applied"
has "$(cat "$WORK/hosts/web-n/root/etc/php/8.5/fpm/conf.d/99-php2shell-backtraces.ini" 2>/dev/null)" "fatal_error_backtraces = 0" "web-n: 8.5 unfixed -> backtraces off"
has "$N" "kind=probe_summary host=web-n state=no-sites" "web-n: no sites -> its own state, not unchanged"
has "$N" "no sites found" "web-n: says so"

O=$(bash "$S/run.sh" fix web-o); code=$?
eq "$code" 1 "web-o: config test fails -> exit 1"
eq "$(ls "$WORK/hosts/web-o/root/etc/php/8.3/fpm/conf.d/99-security.ini" 2>/dev/null)" "" "web-o: new ini removed"
has "$O" "branch=8.3 sapi=fpm ini=absent action=test-failed" "web-o: ensure reports the failed test"
has "$O" "restart=skipped modules=same state=test-failed" "web-o: pool not restarted"

P=$(bash "$S/run.sh" fix web-p); code=$?
eq "$code" 1 "web-p: pool down after restart -> exit 1"
has "$P" "php8.3-fpm is DOWN after its restart" "web-p: says so"
has "$P" "Main process exited, code=exited, status=78/CONFIG" "web-p: journal excerpt"
has "$P" "restart=failed modules=same state=pool-down" "web-p: recorded"

Q=$(bash "$S/run.sh" fix web-q); code=$?
eq "$code" 1 "web-q: held package -> exit 1"
has "$Q" "STOP: held PHP packages: php8.3-fpm" "web-q: names the held package"
has "$Q" "kind=preflight host=web-q result=failed reason=held packages=php8.3-fpm" "web-q: preflight record"
hasnt "$Q" "kind=fix " "web-q: stops before any branch"

Rr=$(bash "$S/run.sh" fix web-r); code=$?
eq "$code" 1 "web-r: changed Release Label -> exit 1"
has "$Rr" "apt-get update --allow-releaseinfo-change-label" "web-r: accept command printed"
has "$Rr" "kind=preflight host=web-r result=failed reason=release-info-changed fields=Label" "web-r: preflight record"
hasnt "$Rr" "kind=fix " "web-r: nothing installed"
hasnt "$(grep '^apt-get ' "$STUB_LOG")" "--allow-releaseinfo-change" "web-r: the patcher never runs the accept command itself"

Tt=$(bash "$S/run.sh" fix web-t); code=$?
eq "$code" 3 "web-t: HTTP status changed -> exit 3"
has "$Tt" "shop.example.com: 200 -> 502" "web-t: names the site"
has "$Tt" "kind=probe_summary host=web-t state=changed" "web-t: recorded"

S1=$(bash "$S/run.sh" fix web-s 2>&1); code=$?
eq "$code" 255 "web-s: connection dropped mid-upgrade"
for i in $(seq 1 60); do ls "$(state web-s)"/*.exit >/dev/null 2>&1 && break; sleep 0.25; done
eq "$(cat "$(state web-s)"/*.exit 2>/dev/null)" 0 "web-s: the unit ran to its end after the drop"
rm "$WORK/hosts/web-s/drop-after"
S2=$(bash "$S/run.sh" fix web-s); code=$?
eq "$code" 0 "web-s: next run hands back the finished run's exit code"
has "$S2" "finished while nobody was watching; its log follows. No new patch was started." "web-s: reads the finished log"
has "$S2" "state=fixed" "web-s: the log shows the fix"
eq "$(ls "$WORK/hosts/web-s/units/" | wc -l)" 1 "web-s: one patch unit only"

U1=$(bash "$S/run.sh" fix web-u 2>&1); code=$?
eq "$code" 255 "web-u: connection dropped mid-upgrade"
rm "$WORK/hosts/web-u/drop-after"
U2=$(bash "$S/run.sh" fix web-u); code=$?
has "$U2" "attaching to run" "web-u: next run attaches to the running unit"
eq "$code" 0 "web-u: and follows it to its exit code"
eq "$(ls "$WORK/hosts/web-u/units/" | wc -l)" 1 "web-u: no second patch while one runs"
U3=$(bash "$S/run.sh" fix web-u); code=$?
has "$U3" "patch started as unit" "web-u: a run reported once lets the next call start a new patch"

echo "▸ fix: mod_php"
: >"$STUB_LOG"
We=$(bash "$S/run.sh" ensure web-w); code=$?
eq "$code" 1 "web-w ensure: apachectl configtest fails -> exit 1"
eq "$(ls "$WORK/hosts/web-w/root/etc/php/8.3/apache2/conf.d/99-security.ini" 2>/dev/null)" "" "web-w ensure: new ini removed"
has "$We" "branch=8.3 sapi=apache2 ini=absent action=test-failed" "web-w ensure: failed configtest recorded"
has "$We" "AH00526: Syntax error" "web-w ensure: configtest output shown"
eq "$(grep -E '^systemctl (reload|restart|stop) ' "$STUB_LOG")" "" "web-w ensure: Apache neither reloaded nor restarted"
: >"$STUB_LOG"
Wf=$(bash "$S/run.sh" fix web-w); code=$?
eq "$code" 1 "web-w fix: apachectl configtest fails -> exit 1"
has "$(grep -E '^apt-get .* install ' "$STUB_LOG")" "libapache2-mod-php8.3=8.3.6-0ubuntu0.24.04.13" "web-w fix: mod_php pinned to the target"
eq "$(ls "$WORK/hosts/web-w/root/etc/php/8.3/apache2/conf.d/99-security.ini" 2>/dev/null)" "" "web-w fix: new ini removed"
has "$(grep '^apachectl ' "$STUB_LOG")" "apachectl configtest" "web-w fix: Apache config tested"
eq "$(grep -E '^systemctl (reload|restart|stop) ' "$STUB_LOG")" "" "web-w fix: Apache not restarted"
has "$Wf" "kind=fix host=web-w branch=8.3 before=8.3.6-0ubuntu0.24.04.12 after=8.3.6-0ubuntu0.24.04.13 target=8.3.6-0ubuntu0.24.04.13 fixed=yes restart=skipped modules=same state=test-failed sapi=apache2" \
  "web-w fix: installed, but Apache left alone on the failed configtest"

# mod_php only, no nginx: the probe finds the sites through apachectl -S.
: >"$STUB_LOG"
Lf=$(bash "$S/run.sh" fix web-l); code=$?
eq "$code" 0 "web-l fix: mod_php fixed, exit 0"
has "$Lf" "kind=fix host=web-l branch=8.3 before=8.3.6-0ubuntu0.24.04.12 after=8.3.6-0ubuntu0.24.04.13 target=8.3.6-0ubuntu0.24.04.13 fixed=yes restart=done modules=same state=fixed sapi=apache2" \
  "web-l fix: installed, Apache restarted"
eq "$(grep -E '^systemctl (restart|reload) ' "$STUB_LOG")" "systemctl restart apache2" "web-l fix: Apache restarted once"
has "$Lf" "kind=probe host=web-l name=shop.example.com before=200 after=200" "web-l fix: Apache vhost probed before and after"
has "$Lf" "kind=probe_summary host=web-l state=unchanged" "web-l fix: Apache-only host is not 'no sites'"

# One branch served by both FPM and mod_php: one pinned install, both SAPIs mitigated, tested, restarted.
: >"$STUB_LOG"
X=$(bash "$S/run.sh" fix web-x); code=$?
eq "$code" 0 "web-x: FPM and mod_php of 8.3 fixed in one run, exit 0"
INSTALL=$(grep -E '^apt-get .* install ' "$STUB_LOG")
eq "$(grep -c . <<<"$INSTALL")" 1 "web-x: one install for the branch"
has "$INSTALL" "php8.3-fpm=8.3.6-0ubuntu0.24.04.13" "web-x: FPM package pinned to the target"
has "$INSTALL" "libapache2-mod-php8.3=8.3.6-0ubuntu0.24.04.13" "web-x: mod_php package pinned to the same target"
has "$X" "kind=fix host=web-x branch=8.3 before=8.3.6-0ubuntu0.24.04.12 after=8.3.6-0ubuntu0.24.04.13 target=8.3.6-0ubuntu0.24.04.13 fixed=yes restart=done modules=same state=fixed sapi=fpm" \
  "web-x: FPM patched and restarted"
has "$X" "kind=fix host=web-x branch=8.3 before=8.3.6-0ubuntu0.24.04.12 after=8.3.6-0ubuntu0.24.04.13 target=8.3.6-0ubuntu0.24.04.13 fixed=yes restart=done modules=same state=fixed sapi=apache2" \
  "web-x: mod_php patched and Apache restarted"
eq "$(grep -E '^systemctl (restart|reload) ' "$STUB_LOG" | sort)" "$(printf 'systemctl restart apache2\nsystemctl restart php8.3-fpm')" \
  "web-x: the pool and Apache restarted once each, no reload"
has "$(grep -E '^(php-fpm8.3 -t|apachectl configtest)' "$STUB_LOG" | sort -u)" "$(printf 'apachectl configtest\nphp-fpm8.3 -t')" "web-x: both config tests ran"
has "$X" "kind=mitigation host=web-x branch=8.3 sapi=apache2 ini=absent action=written upload_progress=Off overrides=0 state=mitigated" \
  "web-x: mod_php mitigated"
has "$X" "kind=mitigation host=web-x branch=8.3 sapi=fpm ini=absent action=written upload_progress=Off overrides=0 state=mitigated" \
  "web-x: FPM mitigated"
has "$X" "rm /etc/php/8.3/apache2/conf.d/99-security.ini && systemctl reload apache2" "web-x: rollback line for the mod_php ini"
has "$X" "kind=probe host=web-x name=api.example.com before=200 after=200" "web-x: nginx site probed"
has "$X" "kind=probe host=web-x name=shop.example.com:8080 before=200 after=200" "web-x: Apache vhost probed over http on its own address and port"
has "$X" "kind=probe host=web-x name=www.shop.example.com:8080 before=301 after=301" "web-x: Apache alias probed"
has "$X" "kind=probe host=web-x name=blog.example.org:8080 before=200 after=200" "web-x: second Apache vhost probed"
eq "$(grep -c 'kind=probe host=web-x name=shop.example.com:8080 ' <<<"$X")" 1 "web-x: a vhost listed as default server and as namevhost probed once"
XR=$(bash "$S/report.sh" "$(ls "$P2S_CACHE"/web-x-fix-*.log)")
has "$XR" '| 8.3 | fpm | `8.3.6-0ubuntu0.24.04.12` | `8.3.6-0ubuntu0.24.04.13` | `8.3.6-0ubuntu0.24.04.13` | yes | done | same | fixed |' "report: FPM patch row"
has "$XR" '| 8.3 | apache2 | `8.3.6-0ubuntu0.24.04.12` | `8.3.6-0ubuntu0.24.04.13` | `8.3.6-0ubuntu0.24.04.13` | yes | done | same | fixed |' "report: mod_php patch row"

PR=$(bash "$S/report.sh" "$(ls "$P2S_CACHE"/web-m-fix-*.log)" "$(ls "$P2S_CACHE"/web-q-fix-*.log)" "$(ls "$P2S_CACHE"/web-t-fix-*.log)")
has "$PR" '| 8.3 | fpm | `8.3.6-0ubuntu0.24.04.12` | `8.3.6-0ubuntu0.24.04.13` | `8.3.6-0ubuntu0.24.04.13` | yes | done | same | fixed |' "report: patch row"
has "$PR" "- Backup before the patch: \`/root/etc-php-" "report: backup named"
has "$PR" "- HTTP probe: every status code unchanged" "report: probe unchanged"
has "$PR" '- **Preflight stopped the patch: held**, held: `php8.3-fpm`' "report: preflight stop"
has "$PR" '- `shop.example.com`: 200 -> 502 - **changed**' "report: changed site"
hasnt "$PR" "No PHP-FPM or PHP-CGI installed." "report: a fix log is not an empty host"

echo "▸ autoupdate"
# A host's whole tree, directories included: the keeper must not even create one where it has nothing to do.
tree() { (cd "$WORK/hosts/$1" && find . -type d | sort && find . -type f -exec md5sum {} + | sort); }
yreset() { rm -rf "$WORK/hosts/web-y"; cp -r "$WORK/web-y.pristine" "$WORK/hosts/web-y"; }
y() { echo "$WORK/hosts/web-y/root$1"; }
PIN83=/etc/apt/preferences.d/php2shell-php8.3.pref
UUC=/etc/apt/apt.conf.d/51php2shell-ppa-origins
SU835=8.3.35-1+ubuntu24.04.1+deb.sury.org+1
U83=8.3.6-0ubuntu0.24.04.13
before_line() { # before_line <text> <pattern a> <pattern b>: a's first line comes before b's
  local a b
  a=$(grep -nF -- "$2" <<<"$1" | head -1 | cut -d: -f1) b=$(grep -nF -- "$3" <<<"$1" | head -1 | cut -d: -f1)
  [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]
}

TB=$(tree web-b)
: >"$STUB_LOG"
AB=$(bash "$S/run.sh" autoupdate web-b); code=$?
eq "$code" 0 "web-b (PPA builds, no PPA source): exit 0"
LOG_AB=$(sed -n 's/^log: //p' <<<"$AB")
has "$AB" "kind=keeper host=web-b state=no-ppa" "web-b: no PPA, nothing to keep"
eq "$(tree web-b)" "$TB" "web-b: no file written, no directory made"
eq "$(grep -cE '^(apt-cache policy|unattended-upgrade) ' "$STUB_LOG")" 0 "web-b: apt not even asked"

yreset
: >"$STUB_LOG"
AY=$(bash "$S/run.sh" autoupdate web-y); code=$?
eq "$code" 0 "web-y: Ubuntu 8.3 pinned, PPA origin added -> exit 0"
LOG_AY=$(sed -n 's/^log: //p' <<<"$AY")
PIN=$(cat "$(y $PIN83)" 2>/dev/null)
has "$PIN" "Package: php8.3 php8.3-* libapache2-mod-php8.3" "web-y: the pin covers every package of the 8.3 branch"
has "$PIN" "Pin: origin ppa.launchpadcontent.net" "web-y: the pin names the PPA's site"
has "$PIN" "Pin-Priority: -1" "web-y: the pin keeps PPA builds off the branch (-1)"
eq "$(ls "$(y /etc/apt/preferences.d)")" "php2shell-php8.3.pref" "web-y: one pin, none for the PPA-built 8.4"
has "$(cat "$(y $UUC)" 2>/dev/null)" 'Unattended-Upgrade::Allowed-Origins { "LP-PPA-ondrej-php:noble"; };' \
  "web-y: unattended-upgrades accepts the PPA origin (Origin and Suite from its Release file)"
has "$AY" "kind=pin host=web-y branch=8.3 file=$PIN83 action=written" "web-y: pin record"
has "$AY" "kind=uu_entry host=web-y value=LP-PPA-ondrej-php:noble file=$UUC action=written" "web-y: origin entry record"
before_line "$AY" "kind=pin host=web-y branch=8.3" "kind=uu_entry host=web-y" && ok "web-y: the pin is written before the origin entry" \
  || bad "web-y: the pin is written before the origin entry" "$AY"
has "$AY" "kind=policy host=web-y branch=8.3 origin=distro package=php8.3-fpm installed=$U83 before=$SU835 candidate=$U83 candidate_origin=distro moved=- pin=$PIN83 state=kept" \
  "web-y: 8.3 candidate is the PPA's 8.3.35 before the pin and Ubuntu's after it"
has "$AY" "kind=policy host=web-y branch=8.4 origin=ppa package=php8.4-fpm installed=8.4.17-1+ubuntu24.04.1+deb.sury.org+1 before=8.4.27-1+ubuntu24.04.1+deb.sury.org+1 candidate=8.4.27-1+ubuntu24.04.1+deb.sury.org+1 candidate_origin=ppa moved=- pin=- state=kept" \
  "web-y: 8.4 candidate stays the PPA's newer build"
has "$(grep '^unattended-upgrade ' "$STUB_LOG")" "unattended-upgrade --dry-run" "web-y: unattended-upgrades dry run"
has "$AY" "kind=uu_dryrun host=web-y result=ok exit=0 origins_allowed=LP-PPA-ondrej-php from_ppa=-" "web-y: the dry run accepts the PPA origin"
has "$AY" "kind=keeper host=web-y state=configured" "web-y: configured"
has "$AY" "rm $PIN83" "web-y: rollback line for the pin"
has "$AY" "rm $UUC" "web-y: rollback line for the origin entry"
YA=$(bash "$S/run.sh" audit web-y)
LOG_YA=$(sed -n 's/^log: //p' <<<"$YA")
has "$YA" "kind=autoupdate host=web-y periodic=1 origins=4 ppa_covered=yes" "web-y: the audit now sees the PPA covered"

TY=$(tree web-y)
: >"$STUB_LOG"
AY2=$(bash "$S/run.sh" autoupdate web-y); code=$?
eq "$code" 0 "web-y second run: exit 0"
LOG_AY2=$(sed -n 's/^log: //p' <<<"$AY2")
eq "$(tree web-y)" "$TY" "web-y second run: nothing written"
has "$AY2" "kind=pin host=web-y branch=8.3 file=$PIN83 action=present" "web-y second run: its own pin recognised"
has "$AY2" "kind=uu_entry host=web-y value=LP-PPA-ondrej-php:noble file=- action=present" "web-y second run: origin entry recognised"
has "$AY2" "kind=keeper host=web-y state=unchanged" "web-y second run: unchanged"
hasnt "$AY2" "rm $PIN83" "web-y second run: no rollback line for files it did not write"

# Someone pinned all PHP up to the PPA, in a file apt reads before the keeper's: the keeper's pin is written
# but cannot hold 8.3, so the candidate would move. The run refuses before the origin entry.
yreset
mkdir -p "$(y /etc/apt/preferences.d)"
printf 'Package: php*\nPin: origin ppa.launchpadcontent.net\nPin-Priority: 900\n' >"$(y /etc/apt/preferences.d/00ondrej-php)"
: >"$STUB_LOG"
AR=$(bash "$S/run.sh" autoupdate web-y); code=$?
eq "$code" 1 "web-y refused: a candidate would change origin -> exit 1"
LOG_AR=$(sed -n 's/^log: //p' <<<"$AR")
has "$AR" "STOP: php8.3: apt would move php8.3-fpm php8.3-common from the distro build to ppa ($SU835)" "web-y refused: names the branch, its packages and the candidate"
has "$AR" "kind=policy host=web-y branch=8.3 origin=distro package=php8.3-fpm installed=$U83 before=$SU835 candidate=$SU835 candidate_origin=ppa moved=php8.3-fpm,php8.3-common pin=$PIN83 state=pin-ineffective" \
  "web-y refused: candidate still the PPA's despite the pin"
has "$AR" "kind=keeper host=web-y state=refused branches=8.3" "web-y refused: keeper record"
[ -f "$(y $PIN83)" ] && ok "web-y refused: the pin is kept" || bad "web-y refused: the pin is kept"
[ -e "$(y $UUC)" ] && bad "web-y refused: the origin entry is not added" || ok "web-y refused: the origin entry is not added"
hasnt "$AR" "kind=uu_entry" "web-y refused: no origin entry record"
eq "$(grep -c '^unattended-upgrade ' "$STUB_LOG")" 0 "web-y refused: no dry run"
has "$AR" "rm $PIN83" "web-y refused: rollback line for the pin it wrote"

# An operator's pin under a name apt skips (".conf"): recognised by content, so no second pin is written, and
# apt-cache policy shows it does nothing.
yreset
mkdir -p "$(y /etc/apt/preferences.d)"
printf 'Package: php8.3*\nPin: origin ppa.launchpadcontent.net\nPin-Priority: -1\n' >"$(y /etc/apt/preferences.d/ondrej-php.conf)"
AI=$(bash "$S/run.sh" autoupdate web-y); code=$?
eq "$code" 1 "web-y ignored pin: exit 1"
LOG_AI=$(sed -n 's/^log: //p' <<<"$AI")
has "$AI" "kind=pin host=web-y branch=8.3 file=/etc/apt/preferences.d/ondrej-php.conf action=present" "web-y ignored pin: recognised by content"
eq "$(ls "$(y /etc/apt/preferences.d)")" "ondrej-php.conf" "web-y ignored pin: no duplicate pin written"
has "$AI" "candidate=$SU835 candidate_origin=ppa moved=php8.3-fpm,php8.3-common pin=/etc/apt/preferences.d/ondrej-php.conf state=pin-ineffective" \
  "web-y ignored pin: detected as ineffective, the candidate still the PPA's"
has "$AI" "mv /etc/apt/preferences.d/ondrej-php.conf /etc/apt/preferences.d/ondrej-php.pref" "web-y ignored pin: says how to make apt read it"
[ -e "$(y $UUC)" ] && bad "web-y ignored pin: no origin entry" || ok "web-y ignored pin: no origin entry"

# The same ignored pin while the PPA's 8.3 build sorts below Ubuntu's: the candidate stays the installed build
# today, but the pin still holds nothing and the next PPA upload would move 8.3. apt-cache policy shows the PPA
# build at its source's priority instead of -1, and that is what the keeper reads.
yreset
mkdir -p "$(y /etc/apt/preferences.d)"
printf 'Package: php8.3*\nPin: origin ppa.launchpadcontent.net\nPin-Priority: -1\n' >"$(y /etc/apt/preferences.d/ondrej-php.conf)"
sed -i "s/$SU835/8.3.5-1+ubuntu24.04.1+deb.sury.org+1/" "$WORK/hosts/web-y/madison/php8.3-fpm.txt" "$WORK/hosts/web-y/madison/php8.3-common.txt"
AJ=$(bash "$S/run.sh" autoupdate web-y); code=$?
eq "$code" 1 "web-y ignored pin, PPA build lower: exit 1"
has "$AJ" "candidate=$U83 candidate_origin=distro moved=- pin=/etc/apt/preferences.d/ondrej-php.conf state=pin-ineffective" \
  "web-y ignored pin, PPA build lower: still detected as ineffective"
has "$AJ" "unheld=php8.3-fpm,php8.3-common" "web-y ignored pin, PPA build lower: names the packages whose PPA builds keep a priority"
has "$AJ" "mv /etc/apt/preferences.d/ondrej-php.conf /etc/apt/preferences.d/ondrej-php.pref" "web-y ignored pin, PPA build lower: says how to make apt read it"
[ -e "$(y $UUC)" ] && bad "web-y ignored pin, PPA build lower: no origin entry" || ok "web-y ignored pin, PPA build lower: no origin entry"
has "$(bash "$S/report.sh" "$(sed -n 's/^log: //p' <<<"$AJ")")" '**pin-ineffective**: PPA builds of php8.3-fpm,php8.3-common not held off' \
  "report: a pin that holds nothing yet, though nothing would move today"

# Equivalent config already in place under other names, in other forms: nothing written.
yreset
mkdir -p "$(y /etc/apt/preferences.d)" "$(y /etc/apt/apt.conf.d)"
printf 'Explanation: Ubuntu PHP stays Ubuntu\nPackage: php8.3*\nPin: release o=LP-PPA-ondrej-php\nPin-Priority: -10\n' \
  >"$(y /etc/apt/preferences.d/ubuntu-php)"
printf '%s\n' 'Unattended-Upgrade::Origins-Pattern {' '  "origin=LP-PPA-ondrej-php,codename=${distro_codename}";' '};' \
  >"$(y /etc/apt/apt.conf.d/60ondrej-php)"
TE=$(tree web-y)
AE=$(bash "$S/run.sh" autoupdate web-y); code=$?
eq "$code" 0 "web-y equivalent config: exit 0"
eq "$(tree web-y)" "$TE" "web-y equivalent config: no file written"
has "$AE" "kind=pin host=web-y branch=8.3 file=/etc/apt/preferences.d/ubuntu-php action=present" "web-y equivalent config: release o= pin recognised"
has "$AE" "kind=uu_entry host=web-y value=LP-PPA-ondrej-php:noble file=- action=present" "web-y equivalent config: Origins-Pattern entry recognised"
has "$AE" "candidate=$U83 candidate_origin=distro moved=- pin=/etc/apt/preferences.d/ubuntu-php state=kept" "web-y equivalent config: and it holds 8.3"
has "$AE" "kind=keeper host=web-y state=unchanged" "web-y equivalent config: unchanged"

# The ondrej/nginx PPA as well: its Release file is cached, but its packages are not PHP. Accepting its origin
# would let unattended-upgrades move nginx to it, so the keeper leaves that source out.
yreset
printf 'deb https://ppa.launchpadcontent.net/ondrej/nginx/ubuntu noble main\n' >"$(y /etc/apt/sources.list.d/ondrej-nginx.list)"
sed 's/LP-PPA-ondrej-php/LP-PPA-ondrej-nginx/; s/PPA for PHP/PPA for nginx/' \
  "$(y /var/lib/apt/lists/ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_noble_InRelease)" \
  >"$(y /var/lib/apt/lists/ppa.launchpadcontent.net_ondrej_nginx_ubuntu_dists_noble_InRelease)"
AG=$(bash "$S/run.sh" autoupdate web-y); code=$?
eq "$code" 0 "web-y with the ondrej/nginx PPA too: exit 0"
eq "$(grep -o 'Allowed-Origins.*' "$(y $UUC)" 2>/dev/null)" 'Allowed-Origins { "LP-PPA-ondrej-php:noble"; };' \
  "web-y with the ondrej/nginx PPA too: only the PHP PPA's origin accepted"
hasnt "$AG" "ondrej/nginx" "web-y with the ondrej/nginx PPA too: the nginx PPA is not a PHP source"

# web-y as a Debian trixie host with packages.sury.org: Debian's own 8.4.11-1 has no ~debNN suffix and sury's
# Debian builds carry +debian13 and no "sury", so the version strings say nothing about origin. The keeper
# reads it from the source apt-cache policy lists under the installed build and the candidate.
SUD84=8.4.13-1+0~20251023.80+debian13~1.gbp1a2b3c SUD83=8.3.27-1+0~20251023.80+debian13~1.gbp1a2b3c
ydeb() {
  yreset
  printf '%s\n' 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"' 'VERSION_ID="13"' 'VERSION_CODENAME=trixie' 'ID=debian' >"$(y /etc/os-release)"
  rm "$(y /etc/apt/sources.list.d/ondrej-ubuntu-php-noble.sources)" "$(y /var/lib/apt/lists)"/*
  printf 'deb https://packages.sury.org/php/ trixie main\n' >"$(y /etc/apt/sources.list.d/php.list)"
  printf '%s\n' 'Origin: deb.sury.org' 'Label: PHP' 'Suite: trixie' 'Codename: trixie' \
    >"$(y /var/lib/apt/lists/packages.sury.org_php_dists_trixie_InRelease)"
  printf 'ii |%s|%s\n' php8.4-fpm 8.4.11-1 php8.4-common 8.4.11-1 php8.3-fpm "$SUD83" php8.3-common "$SUD83" \
    >"$WORK/hosts/web-y/dpkg-query.txt"
  rm "$WORK/hosts/web-y/madison"/*
  for p in php8.4-fpm php8.4-common; do
    printf ' %s | %s | %s\n' "$p" "$SUD84" 'https://packages.sury.org/php trixie/main amd64 Packages' \
      "$p" 8.4.11-1 'http://deb.debian.org/debian trixie/main amd64 Packages' >"$WORK/hosts/web-y/madison/$p.txt"
  done
  for p in php8.3-fpm php8.3-common; do
    printf ' %s | %s | %s\n' "$p" "$SUD83" 'https://packages.sury.org/php trixie/main amd64 Packages' >"$WORK/hosts/web-y/madison/$p.txt"
  done
}
ydeb
AT=$(bash "$S/run.sh" autoupdate web-y); code=$?
eq "$code" 0 "web-y on Debian: exit 0"
has "$AT" "kind=pin host=web-y branch=8.4 file=/etc/apt/preferences.d/php2shell-php8.4.pref action=written" \
  "web-y on Debian: Debian's plain 8.4.11-1 is a distro build, pinned off the PPA"
has "$(cat "$(y /etc/apt/preferences.d/php2shell-php8.4.pref)" 2>/dev/null)" "Pin: origin packages.sury.org" "web-y on Debian: the pin names sury's site"
has "$AT" "kind=policy host=web-y branch=8.4 origin=distro package=php8.4-fpm installed=8.4.11-1 before=$SUD84 candidate=8.4.11-1 candidate_origin=distro moved=- pin=/etc/apt/preferences.d/php2shell-php8.4.pref state=kept before_origin=ppa" \
  "web-y on Debian: sury's 8.4.13 was the candidate before the pin, Debian's after it"
has "$AT" "kind=policy host=web-y branch=8.3 origin=ppa package=php8.3-fpm installed=$SUD83 before=$SUD83 candidate=$SUD83 candidate_origin=ppa moved=- pin=- state=kept" \
  "web-y on Debian: sury's 8.3 build is the PPA's, not pinned"
has "$(cat "$(y $UUC)" 2>/dev/null)" '"deb.sury.org:trixie"' "web-y on Debian: sury's origin accepted"

# The dry run fails: the origin entry it was asked to accept is taken out again, the pin stays.
yreset
: >"$WORK/hosts/web-y/fail-uu"
AD=$(bash "$S/run.sh" autoupdate web-y); code=$?
eq "$code" 1 "web-y dry run fails: exit 1"
[ -e "$(y $UUC)" ] && bad "web-y dry run fails: origin entry removed again" || ok "web-y dry run fails: origin entry removed again"
[ -f "$(y $PIN83)" ] && ok "web-y dry run fails: the pin stays" || bad "web-y dry run fails: the pin stays"
has "$AD" "kind=uu_entry host=web-y value=LP-PPA-ondrej-php:noble file=$UUC action=removed" "web-y dry run fails: removal recorded"
has "$AD" "kind=keeper host=web-y state=dryrun-failed" "web-y dry run fails: keeper record"
hasnt "$AD" "rm $UUC" "web-y dry run fails: no rollback line for the removed entry"
has "$AD" "rm $PIN83" "web-y dry run fails: rollback line for the pin"

# The PPA changed its Release Label since apt cached it: apt-get update refuses the source until someone accepts
# the change, so the keeper stops before writing anything and prints the accept command, as the patcher does.
yreset
mkdir -p "$WORK/hosts/web-y/remote"
sed 's/^Label: .*/Label: PPA for PHP (new)/' "$(y /var/lib/apt/lists/ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_noble_InRelease)" \
  >"$WORK/hosts/web-y/remote/https___ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_noble_InRelease"
apthelper "$WORK/hosts/web-y"
TL=$(tree web-y)
: >"$STUB_LOG"
AL=$(bash "$S/run.sh" autoupdate web-y); code=$?
eq "$code" 1 "web-y with a changed Release Label: exit 1"
has "$AL" "apt-get update --allow-releaseinfo-change-label" "web-y with a changed Release Label: accept command printed"
has "$AL" "remote: Label: PPA for PHP (new)" "web-y with a changed Release Label: the change shown"
has "$AL" "kind=keeper host=web-y state=stopped reason=release-info-changed fields=Label" "web-y with a changed Release Label: keeper record"
eq "$(tree web-y)" "$TL" "web-y with a changed Release Label: nothing written"
eq "$(grep -cE '^apt-get ' "$STUB_LOG")" 0 "web-y with a changed Release Label: the keeper never runs the accept command itself"
eq "$(find "$TMPDIR" -mindepth 1 | head -3)" "" "web-y with a changed Release Label: no InRelease download left behind"

# With the PPA origin accepted, this unattended-upgrades would take php8.3-fpm (Ubuntu-built) from the PPA: the
# dry run lists it among the upgrades only once the PPA is allowed, so the entry is taken out again. Ubuntu's
# own update of php8.3-common is listed before and after and is no reason to stop.
yreset
printf '%s\n' 'Ubuntu php8.3-common' 'LP-PPA-ondrej-php php8.3-fpm' 'LP-PPA-ondrej-php php8.4-fpm' >"$WORK/hosts/web-y/uu-upgrades.txt"
AW=$(bash "$S/run.sh" autoupdate web-y); code=$?
eq "$code" 1 "web-y dry run takes a distro branch from the PPA: exit 1"
has "$AW" "kind=uu_dryrun host=web-y result=distro-from-ppa exit=0 origins_allowed=LP-PPA-ondrej-php from_ppa=php8.3-fpm" \
  "web-y dry run takes a distro branch from the PPA: names the package, not Ubuntu's own update or the PPA branch"
[ -e "$(y $UUC)" ] && bad "web-y dry run takes a distro branch from the PPA: origin entry removed again" \
  || ok "web-y dry run takes a distro branch from the PPA: origin entry removed again"
has "$AW" "kind=uu_entry host=web-y value=LP-PPA-ondrej-php:noble file=$UUC action=removed" "web-y dry run takes a distro branch from the PPA: removal recorded"
has "$AW" "kind=keeper host=web-y state=dryrun-failed" "web-y dry run takes a distro branch from the PPA: keeper record"
has "$(bash "$S/report.sh" "$(sed -n 's/^log: //p' <<<"$AW")")" '**would upgrade php8.3-fpm of a distro-built branch from the PPA**' \
  "report: the dry run's PPA upgrade of a distro branch"
yreset
printf '%s\n' 'Ubuntu php8.3-common' 'LP-PPA-ondrej-php php8.4-fpm' >"$WORK/hosts/web-y/uu-upgrades.txt"
AV=$(bash "$S/run.sh" autoupdate web-y); code=$?
eq "$code" 0 "web-y dry run upgrades Ubuntu's 8.3 from Ubuntu and the PPA's 8.4 from the PPA: exit 0"
has "$AV" "kind=uu_dryrun host=web-y result=ok exit=0 origins_allowed=LP-PPA-ondrej-php from_ppa=-" \
  "web-y dry run with only expected upgrades: ok"

# No cached Release file: the Origin to accept is unknown, so nothing is written.
yreset
rm "$(y /var/lib/apt/lists/ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_noble_InRelease)"
TN=$(tree web-y)
AN=$(bash "$S/run.sh" autoupdate web-y); code=$?
eq "$code" 1 "web-y without a cached Release file: exit 1"
has "$AN" "Run apt-get update on the host" "web-y without a cached Release file: says what to do"
eq "$(tree web-y)" "$TN" "web-y without a cached Release file: nothing written"

# packages.sury.org's Release Origin is deb.sury.org: the audit counts it as the PPA covered, like the ondrej one.
yreset
mkdir -p "$(y /etc/apt/apt.conf.d)"
printf '%s\n' 'Unattended-Upgrade::Allowed-Origins { "deb.sury.org:noble"; };' >"$(y /etc/apt/apt.conf.d/52sury)"
has "$(bash "$S/run.sh" audit web-y)" "kind=autoupdate host=web-y periodic=1 origins=4 ppa_covered=yes" "audit: a deb.sury.org origin covers the PPA"

yreset
TN=$(tree web-y)
AU=$(STUB_UID=1000 bash "$S/run.sh" autoupdate web-y); code=$?
eq "$code" 1 "autoupdate not root: exit 1"
has "$AU" "STOP: autoupdate must run as root" "autoupdate not root: says why"
eq "$(tree web-y)" "$TN" "autoupdate not root: nothing written"

echo "▸ runner"
has "$(bash "$S/run.sh" bundle audit | head -3)" "Fixed-build thresholds" "bundle starts with the version data"
bash "$S/run.sh" bundle nope >/dev/null 2>&1; code=$?
eq "$code" 2 "unknown mode: exit 2"
bash "$S/run.sh" >/dev/null 2>&1; code=$?
eq "$code" 2 "no arguments: exit 2"

echo "▸ fleet"
FL=$WORK/fleet
: >"$STUB_LOG"
O=$(P2S_CACHE=$FL bash "$S/run.sh" audit web-a web-b no-such-host 2>/dev/null); code=$?
eq "$code" 255 "fleet: overall exit is the worst host's (unreachable 255)"
has "$O" "######## summary" "fleet: summary printed"
has "$O" "no-such-host: exit 255" "fleet: unreachable host listed, run went on"
eq "$(ls "$FL" | wc -l)" 3 "fleet: one log per host"
eq "$(grep -l 'kind=host ' "$FL"/*.log | wc -l)" 2 "fleet: two logs with host records"
has "$(cat "$FL"/no-such-host-audit-*.log)" "kind=run_end target=no-such-host mode=audit exit=255 status=unreachable" "fleet: unreachable recorded in its log"
has "$(cat "$FL"/web-a-audit-*.log)" "kind=run_end target=web-a mode=audit exit=0 status=ok" "fleet: run_end closes a good log"
has "$(head -1 "$FL"/web-b-audit-*.log)" "@p2s schema=1 kind=run target=web-b mode=audit started=" "fleet: run record opens the log"
has "$(cat "$STUB_LOG")" "ssh -o BatchMode=yes -o ConnectTimeout=10 web-a bash -s" "fleet: BatchMode and connect timeout"
FIRST_A=$(basename "$(ls "$FL"/web-a-audit-*.log)")
P2S_CACHE=$FL bash "$S/run.sh" audit web-a >/dev/null 2>&1
NEWEST_A=$(basename "$(ls "$FL"/web-a-audit-*.log | sort | tail -1)")
[ "$FIRST_A" != "$NEWEST_A" ] && ok "fleet: second web-a audit has its own log" || bad "fleet: second web-a audit has its own log"
# Hand-written logs from before the plugin share the cache dir; --latest leaves them out.
printf 'some old notes\n' >"$FL/run-old.log"
printf 'ssh output\n' >"$FL/audit-somehost.log"
FR=$(P2S_CACHE=$FL bash "$S/report.sh" --latest 2>&1)
hasnt "$FR" "no host record" "report --latest: hand-written logs in the cache dir ignored"
hasnt "$(P2S_CACHE=$FL bash "$S/next.sh" --latest)" "run-old" "next --latest: hand-written logs ignored"
has "$FR" "Log: \`$NEWEST_A\`" "report --latest: newest web-a log"
hasnt "$FR" "Log: \`$FIRST_A\`" "report --latest: older web-a log ignored"
eq "$(grep -c '^## web-a ' <<<"$FR")" 1 "report --latest: one web-a section"
has "$FR" "## no-such-host (exit 255 (unreachable))" "report --latest: unreachable host has its section"
has "$FR" "Run: audit, started " "report: run line"

Z=$(P2S_CACHE=$FL P2S_HOST_TIMEOUT=1 bash "$S/run.sh" audit web-z 2>/dev/null); code=$?
eq "$code" 124 "timeout: a slow audit is cut off (124)"
has "$Z" "status=timeout" "timeout: recorded"
Z2=$(P2S_CACHE=$FL P2S_HOST_TIMEOUT=1 bash "$S/run.sh" ensure web-z 2>/dev/null); code=$?
eq "$code" 0 "timeout: a write mode is never cut off"
has "$Z2" "kind=run_end target=web-z mode=ensure exit=0 status=ok" "timeout: ensure ran to its end"

D1=$(env -u P2S_CACHE -u XDG_CACHE_HOME HOME="$WORK/home" bash "$S/run.sh" audit web-c 2>&1)
has "$D1" "log: $WORK/home/.cache/php2shell/web-c-audit-" "logs default to ~/.cache/php2shell, outside /tmp"
TMPC=/tmp/p2s-warn-test-$$
W=$(env -u P2S_ALLOW_TMP_CACHE P2S_CACHE="$TMPC" bash "$S/run.sh" audit web-c 2>&1 >/dev/null)
rm -rf "$TMPC"
has "$W" "may not survive a reboot" "cache dir under /tmp: warning"

echo "▸ next step"
NX=$(bash "$S/next.sh" "$T"/fixtures/logs/*.log); code=$?
eq "$code" 0 "next: exit 0"
has "$NX" "needs-fix: fix - unfixed: php8.4" "next: unfixed -> fix"
has "$NX" "needs-restart: fix - restart needed: php8.3" "next: restart needed -> fix"
has "$NX" "needs-ensure: ensure - not mitigated: 8.3/cgi:not-mitigated" "next: fixed but mitigation missing -> ensure"
has "$NX" "all-good: done - " "next: all good -> done"
has "$NX" "down: audit - last audit: unreachable" "next: unreachable -> audit again"
has "$NX" "resumed: done - " "next: newest audit wins over an older one"
has "$NX" "verify: verify - ensure finished after the last audit" "next: write after the audit -> verify"
has "$NX" "blocked: ensure - last ensure: exit-3, not mitigated: 8.3/fpm:override, pool override: /etc/php/8.3/fpm/pool.d/www.conf:6 (the operator removes it)" \
  "next: failed ensure names the blocker"
has "$NX" "stale-ensure: ensure - not mitigated" "next: an ensure older than the audit does not count"
has "$NX" "never-audited: audit - no audit yet" "next: no audit -> audit"
has "$NX" "fix-ok: verify - fix finished after the last audit" "next: successful fix -> verify"
has "$NX" "fix-partial: fix - last fix: exit-3, unfixed: php8.4" "next: fix that left a branch unfixed names it"
has "$NX" "hook-missing: ensure - mitigated, but the apt hook that keeps it in place is missing" "next: missing apt hook -> ensure"
has "$NX" "needs-autoupdate: autoupdate - the ondrej PPA is configured, but unattended-upgrades does not install PHP updates from it" \
  "next: everything fixed, PPA not covered -> autoupdate"
eq "$(wc -l <<<"$NX")" 14 "next: one line per host"
eq "$(bash "$S/next.sh" "$LOG_YA" "$LOG_AY2")" "web-y: verify - autoupdate finished after the last audit; audit again to confirm" \
  "next: autoupdate after the audit -> verify"
eq "$(bash "$S/next.sh" "$LOG_YA" "$LOG_AR")" "web-y: autoupdate - last autoupdate: exit-1, refused: php8.3 would change origin, pin that does not hold: $PIN83" \
  "next: refused autoupdate names the branch and the pin"
eq "$(bash "$S/next.sh" "$LOG_YA" "$LOG_AI")" "web-y: autoupdate - last autoupdate: exit-1, refused: php8.3 would change origin, pin that does not hold: /etc/apt/preferences.d/ondrej-php.conf" \
  "next: an ignored pin is named"
NL=$(bash "$S/next.sh" "$(ls "$P2S_CACHE"/web-l-audit-*.log)")
eq "$NL" "web-l: fix - unfixed: php8.3/apache2" "next: unfixed mod_php named with its SAPI"
NV=$(bash "$S/next.sh" "$P2S_CACHE"/web-v-*.log)
eq "$NV" "web-v: ensure - last ensure: exit-3, not mitigated: 8.3/apache2:override, Apache override: /etc/apache2/sites-enabled/shop.conf:6 (the operator removes it)" \
  "next: an Apache override is named as one, with file and line"
bash "$S/next.sh" >/dev/null 2>&1; code=$?
eq "$code" 2 "next: no arguments -> exit 2"

echo "▸ report"
rm -rf "$WORK/hosts"   # the report must work from saved logs alone
LOGS=$(ls "$P2S_CACHE"/web-[abcd]-audit-*.log)
# shellcheck disable=SC2086
R=$(bash "$S/report.sh" $LOGS); code=$?
eq "$code" 0 "report: exit 0"
has "$R" "## web-a (ubuntu-24.04)" "report: web-a section"
has "$R" '| 8.3 | fpm | `8.3.6-0ubuntu0.24.04.13` | distro | active | unknown | yes | fixed | distro-threshold |' "report: web-a 8.3 row"
has "$R" '| 7.4 | fpm | `1:7.4.33-31+ubuntu24.04.1+deb.sury.org+1` | ppa | active | unknown | yes | fixed | changelog |' "report: web-a 7.4 row"
has "$R" '| 8.4 | fpm | `8.4.17-1+ubuntu24.04.1+deb.sury.org+1` | ppa | active | unknown | no | **unfixed** | below-threshold |' "report: unfixed in bold"
has "$R" "## web-c (debian-12)" "report: web-c section"
has "$R" "No PHP-FPM or PHP-CGI installed." "report: host without a web SAPI"
has "$R" '| 8.3 | fpm | `8.3.6-0ubuntu0.24.04.12` | distro | inactive | not-running | no | **unfixed** | below-threshold | `8.3.6-0ubuntu0.24.04.13` |' \
  "report: target column with the target build"
has "$R" '| below-threshold | none (no-fixed-build-in-cached-lists) |' "report: no target shows its reason"
has "$R" '| distro-threshold | none (installed-fixed) |' "report: fixed branch shows installed-fixed"
hasnt "$R" "kind=candidate" "report: candidate records not dumped"
LR=$(bash "$S/report.sh" "$(ls "$P2S_CACHE"/web-l-audit-*.log)")
has "$LR" '| 8.3 | apache2 | `8.3.6-0ubuntu0.24.04.12` | distro | active | **needed** (started 2026-10-20, installed 2026-10-22) | no | **unfixed** | below-threshold | `8.3.6-0ubuntu0.24.04.13` |' \
  "report: mod_php branch row"
VR=$(bash "$S/report.sh" "$(ls "$P2S_CACHE"/web-v-ensure-*.log)")
has "$VR" '| 8.3 | apache2 | absent | written | Off | 1 | **override** |' "report: mod_php mitigation row"
has "$VR" '- php8.3 Apache: `/etc/apache2/sites-enabled/shop.conf:6` php_admin_flag = on - **re-enables it**' \
  "report: Apache override listed as Apache's, with file and line"
AYR=$(bash "$S/report.sh" "$LOG_AY")
has "$AYR" "## web-y (ubuntu-24.04)" "report: keeper log has its host section"
hasnt "$AYR" "No PHP-FPM or PHP-CGI installed." "report: a keeper log is not an empty host"
has "$AYR" '| 8.3 | distro | php8.3-fpm | `8.3.6-0ubuntu0.24.04.13` | `8.3.35-1+ubuntu24.04.1+deb.sury.org+1` (ppa) | `8.3.6-0ubuntu0.24.04.13` (distro) | `/etc/apt/preferences.d/php2shell-php8.3.pref` | kept |' \
  "report: keeper row for the pinned distro branch"
has "$AYR" '| 8.4 | ppa | php8.4-fpm | `8.4.17-1+ubuntu24.04.1+deb.sury.org+1` | `8.4.27-1+ubuntu24.04.1+deb.sury.org+1` (ppa) | `8.4.27-1+ubuntu24.04.1+deb.sury.org+1` (ppa) | - | kept |' \
  "report: keeper row for the PPA branch"
has "$AYR" '- Pin for php8.3: `/etc/apt/preferences.d/php2shell-php8.3.pref` (written)' "report: pin listed"
has "$AYR" '- unattended-upgrades origin `LP-PPA-ondrej-php:noble`: written to `/etc/apt/apt.conf.d/51php2shell-ppa-origins`' "report: origin entry listed"
has "$AYR" '- unattended-upgrade --dry-run: ok, accepts LP-PPA-ondrej-php' "report: dry run listed"
has "$AYR" '- Auto-update keeper: configured' "report: keeper result"
ARR=$(bash "$S/report.sh" "$LOG_AR")
has "$ARR" '| `/etc/apt/preferences.d/php2shell-php8.3.pref` | **pin-ineffective**: php8.3-fpm,php8.3-common would move |' "report: refused branch in bold with what would move"
has "$ARR" '- Auto-update keeper: **refused** (php8.3): the origin entry was not written' "report: refusal stated"
has "$(bash "$S/report.sh" "$LOG_AB")" '- Auto-update keeper: no ondrej/sury PPA on this host, nothing written' "report: no-PPA host"
printf '@p2s schema=1 kind=host host=old os=ubuntu-24.04\n@p2s schema=1 kind=branch host=old branch=8.3 sapi=fpm installed=8.3.6-0ubuntu0.24.04.13 origin=distro active=active cve_changelog=yes verdict=fixed reason=distro-threshold\n' >"$WORK/old.log"
JR=$(bash "$S/report.sh" "$(ls "$P2S_CACHE"/web-j-audit-*.log)")
has "$JR" '| 8.3 | fpm | `8.3.6-0ubuntu0.24.04.13` | distro | active | **needed** (started 2026-10-20, installed 2026-10-22) |' "report: restart needed with both dates"
has "$JR" '| shop.example.com,www.shop.example.com | `unix:/var/run/php/php8.3-fpm.sock` | 8.3 | www |' "report: site row"
has "$JR" '| 8.3 | legacy | `/run/php/php8.3-legacy.sock` | 0 | **unused: stop candidate** |' "report: unused pool flagged as stop candidate"
has "$JR" 'Held PHP packages (apt will not upgrade them): `php8.3-fpm`' "report: held packages"
has "$JR" '| **changed: Label** - apt-get update refuses this source until the change is accepted |' "report: changed Release Label"
has "$JR" 'ondrej PPA covered: no - **PPA PHP is not updated automatically**' "report: PPA not covered by unattended-upgrades"
has "$JR" '`${distro_id}:${distro_codename}-security`' "report: origins decoded"
MR=$(bash "$S/report.sh" "$(grep -l 'kind=mitigation' "$P2S_CACHE"/web-h-ensure-*.log | head -1)" "$(ls "$P2S_CACHE"/web-g-audit-*.log)")
has "$MR" '| 8.3 | fpm | absent | written | Off | 1 | **override** |' "report: mitigation row with the override state"
has "$MR" '- php8.3 pool `www`: `/etc/php/8.3/fpm/pool.d/www.conf:6` php_admin_flag = on - **re-enables it**' "report: override listed with file and line"
has "$MR" '| 8.3 | cgi | foreign | inspected | On | 0 | **foreign** |' "report: foreign file in the audit"
hasnt "$MR" "No PHP-FPM or PHP-CGI installed." "report: ensure log without branch rows still has its table"
has "$(bash "$S/report.sh" "$WORK/old.log")" '| fixed | distro-threshold | - |' "report: log from before targets shows -"
has "$R" '| none (no-fixed-build-in-cached-lists) | **2026-09-30, older than the fixes** |' "report: stale lists flagged next to the missing target"
has "$R" '| `8.3.6-0ubuntu0.24.04.13` | 2026-10-24 |' "report: fresh lists show their date"
has "$R" '| none (installed-fixed) | unknown |' "report: host without apt lists shows unknown"
eq "$(grep -c '^| Branch | SAPI | Installed |' <<<"$R")" 3 "report: one branch table per host with branches"
hasnt "$R" "== php2shell audit" "report: human section of the log not copied"

bash "$S/report.sh" "$WORK/missing.log" >/dev/null 2>&1; code=$?
eq "$code" 1 "report: unreadable log -> exit 1"
printf 'some text, no records\n' >"$WORK/norecords.log"
E=$(bash "$S/report.sh" "$WORK/norecords.log" 2>&1 >/dev/null); code=$?
eq "$code" 1 "report: log with neither a host nor a run record -> exit 1"
has "$E" "no host record" "report: says why"
LOG_X=$(ls "$P2S_CACHE"/no-such-host-audit-*.log)
X=$(bash "$S/report.sh" "$LOG_X"); code=$?
eq "$code" 0 "report: unreachable host is a section, not an error"
has "$X" "## no-such-host (exit 255 (unreachable))" "report: unreachable section"
has "$X" 'Last output: `ssh: Could not resolve hostname no-such-host: Name or service not known`' "report: ssh's own error shown"
printf '@p2s schema=9 kind=host host=future os=x\n' >"$WORK/future.log"
E=$(bash "$S/report.sh" "$WORK/future.log" 2>&1 >/dev/null)
has "$E" "schema 9" "report: unknown schema skipped with a warning"

echo "▸ fixtures carry no real client data"
FX=$T/fixtures
eq "$(find "$FX/hosts" -mindepth 1 -maxdepth 1 -printf '%f\n' | grep -vE '^web-[a-z]$')" "" "host names are web-<letter>"
eq "$(grep -rhoE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+' "$FX" | grep -vE '@[A-Za-z0-9.-]+\.example$')" "" "e-mail domains are .example"
eq "$(grep -rhoE '(^|[[:space:]@=/])([0-9]{1,3}\.){3}[0-9]{1,3}' "$FX" | grep -vE '(192\.0\.2|198\.51\.100|203\.0\.113)\.|127\.[0-9.]+$|0\.0\.0\.0$')" "" \
  "IPv4 addresses only from documentation ranges or loopback"
eq "$(grep -rhoE 'https?://[^/ ]+' "$FX" | sort -u | grep -vxE 'https?://(archive|security)\.ubuntu\.com|https://(ppa\.launchpadcontent\.net|packages\.sury\.org)')" "" \
  "URLs only of public package archives"

echo
echo "PASS: $pass   FAIL: $fail"
[[ $fail -eq 0 ]]
