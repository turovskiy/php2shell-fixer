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

# Stubs, first on PATH. ssh runs the streamed program locally against the named host's fake root.
REAL_DPKG=$(command -v dpkg)
mkdir -p "$WORK/bin"
export STUB_LOG=$WORK/calls.log P2S_TEST_HOSTS=$WORK/hosts P2S_CACHE=$WORK/cache
stub() { # stub <name> <body>: a logging stub
  printf '#!/usr/bin/env bash\necho "%s $*" >>"$STUB_LOG"\n%s\n' "$1" "$2" >"$WORK/bin/$1"
  chmod +x "$WORK/bin/$1"
}
stub ssh 'd=$P2S_TEST_HOSTS/$1
[ -d "$d" ] || { echo "ssh: Could not resolve hostname $1: Name or service not known" >&2; exit 255; }
P2S_ROOT=$d/root P2S_STUB=$d STUB_HOST=$1 exec bash -s'
stub hostname 'echo "$STUB_HOST"'
stub dpkg-query 'cat "$P2S_STUB/dpkg-query.txt"'
stub systemctl 'if [ "$1" = is-active ]; then
  grep -qxF "${2%.service}" "$P2S_STUB/active.txt" && { echo active; exit 0; }
  echo inactive; exit 3
fi'
stub dpkg "exec $REAL_DPKG \"\$@\""
for t in apt apt-get apt-mark; do stub "$t" 'exit 0'; done
export PATH="$WORK/bin:$PATH"

# Calls an audit may make; anything else in the stub log is a write or a package operation.
READ_ONLY='^(ssh [^ ]+ bash -s|hostname ?|dpkg-query .*|systemctl is-active [^ ]+|dpkg --compare-versions .*)$'
fingerprint() { (cd "$WORK/hosts" && find . -type f -exec md5sum {} + | sort); }

echo "▸ verdict (installed build)"
# shellcheck source=../scripts/lib/versions.sh
. "$S/lib/versions.sh"
# shellcheck source=../scripts/lib/p2s.sh
. "$S/lib/p2s.sh"
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
p2s_changelog_has_cves "  - debian/patches/CVE-2026-109618_109619.patch" && ok "Ubuntu patch name counts as both CVEs" \
  || bad "Ubuntu patch name counts as both CVEs"
p2s_changelog_has_cves "  - CVE-2026-109618 only" && bad "one CVE alone is not a fix" || ok "one CVE alone is not a fix"

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

bash "$S/run.sh" audit no-such-host >/dev/null 2>&1; code=$?
eq "$code" 255 "unreachable host: ssh exit code passed through"

echo "▸ audit: read-only"
WRITES=$(grep -vE "$READ_ONLY" "$STUB_LOG")
eq "$WRITES" "" "no write command or package operation in the stub log"
eq "$(printf 'apt-get install -y php8.3-fpm\nsystemctl restart php8.3-fpm\ndpkg -i x.deb\n' | grep -cvE "$READ_ONLY")" 3 \
  "the read-only filter flags installs, restarts and dpkg -i"
eq "$(fingerprint)" "$BEFORE" "fake roots unchanged"

echo "▸ runner"
has "$(bash "$S/run.sh" bundle audit | head -3)" "Fixed-build thresholds" "bundle starts with the version data"
bash "$S/run.sh" bundle nope >/dev/null 2>&1; code=$?
eq "$code" 2 "unknown mode: exit 2"
bash "$S/run.sh" >/dev/null 2>&1; code=$?
eq "$code" 2 "no arguments: exit 2"

echo "▸ report"
rm -rf "$WORK/hosts"   # the report must work from saved logs alone
LOGS=$(ls "$P2S_CACHE"/web-[abc]-audit-*.log)
# shellcheck disable=SC2086
R=$(bash "$S/report.sh" $LOGS); code=$?
eq "$code" 0 "report: exit 0"
has "$R" "## web-a (ubuntu-24.04)" "report: web-a section"
has "$R" '| 8.3 | fpm | `8.3.6-0ubuntu0.24.04.13` | distro | active | yes | fixed | distro-threshold |' "report: web-a 8.3 row"
has "$R" '| 7.4 | fpm | `1:7.4.33-31+ubuntu24.04.1+deb.sury.org+1` | ppa | active | yes | fixed | changelog |' "report: web-a 7.4 row"
has "$R" '| 8.4 | fpm | `8.4.17-1+ubuntu24.04.1+deb.sury.org+1` | ppa | active | no | **unfixed** | below-threshold |' "report: unfixed in bold"
has "$R" "## web-c (debian-12)" "report: web-c section"
has "$R" "No PHP-FPM branch installed." "report: host without PHP-FPM"
eq "$(grep -c '^| Branch |' <<<"$R")" 2 "report: one table per host with branches"
hasnt "$R" "== php2shell audit" "report: human section of the log not copied"

bash "$S/report.sh" "$WORK/missing.log" >/dev/null 2>&1; code=$?
eq "$code" 1 "report: unreadable log -> exit 1"
LOG_X=$(ls "$P2S_CACHE"/no-such-host-audit-*.log)
E=$(bash "$S/report.sh" "$LOG_X" 2>&1 >/dev/null); code=$?
eq "$code" 1 "report: log without a host record -> exit 1"
has "$E" "no host record" "report: says why"
printf '@p2s schema=9 kind=host host=future os=x\n' >"$WORK/future.log"
E=$(bash "$S/report.sh" "$WORK/future.log" 2>&1 >/dev/null)
has "$E" "schema 9" "report: unknown schema skipped with a warning"

echo "▸ fixtures carry no real client data"
FX=$T/fixtures
eq "$(find "$FX/hosts" -mindepth 1 -maxdepth 1 -printf '%f\n' | grep -vE '^web-[a-z]$')" "" "host names are web-<letter>"
eq "$(grep -rhoE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+' "$FX" | grep -vE '@[A-Za-z0-9.-]+\.example$')" "" "e-mail domains are .example"
eq "$(grep -rhoE '(^|[[:space:]@=/])([0-9]{1,3}\.){3}[0-9]{1,3}' "$FX" | grep -vE '(192\.0\.2|198\.51\.100|203\.0\.113)\.')" "" \
  "IPv4 addresses only from documentation ranges"
eq "$(grep -rlE 'https?://' "$FX")" "" "no URLs"

echo
echo "PASS: $pass   FAIL: $fail"
[[ $fail -eq 0 ]]
