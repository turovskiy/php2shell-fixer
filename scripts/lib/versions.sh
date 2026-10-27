# Fixed-build thresholds for CVE-2026-109618 and CVE-2026-109619. Data only: the verdict rules live in p2s.sh.
# A branch with no threshold here is judged by its package changelog.

# Upstream releases, compared with the upstream part of any build (1:8.4.27-1+deb.sury.org+1 -> 8.4.27).
declare -A P2S_UPSTREAM_FIXED=([8.2]=8.2.35 [8.3]=8.3.36 [8.4]=8.4.27 [8.5]=8.5.12)
# Ubuntu security builds keep the upstream version and bump the revision (USN-8948-1). Keyed by branch and
# release (VERSION_ID): one branch is fixed on different bases per release, and 26.10's unfixed 8.5.9-0ubuntu2
# sorts above 26.04's fixed 8.5.4-0ubuntu1.5, so a threshold never crosses releases.
declare -A P2S_UBUNTU_FIXED=([8.1@22.04]=8.1.2-1ubuntu2.28 [8.3@24.04]=8.3.6-0ubuntu0.24.04.13
  [8.5@26.04]=8.5.4-0ubuntu1.5 [8.5@26.10]=8.5.9-0ubuntu2.1)
# Day the fixed builds were published (php.net, 2026-10-21). An apt list last changed before it cannot offer one.
P2S_FIXES_RELEASED=2026-10-21
