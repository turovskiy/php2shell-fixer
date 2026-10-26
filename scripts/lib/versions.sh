# Fixed-build thresholds for CVE-2026-109618 and CVE-2026-109619. Data only: the verdict rules live in p2s.sh.
# A branch with no threshold here is judged by its package changelog.

# Upstream releases, compared with the upstream part of any build (1:8.4.27-1+deb.sury.org+1 -> 8.4.27).
declare -A P2S_UPSTREAM_FIXED=([8.2]=8.2.35 [8.3]=8.3.36 [8.4]=8.4.27 [8.5]=8.5.12)
# Ubuntu security builds keep the upstream version and bump the revision (USN-8948-1).
declare -A P2S_UBUNTU_FIXED=([8.1]=8.1.2-1ubuntu2.28 [8.3]=8.3.6-0ubuntu0.24.04.13)
# Day the fixed builds were published (php.net, 2026-10-21). An apt list last changed before it cannot offer one.
P2S_FIXES_RELEASED=2026-10-21
