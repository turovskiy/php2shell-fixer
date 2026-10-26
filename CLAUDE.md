# php2shell-fixer

## Agent skills

### Issue tracker

Issues and specs live in GitHub Issues of turovskiy/php2shell-fixer, via `gh`. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: needs-triage, needs-info, ready-for-agent, ready-for-human, wontfix. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.

## Development

- Tests: `bash tests/run.sh`. Stubs replace ssh, dpkg-query, systemctl and the apt tools; every host is a fake root under `tests/fixtures/hosts/`.
- Every filesystem path in a script goes through `p2s_path` (root prefix `P2S_ROOT`), so tests can point it at a fake root.
- The repo is public: fixtures use `web-<letter>` hosts, `.example` mail domains and documentation IP ranges only. Real client logs stay outside the repo.
