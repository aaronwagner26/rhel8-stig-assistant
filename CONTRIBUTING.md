# Contributing

Start with the [operator guide](docs/operator-guide.md) and use a disposable guest or isolated fixture for changes that exercise Apply, activation, or rollback.

## Source changes

1. Open a topic branch from `main`. Make the change in `src/`, a build tool, or a corresponding test.
2. Build with `python3 tools/build.py` and run `python3 tests/smoke.py` on Linux. Run the relevant isolated workflow tests for any behavior the smoke checks cannot exercise.
3. Use an issue or pull request to describe the expected operator behavior, the rule or code paths affected, and the verification completed. Share synthetic examples or redact identifying host details.
4. Group changes into focused commits and update the changelog for operator-facing changes. See the [release process](docs/releasing.md).

## Rule changes

Document the benchmark and rule revision, expected state, applicability, and how the finding is assessed. Changes to remediation should explain the operational impact, approval requirement, backups, safe stopping points, rollback limits, and verification. Include coverage for the relevant compliant, failing, unsupported, and insufficient-evidence cases. A remediation change needs a preview, guarded Apply, repeat-run, and recovery test where applicable.

The assembler verifies the classic backend digest. Treat a new backend digest as an explicit release change and rerun catalog and transaction verification.

## Useful issue details

Include the script version, target OS, Bash and Urwid versions if relevant, terminal type and size, mode, and a synthetic or redacted reproduction. A finding ID and a run ID help when describing saved work. Keep reports, proposal diffs, machine configuration, credentials, and backups private. Use the [security guidance](SECURITY.md) for potential security defects.
