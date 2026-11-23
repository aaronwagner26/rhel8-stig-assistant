# Changelog

## 0.6.3-urwid-dev

Released as a development build from the November 20, 2026 validation.

- Preserve the active sort heading and Search caret through resize when the relevant controls are visible. `S` can return focus to sorting from the wide evidence pane.
- Label unfamiliar saved action values while keeping assessment differences visible.
- Keep the Workbench private command channel active when the calling shell exports `TMOUT`. Guest screen and session timeout policies continue to apply.
- Verify the exact script in offline container tests, including a 27-minute terminal hold. Genuine RHEL guest acceptance remains pending.

## 0.6.2-urwid-dev

- Add readiness, editable path browsing, bulk ID paste, and a searchable reviewed plan.
- Add searchable saved reports and outcomes, change-ticket handoff, and an attended read-only recheck and comparison.
- Invalidate changed plans and rechecks when effective site settings drift. Restore the terminal on disconnect and retain access to eligible error reports.

## 0.6.1-urwid-dev

- Open Saved runs and compare compatible JSON reports from Home.
- Add sortable Findings headings, quick triage views, progress, and a review index.

## 0.6.0-urwid-dev

- Introduce the Urwid terminal interface, including focused evidence, diffs, attended decisions, and report and recovery views.
- Reuse the pinned classic 0.5.4 rule engine, CLI, plan signatures, and guarded transactions.

Earlier development history is available from `rhel8-stig-urwid.sh --changelog`. See [validation](docs/validation.md) for the release bytes and test scope.
