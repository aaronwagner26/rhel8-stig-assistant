# Changelog

## 0.6.10-urwid-dev and 0.5.10-dev

- Start the shared SSH crypto-policy review from any of V-230251, V-230252, V-272482 or V-272483. Include required catalog companions and disclose the OpenSSL impact of changing stock DEFAULT to FIPS.
- Show the exact staged policy diff and proceed directly to one attended approval when the shared SSH change is the only operation. Respect explicit exclusions and fixed checklist or resume scopes.

## 0.6.9-urwid-dev and 0.5.9-dev

- Open Resolve for the 22 selected findings to see assessment evidence, the blocking prerequisite, the available fix, and what to verify afterward.
- Collect an approved time source for a supported chrony configuration and offer an explicit review of V-288829 when the shared SSH policy change requires it.
- Save optional operator evidence references with the run report while preserving the assessed result.

## 0.6.8-urwid-dev and 0.5.8-dev

- Open Urwid Findings directly when Apply is launched with an explicit selection. Show assessment progress and keep Run settings available from Findings.
- Separate batch implementation from the focused finding. List proposed changes, grouped findings, and findings that need follow-up before starting approvals.
- Put the before/after diff near the Urwid approval decision and show the exact proposed audit-rule additions for V-288831 and other supported audit drop-ins.

## 0.6.7-urwid-dev

- Return from a plan or diff to the existing Findings list. Back preserves the selection, filters, sort order, and focused finding. **F8** still reassesses the available scope, and opening a new preview checks the requested findings.

## 0.6.6-urwid-dev and 0.5.7-dev

- Remove the change-ticket option and report field from both editions. Remove the ticket field and handoff view from Urwid. Saved reports from earlier editions remain readable.

## 0.6.5-urwid-dev and 0.5.6-dev

- Reuse eligible observations automatically when running Classic Status. Show live and reused counts and the original observation date. `--fresh` forces a live Status assessment.
- Recheck changed dependencies, open and pending findings, and checks without proven reusable inputs.
- Fix GNU awk syntax in the UEFI GRUB password and GNOME logout checks, including in the Classic GUI.

## 0.6.4-urwid-dev and 0.5.5-dev

- Add 96 rules from the pinned DISA RHEL 8 V2R9 benchmark. Urwid and Classic share 164 of the 371 IDs.
- Expand assessment and conditional attended remediation for audit, network and SSH, account defaults, and local system configuration. The rule catalog identifies the supported handling and prerequisites for each addition.
- Build separate standalone scripts and SHA-256 sidecars for Urwid and Classic.
- Validate the expanded behavior using isolated Linux fixtures. Live RHEL 8.10 guest acceptance remains pending. [Expansion catalog](docs/expansion-rules.md) · [Validation record](docs/validation-0.6.4.md)

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

Earlier development history is available from `rhel8-stig-urwid.sh --changelog`. See the [0.6.3 validation record](docs/validation.md) for that release's exact bytes and test scope.
