# Operator guide

## Target and dependencies

The host target is RHEL 8.10 x86_64 with systemd. Use a disposable guest for initial acceptance. `--version`, `--list`, and `--explain V-ID` are catalog and build information. `--ui-check` reports platform and optional runtime readiness.

| Capability | Requirements |
| --- | --- |
| CLI assessment and preview | Bash 4.4 or later and the host tools checked by `--ui-check` |
| Urwid terminal interface | A controlling terminal, Python 3, and Urwid. Use a display at least 56 columns by 18 rows. |
| Legacy DISA CKL import | Python 3 with the standard-library Expat parser |
| File-content diffs | `diffutils` |
| Apply and rollback | Root, an interactive terminal, an eligible operation, and attended approval |

Obtain dependencies through approved RHEL repositories or verified installation media. The tested Urwid runtime used the RHEL 8 BaseOS `python3-urwid` package. The ordinary CLI modes can run without Urwid. [Red Hat BaseOS package manifest](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/package_manifest/baseos-repository)

## Read-only walkthrough

From the directory containing the verified script, launch Status with JSON reporting and a limited explicit scope.

```bash
./rhel8-stig-urwid.sh --gui --status --format json \
  --only V-230498,V-230279 --change-ticket LAB-READ-ONLY
```

1. At **Run settings**, choose **Check** or press `F8` for readiness. **Browse** fills a CKL, saved selection, or site-file path into an editable field. `/` filters filenames and `Ctrl+L` enters a location.
2. Choose **Findings** to assess. Press `/` to search, `S` to focus the sort headers, `F10` for quick views, and `Space` to toggle the focused row. You can also click column headers.
3. Open **Actions → Paste Vuln-IDs**, enter `V-230498, 230279, V-230498, V-999999`, and use `F2` for the preview. The final ID is an intentional unknown. The preview shows duplicate IDs and any matches outside the filter. **Add** and **Replace** are distinct decisions. **Undo last selection change** restores the earlier selection.
4. Use `F5` for the full selected plan or `F6` for the focused finding. In the full plan, use **Finding index** to jump to evidence and before/after information. The summary includes selected IDs hidden by the current filter.
5. Choose **Save report**, review the exact scope, and explicitly select **Save report** in the confirmation. **Back** is the default. A read-only run shows **Applied IDs (0)**.
6. Open **Findings** in Results for per-ID evidence or **Reports → Change handoff summary** for a compact ticket update. In an artifact preview, use `/` to search and `n` or `N` for the next or previous match.
7. Choose **Follow-up → Run recheck** and then explicitly choose **Run Status**. This creates a separate Status report for the saved scope. With JSON for both runs, **Compare recheck** shows assessment and action differences. Press `F9` from Run settings or Findings to reopen Saved runs on a later launch.

## Scope, formats, and site inputs

- Repeat `--only` or combine it with `--ids-file` for a union of explicit IDs. The file format is one ID per line with optional whole-line `#` comments and blank lines. `--skip` takes precedence. See the [sample scope](../examples/scope.txt).
- With no explicit selector, the CLI assesses the registered 68-ID scope. With no explicit selection source, the Urwid workspace starts with its findings unchecked.
- `--ckl FILE` imports Open findings from legacy DISA CKL XML. It narrows any explicit selection, applies exact benchmark and rule revision checks, and requires acknowledgment for missing or mismatched asset metadata. The import starts a fresh assessment. CKLB is a separate format.
- `--config FILE` accepts supported site values. Record only settings authorized for that host. See the [sample site file](../examples/site.conf).
- `--format text|json|csv` selects the report format. Use JSON for saved-run comparison. Text output for Status, Dry run, and Diff sorts by Vuln-ID by default. Add `--group-by result` to group the report by outcome.
- `--color auto` follows terminal capability and `NO_COLOR`. Use `--no-color` for an explicit monochrome view. The Workbench private channel stays connected with an inherited `TMOUT`. Guest desktop lock and terminal session policies are managed by the guest.

## Attended changes

Use `--diff` or `--dry-run` to inspect eligible changes before a maintenance window. The Apply entry point is explicit, such as `--gui --apply` or `--apply --only V-ID`. The operational risk ceiling defaults to High and can be lowered with `--max-risk` or from Run settings.

Apply and rollback require the verified script at a trusted path. The script and its parent directories must be root-owned, with group and other write access disabled. The preflight rejects symlinks in that path. Keep the corresponding script build with the run records you may need to reopen.

The tool shows the complete selected plan first. Confirming the reviewed scope advances to attended decisions. Scope confirmation defaults to **Back** and per-change approval defaults to **Skip**. When offered, `A` approves the current and remaining eligible unchanged low-risk operations. Sensitive or revised changes require individual approval. Use `--review-each` to ask about every operation. End-of-input stops writes. When reviewed scope or effective site inputs change, prepare and review a fresh plan.

The assessment result, handling, operational risk, and action outcome answer different questions. **Review** means the available evidence is insufficient to resolve the assessment. **Blocked** indicates an unavailable prerequisite or an ineligible operation. Some findings require administrator evidence or manual work. Use the outcome and evidence to plan activation, verification, or handoff.

## Reports, rechecks, and recovery

- Reports default to `/var/tmp/rhel8-stig-UID`, where UID is the effective user ID. Backups default to `/var/lib/rhel8-stig/backups`. Use an authorized location and keep reports and backup contents private.
- An in-app recheck starts a read-only Status run. It uses the eligible saved manifest, original scope, same executable build, and matching effective site settings. Required CKL source and asset checks still apply.
- Saved-run comparison reads protected JSON reports with verified manifests for the same host fingerprint and benchmark. The interface shows differing scope and action-only changes explicitly.
- `--resume RUN-ID` requires the executable build associated with the run. Use the Recovery and report views to inspect errors and backup references. `--rollback RUN-ID` is a separate preview and attended restoration workflow. Review what changed since the original operation first.

| Exit code | Meaning |
| --- | --- |
| 0 | Clean assessment or informational command |
| 2 | Unresolved findings |
| 64 | Usage error |
| 69 | Operation blocked |
| 70 | Operational error |
