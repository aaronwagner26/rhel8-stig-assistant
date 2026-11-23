# Validation for Classic 0.5.10 and Urwid 0.6.10

| Artifact | SHA-256 |
| --- | --- |
| `rhel8-stig.sh` | `26d0f7633b4fc34ee62835ab664f019195849e006bd2ec0115e4215691439846` |
| `rhel8-stig-urwid.sh` | `25f15125e57d3908a54eabc7fd07ccaeaf065b5bbbc03e90ab94d0cee0d62ddc` |

The offline Rocky Linux 8.10 fixtures used the signed RHEL 8.10 DVD crypto-policy packages and exercised these cases in both standalone builds.

- Selecting one SSH finding from the catalog produced one high-risk plan. The preview showed the exact OpenSSH policy module and config diff. On stock DEFAULT, the accompanying OpenSSL finding could remain unresolved without initiating a separate edit.
- Explicit skips, the risk ceiling, and fixed CKL and resume scopes prevented unauthorized expansion. The workbench maintained the original selection when returning from review.
- Declining the sole approval left the original files intact. Approving staged two file changes and recorded the shared findings as pending activation. Native generation in the isolated fixture produced the four approved SSH allowlists, and the rollback test restored the original files.
- The Classic and Urwid workflow fixtures and the existing build smoke tests checked review navigation, explicit approvals, and other attended operations.

The test container did not run production SSH sessions. Verification of live service behavior and client compatibility requires the actual target host.

[Shared SSH policy workflow](operator-guide.md#review-the-shared-ssh-policy) · [SSH fixture](../tests/assessment/ssh-shared-scope.sh)
