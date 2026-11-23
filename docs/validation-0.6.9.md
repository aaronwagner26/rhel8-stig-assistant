# Validation for Classic 0.5.9 and Urwid 0.6.9

The 22-finding resolution workflow shares the existing assessment and remediation engine. Both editions retain the same 164-rule RHEL 8 STIG V2R9 catalog.

| Artifact | SHA-256 |
| --- | --- |
| `rhel8-stig.sh` | `735e6b404818ec2c15218d838137d595a6bf9321f844a7b1c4aeac073321c100` |
| `rhel8-stig-urwid.sh` | `63ed8288d93cd0b257fd04d0df5650cc811f2cc844b305a46bc62beeba6409a9` |

Testing ran offline in Rocky Linux 8.10 with Bash 4.4, Red Hat Platform Python 3.6.8, and Urwid 1.3.1. A real RHEL 8.10 host still needs acceptance testing.

- The build smoke suite verified the exact scripts, CLI reports, Bash syntax, and catalog parity.
- The Classic fixture exercised Resolve, approved time-source input, evidence references, and Back as the scope confirmation default.
- The 64 Urwid tests included resolution navigation, wire format validation, exact dependency scope, rejection of an abandoned preview token, and evidence references in the saved report without changing the assessment.
- The chrony fixture ran against both executables with simulated service and synchronization evidence. It covered strict input parsing, the supported source addition, retention of existing bytes and the maxpoll-only path, and the guards against replacing other sources.
- A separate offline check used the signed chrony 4.5 package from the RHEL 8.10 DVD to verify native configuration parsing and the command output used for source verification.
- Existing terminal workflows verified report creation, Apply and approval decisions, CKL import, site settings drift, and read-only follow-up. The fixtures made changes only in their private test paths.

[Per-finding resolution guide](resolution-guide.md) · [Operator guide](operator-guide.md#attended-changes) · [Urwid fixture instructions](../tests/urwid/README.md)
