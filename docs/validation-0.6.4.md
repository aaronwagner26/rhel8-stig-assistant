# Validation for Classic 0.5.5 and Urwid 0.6.4

The two development artifacts share the same implementation of 164 DISA RHEL 8 STIG V2R9 rules. The 96 additions all have an assessment, administrator guidance, and an attended remediation path. The STIG revision remains pinned for reproducible results. [Expansion catalog](expansion-rules.md) · [DISA benchmark archive](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_8_V2R9_STIG.zip)

| Artifact | SHA-256 |
| --- | --- |
| `rhel8-stig.sh` | `c173ebec78a64644d8af0b3700a77d7e5573081c5815f9b0b30a9c4883d4cf57` |
| `rhel8-stig-urwid.sh` | `54eb413bc46e493c3eb196c2ad0952c2f25ac0c792f01a1c1d194a0723e196c5` |
| V2R9 source archive | `620bdff4d4a5b07b58817297dd5255a3f8f981a7227405c07b098588fe55cdee` |

## Test environment

The tests ran in an isolated, network-disabled Rocky Linux 8.10 x86_64 container with Bash 4.4. Red Hat signatures were verified for Platform Python 3.6.8, Urwid 1.3.1, and diffutils 3.6 before installing those packages in the fixture. The writable configuration and journal paths lived inside the container. Live RHEL 8.10 guest acceptance is pending.

| Area | What the fixtures cover |
| --- | --- |
| Build and catalog | Reproducible bytes and sidecars, Bash syntax, shared rule and recovery function parity, 164 sorted IDs, metadata for all 96 additions, and their inclusion in the default scope |
| Accounts and DNF | Seventeen handlers, native libpwquality and DNF parsing, compatible grouped changes, PAM and drop-in precedence, stale inputs, and no package removal |
| Audit | Official rule syntax, loaded and staged state, rules that overlap or suppress coverage, managed policy, grouped auditd settings, and integrity requirements for audit tools |
| Kernel, network, and SSH | Precedence, masked and changed sources, IPv6 applicability, preserving stricter settings, verified SSH policy, and grouping the selected keepalive settings |
| Local files and desktop | Pinned console notice, systemd and GNOME value validation, grouped log permissions, and native UID change and rollback on a private log inode |
| Urwid | 45 unit fixtures for history, path browsing, events, and terminal restoration. Pseudoterminal tests covered Status, CKL, focused Apply, a read-only recheck, site settings drift, and both bulk and individual approval. |

The fixtures cover common supported layouts and guarded rejection paths. They use simulated service and kernel observations where an actual activation would require a RHEL host. Host acceptance should verify service state, a separate authorized SSH login after SSH activation, audit event delivery and rotation, actual GNOME or GDM state, and effective values after any reboot.

## Apply behavior

New handlers are medium or high operational risk. Every eligible new change requires individual approval. A preview can show multiple selected findings that share one transaction. Externally managed or ambiguous configurations, unverified service state, and stale plans can require administrator review. Use **Pending activation** to schedule and recheck separately approved changes. The tool does not restart services or reboot as part of these new fixes.

Some legacy and new fixes independently touch the same file, such as V-230233 and the new login policy findings in `login.defs`. If a plan is skipped because an earlier transaction changed its input, rerun only the remaining IDs and review the new diff.

## Reproduce the checks

From the repository root:

```bash
python3 tests/smoke.py \
  --expected-classic-sha256 c173ebec78a64644d8af0b3700a77d7e5573081c5815f9b0b30a9c4883d4cf57 \
  --expected-sha256 54eb413bc46e493c3eb196c2ad0952c2f25ac0c792f01a1c1d194a0723e196c5
PYTHONPATH=src/urwid python3 -B -m unittest discover -s tests/urwid
```

To run the expansion fixtures, build the scripts first and run from a Bash shell in the repository root with the Rocky 8.10 image already present:

```bash
docker run --pull=never --rm --network none --read-only \
  --tmpfs /var/tmp:rw,nosuid,nodev \
  --tmpfs /etc/audit:rw,nosuid,nodev \
  --tmpfs /var/log:rw,nosuid,nodev \
  --mount "type=bind,source=$PWD,target=/src,readonly" \
  rockylinux/rockylinux:8.10 bash -c '
    set -e
    if ! command -v python3 >/dev/null; then
      mkdir /var/tmp/fixture-bin
      ln -s /usr/libexec/platform-python /var/tmp/fixture-bin/python3
      export PATH=/var/tmp/fixture-bin:$PATH
    fi
    for edition in /src/dist/*.sh; do
      for fixture in /src/tests/expansion/*.sh; do
        bash "$fixture" "$edition"
      done
    done
  '
```

The local UID fixture uses Python 3. Each fixture checks that its writable configuration paths are on private temporary filesystems before proceeding.
