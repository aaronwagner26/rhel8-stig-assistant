# Resolution guide for the 22 selected findings

Start with the current assessment and the blocking prerequisite shown in the review. These findings can share a workflow while requiring different things from the operator. **Guarded remediation** means the script can prepare a host change when it can verify the target and its prerequisites. **Evidence review** means that the administrator must establish part of the requirement from site records or operational evidence. A staged change may still need activation and a fresh check.

Use `--guided` to select this entire set. The preview combines eligible selected module, authselect and audit edits into separate subsystem approvals and keeps the shared SSH operation. **Follow-up** shows the remaining activation and verification work by subsystem. [Operator workflow](operator-guide.md#review-eligible-changes-together)

In Urwid, open **Resolve** for a reviewed finding to see its observed evidence, any blocking prerequisite, and what is needed next. For a supported chrony configuration without a time source, enter the approved source and review the updated plan. Select any of the four SSH findings to open their shared preview. An optional evidence note records what the administrator reviewed. The live check still determines the assessment outcome.

## Guarded remediation

| Vuln-ID | What the script can change | What needs to be resolved or decided |
| --- | --- | --- |
| V-230251 | Stage the SSH server MAC restrictions through the shared SSH crypto operation. | Review the automatically included companions and, on stock `DEFAULT`, the OpenSSL impact. Verify recovery access and a fresh server connection after activation. |
| V-230252 | Stage the SSH server cipher restrictions through the same operation. | Review the effective server settings. After separate activation, test clients that depend on the server. |
| V-230264 | Enable `gpgcheck=1` for eligible enabled static DNF repository definitions. | Confirm the approved fingerprints already present in the local RPM trust store and any approved alternate verification. Correct managed repositories at their authoritative source. Verify the resulting effective DNF settings. |
| V-230279 | Stage `init_on_free=1` for a verified GRUB/BLS layout. | Resolve conflicting or ambiguous boot configuration. Review workload impact and console recovery, activate the boot entries as shown in the plan, then reboot and check the running kernel arguments. |
| V-230287 | Tighten standard SSH private host-key modes to `0600` or stricter. | Identify the packaged sshd configuration and trusted regular keys. Review custom or linked paths and group-access dependencies. Validate the configuration and verify a fresh connection after approved activation. |
| V-230301 | Stage `nodev` in verified `fstab` entries for mounted non-root local device partitions. | Confirm the active mount matches its `fstab` source and generated unit. Review affected applications, activate with an approved targeted remount or reboot, and check active options. |
| V-230484 | Stage a bounded chrony `maxpoll` correction, or add an approved source to a supported configuration with no configured sources. | Supply the site-approved host using `CHRONY_APPROVED_SERVER` for the empty-source case. Confirm the required authentication and policy. Review noncanonical layouts or source replacement separately. Verify approved source selection, synchronization and polling after activation. |
| V-230494 | Stage install denial and blacklisting for ATM (`atm`). | Verify the module is unused, loadable, and locally managed, and check ATM dependencies. Resolve competing directives at their source, review the next-boot image and verify the denial after reboot. |
| V-230495 | Stage install denial and blacklisting for CAN (`can`). | Resolve the same module-policy prerequisites, including physical or virtual CAN dependencies. Verify the denial after the approved reboot. |
| V-230496 | Stage install denial and blacklisting for SCTP (`sctp`). | Review SCTP dependencies such as cluster or application transport before approval. Resolve local policy conflicts and verify the denial after reboot. |
| V-230497 | Stage install denial and blacklisting for TIPC (`tipc`). | Review cluster and service dependencies. Resolve a loaded or built-in module, competing directives, or authoritative site policy before staging. Verify the denial after reboot. |
| V-230498 | Stage install denial and blacklisting for cramfs (`cramfs`). | Review installed images and recovery media that depend on cramfs. Resolve module-policy conflicts and verify the denial after reboot. |
| V-230499 | Stage install denial and blacklisting for FireWire (`firewire-core`). | Confirm FireWire storage, controller and recovery dependencies. Resolve the effective modprobe policy before staging, and verify after an approved reboot. |
| V-230530 | Stage an empty GNOME Ctrl+Alt+Delete logout binding. | Verify supported x86 GNOME and an unambiguous trusted dconf profile. Review queued dconf changes, publish them, then verify the effective binding in a fresh session. |
| V-244541 | Remove `nullok` from supported literal and stock conditional forms in the active custom `password-auth` template. | Use the editable copied authselect template with generated state in sync. Review other queued changes and keep independent administrator access before regeneration. Verify a fresh relevant login. |
| V-257258 | Stage `StopIdleSessionSec=600` for the supported logind layout. | Verify the applicable cloud exception, corrected systemd version, authoritative unit and absence of conflicting overrides. Approve activation and test that a fresh applicable session terminates after 600 seconds idle. |
| V-268322 | Remove `nullok` from supported literal and stock conditional forms in the active custom `system-auth` template. | Use the editable copied authselect template with generated state in sync. Review the generated local authentication stack and verify fresh login after approved regeneration. |
| V-272482 | Stage the SSH client MAC restrictions through the shared SSH crypto operation. | Review client and non-SSH impact where the base policy changes. Verify the effective client settings and a new session after activation. |
| V-272483 | Stage the SSH client cipher restrictions through the same operation. | Verify the trusted stock client backend. Resolve custom overrides and test a fresh client connection after activation. |
| V-274877 | Stage the missing configuration audit watches for `/etc/cron.d` and `/var/spool/cron`. | Verify the standard directories, audit loader and enabled kernel auditing. Reconcile overlapping rules and review the broader privileged cron execution requirement. Observe the loaded rules and expected events after activation. |
| V-288831 | Stage the execution audit rule for `/usr/sbin/useradd`. | Verify the executable, audit loader and policy order. Review effective audit suppression and whether the account filters cover the required operators. Observe the loaded rule and events after approved loading or reboot for immutable audit. |

The audit plan can show **Pending activation** after it writes a file. GRUB, module, authselect, logind, dconf, SSH, mount and chrony changes can also require separate activation. Use the plan's activation and verification instructions. [Shared rule coverage](rule-coverage.md) · [Operator guide](operator-guide.md#attended-changes)

## Evidence that requires administrator review

| Vuln-ID | What can be automated | What establishes compliance |
| --- | --- | --- |
| V-251710 | Inspect the installed package, configuration and database. Resolve can run a bounded, read-only AIDE check against the existing verified default baseline and save a result summary. | The administrator identifies the approved tool, establishes that its database is trusted, confirms coverage of the required security functions, and reviews check results. For a custom or alternate tool, record a reference to its approved result. |

Evidence decisions and host edits can coexist in a single finding. An approved time source lets the chrony planner work within its supported configuration. Confirming actual synchronization needs a live observation.
