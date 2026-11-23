# 96 additional RHEL 8 rules

These IDs extend the original 68 to 164 in the pinned DISA RHEL 8 STIG V2R9 benchmark.
An attended handler applies only when its prerequisites, reviewed scope, and risk ceiling allow it.
Source edits can produce Pending activation or Review. Check those outcomes on the host.

| Vuln-ID | Area | CAT | Handling | Requirement |
| --- | --- | --- | --- | --- |
| V-230227 | Sessions | II | attended-file | RHEL 8 must display the Standard Mandatory DoW Notice and Consent Banner before granting local or remote access to the system via a command line user logon. |
| V-230244 | SSH | II | attended-file | RHEL 8 must be configured so that all network connections associated with SSH traffic terminate after becoming unresponsive. |
| V-230245 | Logging | II | attended-file | The RHEL 8 /var/log/messages file must have mode 0640 or less permissive. |
| V-230246 | Logging | II | attended-action | The RHEL 8 /var/log/messages file must be owned by root. |
| V-230247 | Logging | II | attended-file | The RHEL 8 /var/log/messages file must be group-owned by root. |
| V-230248 | Logging | II | attended-file | The RHEL 8 /var/log directory must have mode 0755 or less permissive. |
| V-230250 | Logging | II | attended-file | The RHEL 8 /var/log directory must be group-owned by root. |
| V-230267 | Kernel | II | attended-file | RHEL 8 must enable kernel parameters to enforce discretionary access control on symlinks. |
| V-230268 | Kernel | II | attended-file | RHEL 8 must enable kernel parameters to enforce discretionary access control on hardlinks. |
| V-230269 | Kernel | III | attended-file | RHEL 8 must restrict access to the kernel message buffer. |
| V-230270 | Kernel | III | attended-file | RHEL 8 must prevent kernel profiling by unprivileged users. |
| V-230280 | Kernel | II | attended-file | RHEL 8 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution. |
| V-230281 | Packages | III | attended-file | YUM must remove all software components after updated versions have been installed on RHEL 8. |
| V-230286 | SSH | II | attended-file | The RHEL 8 SSH public host key files must have mode 0644 or less permissive. |
| V-230288 | SSH | II | attended-file | The RHEL 8 SSH daemon must perform strict mode checking of home directory configuration files. |
| V-230290 | SSH | II | attended-file | The RHEL 8 SSH daemon must not allow authentication using known host’s authentication. |
| V-230321 | Files | II | attended-action | All RHEL 8 local interactive user home directories must have mode 0750 or less permissive. |
| V-230324 | Identity | II | attended-file | All RHEL 8 local interactive user accounts must be assigned a home directory upon creation. |
| V-230325 | Files | II | attended-action | All RHEL 8 local initialization files must have mode 0740 or less permissive. |
| V-230330 | SSH | II | attended-file | RHEL 8 must not allow users to override SSH environment variables. |
| V-230347 | Desktop | II | attended-file | RHEL 8 must enable a user session lock until that user re-establishes access using established identification and authentication procedures for graphical user sessions. |
| V-230357 | Identity | II | attended-file | RHEL 8 must enforce password complexity by requiring that at least one uppercase character be used. |
| V-230358 | Identity | II | attended-file | RHEL 8 must enforce password complexity by requiring that at least one lower-case character be used. |
| V-230359 | Identity | II | attended-file | RHEL 8 must enforce password complexity by requiring that at least one numeric character be used. |
| V-230360 | Identity | II | attended-file | RHEL 8 must require the maximum number of repeating characters of the same character class be limited to four when passwords are changed. |
| V-230361 | Identity | II | attended-file | RHEL 8 must require the maximum number of repeating characters be limited to three when passwords are changed. |
| V-230362 | Identity | II | attended-file | RHEL 8 must require the change of at least four character classes when passwords are changed. |
| V-230363 | Identity | II | attended-file | RHEL 8 must require the change of at least 8 characters when passwords are changed. |
| V-230365 | Identity | II | attended-file | RHEL 8 passwords for new users or password changes must have a 24 hours/1 day minimum password lifetime restriction in /etc/login.defs. |
| V-230366 | Identity | II | attended-file | RHEL 8 user account passwords must have a 180-day maximum password lifetime restriction. |
| V-230369 | Identity | II | attended-file | RHEL 8 passwords must have a minimum of 15 characters. |
| V-230375 | Identity | II | attended-file | All RHEL 8 passwords must contain at least one special character. |
| V-230377 | Identity | II | attended-file | RHEL 8 must prevent the use of dictionary words for passwords. |
| V-230378 | Identity | II | attended-file | RHEL 8 must enforce a delay of at least four seconds between logon prompts following a failed logon attempt. |
| V-230382 | SSH | II | attended-file | RHEL 8 must display the date and time of the last successful account logon upon an SSH logon. |
| V-230383 | Identity | II | attended-file | RHEL 8 must define default permissions for all authenticated users in such a way that the user can only read and modify their own files. |
| V-230393 | Audit | II | attended-file | The RHEL 8 audit system must audit local events. |
| V-230395 | Audit | III | attended-file | RHEL 8 must resolve audit information before writing to disk. |
| V-230397 | Audit | II | attended-action | RHEL 8 audit logs must be owned by root to prevent unauthorized read access. |
| V-230399 | Audit | II | attended-action | RHEL 8 audit log directory must be owned by root to prevent unauthorized read access. |
| V-230404 | Audit | II | attended-file | RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow. |
| V-230405 | Audit | II | attended-file | RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/security/opasswd. |
| V-230406 | Audit | II | attended-file | RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd. |
| V-230407 | Audit | II | attended-file | RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow. |
| V-230408 | Audit | II | attended-file | RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group. |
| V-230409 | Audit | II | attended-file | RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/sudoers. |
| V-230410 | Audit | II | attended-file | RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/sudoers.d/. |
| V-230412 | Audit | II | attended-file | Successful/unsuccessful uses of the su command in RHEL 8 must generate an audit record. |
| V-230418 | Audit | II | attended-file | Successful/unsuccessful uses of the chage command in RHEL 8 must generate an audit record. |
| V-230419 | Audit | II | attended-file | Successful/unsuccessful uses of the chcon command in RHEL 8 must generate an audit record. |
| V-230421 | Audit | II | attended-file | Successful/unsuccessful uses of the ssh-agent in RHEL 8 must generate an audit record. |
| V-230422 | Audit | II | attended-file | Successful/unsuccessful uses of the passwd command in RHEL 8 must generate an audit record. |
| V-230423 | Audit | II | attended-file | Successful/unsuccessful uses of the mount command in RHEL 8 must generate an audit record. |
| V-230424 | Audit | II | attended-file | Successful/unsuccessful uses of the umount command in RHEL 8 must generate an audit record. |
| V-230426 | Audit | II | attended-file | Successful/unsuccessful uses of the unix_update in RHEL 8 must generate an audit record. |
| V-230427 | Audit | II | attended-file | Successful/unsuccessful uses of postdrop in RHEL 8 must generate an audit record. |
| V-230428 | Audit | II | attended-file | Successful/unsuccessful uses of postqueue in RHEL 8 must generate an audit record. |
| V-230429 | Audit | II | attended-file | Successful/unsuccessful uses of semanage in RHEL 8 must generate an audit record. |
| V-230430 | Audit | II | attended-file | Successful/unsuccessful uses of setfiles in RHEL 8 must generate an audit record. |
| V-230431 | Audit | II | attended-file | Successful/unsuccessful uses of userhelper in RHEL 8 must generate an audit record. |
| V-230432 | Audit | II | attended-file | Successful/unsuccessful uses of setsebool in RHEL 8 must generate an audit record. |
| V-230433 | Audit | II | attended-file | Successful/unsuccessful uses of unix_chkpwd in RHEL 8 must generate an audit record. |
| V-230434 | Audit | II | attended-file | Successful/unsuccessful uses of the ssh-keysign in RHEL 8 must generate an audit record. |
| V-230435 | Audit | II | attended-file | Successful/unsuccessful uses of the setfacl command in RHEL 8 must generate an audit record. |
| V-230436 | Audit | II | attended-file | Successful/unsuccessful uses of the pam_timestamp_check command in RHEL 8 must generate an audit record. |
| V-230437 | Audit | II | attended-file | Successful/unsuccessful uses of the newgrp command in RHEL 8 must generate an audit record. |
| V-230444 | Audit | II | attended-file | Successful/unsuccessful uses of the gpasswd command in RHEL 8 must generate an audit record. |
| V-230447 | Audit | II | attended-file | Successful/unsuccessful uses of the crontab command in RHEL 8 must generate an audit record. |
| V-230448 | Audit | II | attended-file | Successful/unsuccessful uses of the chsh command in RHEL 8 must generate an audit record. |
| V-230462 | Audit | II | attended-file | Successful/unsuccessful uses of the sudo command in RHEL 8 must generate an audit record. |
| V-230463 | Audit | II | attended-file | Successful/unsuccessful uses of the usermod command in RHEL 8 must generate an audit record. |
| V-230464 | Audit | II | attended-file | Successful/unsuccessful uses of the chacl command in RHEL 8 must generate an audit record. |
| V-230465 | Audit | II | attended-file | Successful/unsuccessful uses of the kmod command in RHEL 8 must generate an audit record. |
| V-230467 | Audit | II | attended-file | Successful/unsuccessful modifications to the lastlog file in RHEL 8 must generate an audit record. |
| V-230472 | Audit | II | attended-file | RHEL 8 audit tools must have a mode of 0755 or less permissive. |
| V-230474 | Audit | II | attended-file | RHEL 8 audit tools must be group-owned by root. |
| V-230531 | Sessions | I | attended-file | The systemd Ctrl-Alt-Delete burst key sequence in RHEL 8 must be disabled. |
| V-230535 | Network | II | attended-file | RHEL 8 must prevent IPv6 Internet Control Message Protocol (ICMP) redirect messages from being accepted. |
| V-230536 | Network | II | attended-file | RHEL 8 must not allow IPv4 ICMP redirect messages. |
| V-230537 | Network | II | attended-file | RHEL 8 must not respond to Internet Control Message Protocol (ICMP) echoes sent to a broadcast address. |
| V-230538 | Network | II | attended-file | RHEL 8 must not forward IPv6 source-routed packets. |
| V-230539 | Network | II | attended-file | RHEL 8 must not forward IPv6 source-routed packets by default. |
| V-230543 | Network | II | attended-file | RHEL 8 must not allow interfaces to perform Internet Control Message Protocol (ICMP) redirects by default. |
| V-230544 | Network | II | attended-file | RHEL 8 must ignore IPv6 Internet Control Message Protocol (ICMP) redirect messages. |
| V-230547 | Kernel | II | attended-file | RHEL 8 must restrict exposed kernel pointer addresses access. |
| V-230556 | SSH | II | attended-file | The RHEL 8 SSH daemon must prevent remote hosts from connecting to the proxy display. |
| V-244519 | Desktop | II | attended-file | RHEL 8 must display a banner before granting local or remote access to the system via a graphical user logon. |
| V-244525 | SSH | II | attended-file | RHEL 8 must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive. |
| V-244535 | Desktop | II | attended-file | RHEL 8 must initiate a session lock for graphical user interfaces when the screensaver is activated. |
| V-244550 | Network | II | attended-file | RHEL 8 must prevent IPv4 Internet Control Message Protocol (ICMP) redirect messages from being accepted. |
| V-244551 | Network | II | attended-file | RHEL 8 must not forward IPv4 source-routed packets. |
| V-244552 | Network | II | attended-file | RHEL 8 must not forward IPv4 source-routed packets by default. |
| V-244553 | Network | II | attended-file | RHEL 8 must ignore IPv4 Internet Control Message Protocol (ICMP) redirect messages. |
| V-251716 | Identity | II | attended-file | RHEL 8 systems, version 8.4 and above, must ensure the password complexity module is configured for three retries or less. |
| V-284948 | Network | II | attended-file | RHEL 8 must log IPv4 packets with impossible addresses. |
| V-284949 | Network | II | attended-file | RHEL 8 must log IPv4 packets with impossible addresses by default. |
