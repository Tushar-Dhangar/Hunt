# Hunt Findings Report

**Engagement:** Internal assumed-breach assessment, Apex Dynamics (`apexdynamics.internal`)
**Portfolio:** WolfSec Labs
**Assessor platform:** KALI01 (10.10.10.40)
**Scope:** Windows/Active Directory attack chain, WS01 through DC01

This report summarises the findings from the Hunt engagement in a structured
format. The step-by-step attack chain, full commands and raw evidence are in
[the engagement guide](setup/engagement-guide.md). Transparency note: one of
the findings below (F-01) was a misconfiguration deliberately introduced for
this engagement; this is documented openly in
[ADR-002](engineering-decisions/002-planted-misconfiguration.md). The
condition it represents is nonetheless a genuinely exploitable one and is
reported as it would be in a real assessment.

## Executive summary

A single low-privilege foothold on the internal network was escalated to full
domain compromise. Starting with no credentials, an attacker on corpnet
captured a domain user's credential hash from ordinary Windows name-resolution
traffic, cracked it offline, used it to extract and crack the password of an
over-privileged service account, and gained command execution on the domain
controller as a Domain Admin.

The chain succeeded because of three compounding weaknesses: default-enabled
broadcast name resolution (LLMNR/NBT-NS), weak and crackable account
passwords, and a service account that was both Kerberoastable and a member of
Domain Admins. None of these is individually unusual in a real environment;
together they form a direct path from "any network access" to "domain owned."

## Scope

| In scope | Out of scope |
|---|---|
| DC01 (10.10.10.10), WS01 (10.10.10.30) | APP01 (10.10.10.20), deferred to a later iteration |
| Active Directory / Windows attack chain | Linux-specific assessment |
| Credential capture, privilege escalation, lateral movement | External/perimeter testing (no internet-facing perimeter exists) |

## Findings summary

| ID | Finding | Severity | Status |
|---|---|---|---|
| F-01 | Kerberoastable service account with Domain Admin membership | Critical | Open (remediation planned for Forge) |
| F-02 | LLMNR/NBT-NS broadcast name resolution enabled | High | Open (remediation planned for Forge) |
| F-03 | Weak, wordlist-crackable account passwords | High | Open (remediation planned for Forge) |
| F-04 | No detection coverage for Kerberoasting in SIEM default ruleset | Medium | Remediated during engagement |

## Detailed findings

### F-01: Kerberoastable service account with Domain Admin membership

**Severity:** Critical
**Affected asset:** `svc-appsvc` (service account), DC01

**Description.** The service account `svc-appsvc` had a Service Principal Name
registered (making it Kerberoastable by any authenticated domain user), a
weak password, and direct membership in the Domain Admins group. Any
domain user can request a Kerberos service ticket for an account with an SPN;
that ticket is encrypted with a key derived from the account's password and
can be cracked offline. Because this account was a Domain Admin, cracking it
yielded full control of the domain.

**Evidence.** `impacket-GetUserSPNs` returned the account with its Domain
Admins membership shown directly in the tool output, and a crackable
`$krb5tgs$` ticket. The ticket cracked to `Password123`. Authenticating with
that credential returned `Pwn3d!` from NetExec against DC01 and yielded a
`wmiexec` shell running as `apex\svc-appsvc` on DC01. See the engagement
guide for full output.

**Impact.** Complete domain compromise: arbitrary command execution on the
domain controller with the highest privilege level in the domain.

**Remediation.**
- Remove `svc-appsvc` from Domain Admins; grant only the specific privileges
  the service requires.
- Replace the static password with a Group Managed Service Account (gMSA), or
  at minimum a long (25+ character) random password that is rotated.
- Where SPNs are required, ensure the account uses AES encryption rather than
  RC4.

### F-02: LLMNR/NBT-NS broadcast name resolution enabled

**Severity:** High
**Affected assets:** WS01, and all Windows hosts by default

**Description.** LLMNR and NBT-NS are legacy name-resolution protocols enabled
by default on Windows. When a name fails to resolve via DNS, the host
broadcasts the query to the local network, and any machine can answer. An
attacker answering these broadcasts can impersonate the requested host and
capture the authenticating user's NTLMv2 credential hash.

**Evidence.** Responder on KALI01 answered a failed name lookup from WS01 and
captured the NTLMv2 hash for `apex\james.whitmore`, which was then cracked
offline.

**Impact.** Interception of domain credentials from ordinary, organic network
traffic, requiring no user interaction beyond normal activity and no prior
access beyond a position on the network.

**Remediation.**
- Disable LLMNR via Group Policy (Turn off multicast name resolution).
- Disable NBT-NS across the estate (DHCP option or per-adapter configuration).
- Enforce SMB signing to limit the relay variant of this attack.

### F-03: Weak, wordlist-crackable account passwords

**Severity:** High
**Affected assets:** domain user and service accounts

**Description.** Account passwords in the environment were short and present in
common wordlists, allowing captured hashes and Kerberos tickets to be cracked
offline in seconds. Offline cracking is undetectable by the domain, so weak
passwords convert any captured hash directly into a usable credential.

**Evidence.** Both captured credentials (`Password1` for a user account,
`Password123` for the service account) cracked instantly against the standard
`rockyou` wordlist with John the Ripper.

**Impact.** Any credential hash obtained through F-01 or F-02 becomes a working
plaintext credential, removing the main practical barrier in the attack chain.

**Remediation.**
- Enforce a password policy requiring length over complexity (15+ characters).
- Deploy a banned-password list covering common and breached passwords.
- Use managed service accounts to remove human-set service passwords entirely.

### F-04: No detection coverage for Kerberoasting in SIEM default ruleset

**Severity:** Medium
**Affected asset:** MON01 (Wazuh)
**Status:** Remediated during this engagement

**Description.** The Kerberoasting step (a Kerberos service-ticket request,
Windows Event ID 4769) was collected by the SIEM but matched only a generic
"Windows Logon Success" rule. No default rule distinguished the RC4-encrypted
ticket request that characterises a Kerberoasting attempt, so the attack
produced no alert.

By contrast, the louder steps were detected by the default ruleset: the
Domain Admins group change raised a level-12 alert, and the final privileged
logon was flagged as a possible pass-the-hash attack (level 6).

**Evidence.** Dashboard review showed the 4769 events under rule 60106 (level
3). After a custom rule (id 100010, level 10, mapped to MITRE T1558.003) was
written and deployed, re-running the attack produced the expected alert.

**Impact.** Without the custom rule, an attacker could enumerate and attack
service account credentials with no alert generated, leaving the most likely
AD privilege-escalation path unmonitored.

**Remediation.** A custom Wazuh rule keyed on Event ID 4769 with RC4
encryption (`0x17`), excluding computer accounts, was deployed to MON01 and
validated live. Rule definition is in the engagement guide.

## Detection coverage summary

| Attack phase | Detected by default ruleset? |
|---|---|
| LLMNR/NBT-NS poisoning (initial access) | No, network-layer technique, no host-agent visibility |
| Kerberoasting (privilege escalation) | No by default; now covered by custom rule 100010 |
| Domain Admins group change | Yes, level 12 |
| Privileged logon / domain compromise | Yes, level 6 |

The one remaining blind spot (initial access via LLMNR) is a monitoring
category limit rather than a missing rule: host-based agents cannot see this
network-layer technique. Network monitoring (Zeek/Suricata) would be required
to cover it, which is a candidate addition for a future Sentinel iteration.

## Remediation roadmap (Forge)

F-01, F-02 and F-03 are carried forward as the input to Forge, the hardening
project, where each is fixed and the attack chain re-run to confirm the fix
holds. F-04 was closed during this engagement.
