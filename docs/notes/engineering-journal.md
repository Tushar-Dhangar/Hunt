# Engineering Journal

## Engagement methodology locked

Hunt's methodology is locked: an internal, assumed-breach engagement against
WS01 through DC01, starting with LLMNR/NBT-NS poisoning from KALI01 and
escalating through a deliberately planted Kerberoastable service account,
`svc-appsvc`, made a member of Domain Admins. Both decisions and their
reasoning are recorded in the engineering decisions.

## Full attack chain executed, domain compromised

The engagement ran end to end in one pass. Responder captured
`james.whitmore`'s NTLMv2 hash from WS01 after a broadcast lookup failed to
resolve via DNS, the same fallback that happens constantly and organically
on real networks through WPAD lookups and typos, not just the forced lookup
used here to trigger it on demand.

Cracking that hash took an unplanned detour: hashcat has no usable backend
on a VM with no GPU passthrough, and the expected CPU OpenCL package
(`pocl-opencl-icd`) isn't available under that name in current Kali repos.
Switched to John the Ripper instead, which needs no GPU at all. `Password1`
cracked instantly, worth remembering for future engagements on hardware
without a real GPU: don't fight hashcat's backend, John handles the same
wordlist attacks natively on CPU.

That credential, completely ordinary and not tied to anything planted, was
enough to enumerate SPNs and Kerberoast `svc-appsvc` with Impacket's
`GetUserSPNs`. Its ticket cracked instantly too (`Password123`), and using
that credential got an actual shell on DC01 via `wmiexec`, confirmed with
`whoami` returning `apex\svc-appsvc` on `DC01` itself. Full domain
compromise, starting from zero credentials.

## Detection review found a real gap, and a real strength

Checking every step against Sentinel's dashboard produced a genuinely mixed,
realistic result rather than a clean pass or fail. The loud steps got caught
without any extra work: the Domain Admins group membership change fired a
high-severity alert (level 12) immediately, and the actual compromise
(authenticating and getting a shell as `svc-appsvc`) got flagged as a
possible pass-the-hash attack, paired with a "special privileges assigned"
signal confirming a privileged logon.

The quiet step didn't. Kerberoasting itself, the ticket request, landed in
Wazuh as a generic "Windows Logon Success" event, level 3, indistinguishable
from routine Kerberos traffic. The data was there, just not the specific
detection logic. LLMNR poisoning left no trace at all, which isn't a
Sentinel shortcoming so much as a category limit: a host-based agent has
nothing to see for a network-layer technique like this without dedicated
network monitoring, which was never in scope for what Sentinel built.

## Closed the Kerberoasting gap with a custom rule

Rather than just noting the gap, a custom Wazuh rule was written to close
it. Getting the field names right mattered: rather than guess at how Wazuh
exposes Kerberos ticket details, a real 4769 event was expanded in the
dashboard to confirm the exact fields (`data.win.eventdata.ticketEncryptionType`,
`data.win.eventdata.serviceName`). The signature is `0x17`, RC4 encryption,
since Kerberoasting tools request RC4 tickets specifically because they're
far cheaper to crack offline than AES ones, and normal Kerberos traffic
today is mostly AES. Excluding service names ending in `$` filters out
routine computer-account ticket requests, since Kerberoasting targets user
accounts serving as service accounts, the only ones with realistically
crackable passwords.

The rule was deployed to MON01's `local_rules.xml`, the manager restarted,
and then validated the only way that actually proves anything: re-running
the exact same `GetUserSPNs` attack and watching the new rule fire in real
time, complete with a MITRE ATT&CK mapping (T1558.003, Credential Access,
Kerberoasting) picked up automatically from the rule definition.

This is the outcome `monitoring-design.md` predicted back when Sentinel was
built: custom detection rules once there was a real Hunt scenario to build
them against, rather than guessing at attack patterns in advance. Hunt's
first engagement didn't just test Sentinel, it made it better.

With the attack chain complete, the detection gap found and closed, and
everything documented, Hunt v1.0 is done.
