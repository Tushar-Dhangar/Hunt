# Hunt

**WolfSec Labs** — building, breaking and defending enterprise systems.

Hunt is the third repository in the WolfSec Labs portfolio. It attacks the
enterprise Atlas built and Sentinel is watching, rather than standing up a
separate throwaway target. Every finding in Hunt is a real result against
real infrastructure, and every step gets checked against Sentinel's
dashboard to see what actually got caught.

## This engagement

Scope is an internal, assumed-breach style assessment against the Windows
side of the environment: WS01 through to DC01. KALI01 is the attack
platform, already built and already dual-homed onto corpnet.

Initial access uses LLMNR/NBT-NS poisoning, since those protocols are on by
default and this is one of the most common real openings on a flat internal
network like corpnet. Atlas's Active Directory was otherwise built clean, so
one realistic misconfiguration was deliberately introduced for this
engagement to have something to escalate through: a Kerberoastable service
account, over-privileged into Domain Admins. That's a genuinely common audit
finding in real environments, not a contrived one.

Full reasoning for both of those decisions is in
[docs/engineering-decisions/](docs/engineering-decisions/).

## Result

Full domain compromise, from a starting position of zero credentials.
Responder captured a credential hash from ordinary broadcast traffic on
WS01, cracked offline, then used to Kerberoast the planted `svc-appsvc`
account and crack its password too, landing a shell on DC01 as a Domain
Admin.

Checking every step against Sentinel found a genuinely mixed result: the
loud steps (a Domain Admins group change, the final privileged logon) were
caught by Wazuh's default ruleset with no extra work, while Kerberoasting
itself slipped through as a generic, unflagged event. That gap didn't stay
open: a custom Wazuh rule was written, deployed and validated live against
a second run of the same attack, closing it. Full evidence and every
command used is in
[the engagement guide](docs/setup/engagement-guide.md).

## Relationship to Atlas and Sentinel

Hunt doesn't rebuild or redesign anything Atlas or Sentinel already locked
in. The domain, the network, the hosts and the monitoring stack are all
carried over unchanged. What's documented here is the engagement itself: the
attack chain, the evidence, and what Sentinel did or didn't detect at each
step.

## Repository layout

- `docs/architecture/` — engagement scope and methodology
- `docs/engineering-decisions/` — the reasoning behind the attack plan
- `docs/setup/` — the engagement guide: the attack chain, evidence and results
- `docs/notes/` — engineering journal
- `assets/diagrams/` — attack path diagrams
- `assets/screenshots/` — evidence captures
- `scripts/` — supporting automation

## Roadmap

- Engagement scope and methodology — complete
- Initial access (LLMNR/NBT-NS poisoning) — complete
- Privilege escalation (Kerberoasting) — complete
- Domain compromise confirmed — complete
- Detection review against Sentinel — complete
- Custom Kerberoasting detection rule (closing the gap found) — complete
- Hunt v1.0 — complete

## WolfSec Labs portfolio

Atlas → Sentinel → **Hunt** → Forge

Atlas built the enterprise. Sentinel watches it. Hunt attacks it and
Sentinel's detections get judged against what Hunt actually does. Forge
hardens whatever Hunt finds.
