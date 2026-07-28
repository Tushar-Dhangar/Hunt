# ADR-002: Planted Misconfiguration for Privilege Escalation

**Status:** Accepted

## Background

Atlas's Active Directory was deliberately built clean. There are no
Kerberoastable service accounts, no unconstrained delegation, no obviously
abusable ACLs, and no resource-scoped groups yet, since Atlas only built the
identity (global group) layer and deferred resource permissions until there
were actual resources to protect.

That's the right call for Atlas as an infrastructure build, but it leaves
Hunt with a real problem once initial access succeeds: a low-privilege
domain credential on a well-configured small AD has nowhere obvious to go.

## Decision

One realistic misconfiguration is introduced specifically for this
engagement: a service account, `svc-appsvc`, created in the IT OU with a
Service Principal Name registered against it (making it Kerberoastable), a
deliberately weak and wordlist-crackable password, and membership in Domain
Admins.

## Why this decision?

The alternative was assessing the AD exactly as Atlas built it. That's a
legitimate choice, and the honest result would likely be "no obvious
escalation path from a standard low-privilege account," which is itself a
valid finding for a small, well-configured environment. But it also produces
a much shorter engagement, with no domain compromise to demonstrate and
nothing for Sentinel's detection capability to actually be tested against
beyond the initial credential capture.

An over-privileged, weak-password service account is one of the most common
findings in real Active Directory security assessments. Kerberoasting exists
as an attack technique specifically because organisations routinely create
service accounts for internal applications, set a password once, register an
SPN, and never revisit either. Making `svc-appsvc` a Domain Admin on top of
that mirrors a second extremely common finding: service accounts
accumulating more privilege than they need because it's easier than scoping
access properly. Planting exactly this, and nothing more elaborate, keeps
the engagement realistic instead of turning Atlas into a deliberately broken
CTF box with a trail of unrealistic vulnerabilities to chain together.

Only one misconfiguration was introduced, not several. A real assessment
sometimes finds one meaningful issue and sometimes finds many; a single
well-chosen weak point is enough to demonstrate the full attack chain, from
credential capture through Kerberoasting through domain compromise, without
manufacturing an environment that doesn't resemble anything real.

## Trade-offs

This means the domain compromise Hunt demonstrates isn't purely organic. If
Atlas's environment were assessed as originally built, Hunt would likely
stop after initial access with no privilege escalation path found. That's
worth being transparent about rather than presenting the planted account as
something that was simply discovered. The realism argument still holds: what
was planted is exactly the kind of thing a real assessment finds, the
research and technique used to find and exploit it (SPN enumeration,
Kerberoasting, offline hash cracking) are identical either way.

## Outcome

`svc-appsvc` is created in `Apex/Users/IT`, with an SPN registered, a weak
password set, and membership in Domain Admins added, before the attack chain
runs. The account and its configuration are recorded in
[the engagement guide](../setup/engagement-guide.md) alongside the rest of
the attack chain evidence.
