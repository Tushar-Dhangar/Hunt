# Architecture Overview

**Project:** Hunt

**Portfolio:** WolfSec Labs

**Status:** Final

## Overview

Hunt is the third project in the WolfSec Labs portfolio. It doesn't build
infrastructure the way Atlas did, or add a new host the way Sentinel did.
Hunt attacks the environment that already exists, and measures how well
Sentinel sees it happen.

## What already exists

Hunt reuses the environment Atlas and Sentinel built without changes to it:

- **DC01** – Domain controller, `apexdynamics.internal`
- **APP01** – Ubuntu internal application server
- **WS01** – Domain-joined Windows 11 client
- **KALI01** – Dual-homed security testing workstation, the attack platform
  for this engagement
- **MON01** – Wazuh manager, indexer and dashboard, watching all four hosts

## Engagement scope

This engagement is an internal, assumed-breach assessment: the attacker
already has a foothold on corpnet (via KALI01), which matches how a real
internal penetration test is normally scoped rather than a true external
test, since corpnet has no real internet-facing perimeter to attack from
outside in the first place.

Scope is limited to the Windows/AD attack chain: WS01 through to DC01. APP01
gets at most a light pass. A full Linux-specific assessment on APP01 is a
candidate for a later Hunt iteration, not this one.

Two decisions shape the attack chain itself:

- **Initial access** is LLMNR/NBT-NS poisoning from KALI01, since those
  protocols are on by default on Windows and this is one of the most common
  real openings on a flat network. No planted vulnerability is needed for
  this step.
- **Privilege escalation** needed a planted misconfiguration, since Atlas's
  AD was built clean with no Kerberoastable accounts, delegation issues or
  ACL abuse paths. A single realistic one was added: a Kerberoastable
  service account made a member of Domain Admins.

Full reasoning for both is in
[docs/engineering-decisions/](../engineering-decisions/).

## Design philosophy

The same principle carried from Atlas and Sentinel applies here: do only
what this engagement actually needs. One planted misconfiguration is enough
to demonstrate a full attack chain without turning Atlas into an
unrealistic, deliberately-broken CTF box. A well-run company has weak
credentials and over-privileged service accounts somewhere; that's normal,
not contrived.

## Relationship to other projects

- **Atlas** built the infrastructure being attacked.
- **Sentinel** is watching it, and this engagement is the first real test of
  whether its detections actually work, not just whether logs flow.
- **Forge** hardens whatever this engagement finds, including fixing the
  planted misconfiguration and closing whatever detection gaps show up.

## Current Status

Engagement complete. Full domain compromise achieved via LLMNR/NBT-NS
poisoning and Kerberoasting, checked against Sentinel's dashboard, and the
one detection gap found (Kerberoasting itself) closed with a custom Wazuh
rule, validated live. See
[the engagement guide](../setup/engagement-guide.md) and
[the engineering journal](../notes/engineering-journal.md) for the full
attack chain and evidence.
