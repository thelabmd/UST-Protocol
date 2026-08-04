<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Governance

Deliberately minimal. This document will grow when there is a second independent implementer; until then, a
heavy process would be theatre.

## Two rules this protocol does not trade away

**1. A minor only ADDS.** A change that alters the meaning of anything an earlier minor already defines is a **MAJOR**. There is no third option, and the reason is not taste: an older verifier evaluating under older rules must still be **right** about what it evaluated. A minor that changed a meaning would make every deployed verifier quietly wrong rather than merely less informed.

**2. A verifier never expires.** An older verifier keeps producing correct verdicts about everything it understands. Material from a newer minor that it does not implement is reported as **NOT EVALUATED** — never as invalid, and never silently passed. Whether that reach is sufficient is the **consumer's** policy (the `--require-*` floors), not the protocol's coercion.

**Why the second rule is load-bearing for adoption.** People run old runtimes for years because upgrading means reworking a stack that works. A protocol whose adoption depends on synchronised upgrades across every consumer has chosen a property it cannot have — and a verifier that must be current in order to verify anything is a verifier that stops being run. Refusing politely is still refusing.

**And it is what makes CLOSED systems possible at all.** A consumer with no discovery surface has no way to learn that the world moved. Under a refusal design it sees only *invalid*, with nothing pointing at its own age; under this one it keeps working, keeps being honest about what it did and did not check, and can run for years without ever lying.

*Both rules hold today. A newer minor answers `INDETERMINATE(unsupported_minor)`, a different major `INDETERMINATE(unsupported_major)`; `INVALID` is reserved for its one meaning — the verifier applied ITS OWN rules and they were violated.*

## How changes are made

Changes are proposed via **issues and pull requests** against this repository. Discussion happens in the open.

## What counts as a breaking change

A **breaking change** is anything that affects the **canonical bytes, hashes, signatures, or verdicts** — i.e.
anything that could make a previously-conforming document verify differently, or a conforming implementation
disagree. Editorial, documentation, and additive-tooling changes are not breaking.

Breaking changes require a **version bump** and a **declared cutover `ust_id`** per **§19** of the specification,
so every consumer can tell exactly which frames fall under which version.

## Decisions

Anyone may propose; the **maintainer decides** in case of dispute. When a second independent implementation
exists, this section will be replaced by a real multi-party process.

## Contributions — inbound = outbound

By contributing you agree your contribution is licensed under the **same licenses as the project**: **Apache-2.0**
for code and **CC BY 4.0** for specification/documentation text (see `LICENSE`, `LICENSE-SPEC`). There is **no
CLA** — inbound = outbound.
