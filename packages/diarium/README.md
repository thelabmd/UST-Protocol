<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# diarium

Agent memory as a verifiable UST stream.

```
npm i -D diarium
```

A task closes in your tracker. The agent writes what it understood and what it learned from it — a few sentences, its own voice. That text is sealed as a UST `observation`, `prev`-chained to the entry before it, and appended to `diarium/`. The agent reads it back later as its own memory, walking the chain instead of loading the whole corpus.

Nothing here proves the work was done well. A sealed entry proves **the agent said this, then**, and that nobody — including the agent — rewrote it afterwards. Fixation, not truth. Ordering and non-repudiation are the product; correctness is not on offer.

The full walkthrough, with real command output, is in [FLOW.md](./FLOW.md). Wiring it to your agent is one paragraph: [INTEGRATE.md](./INTEGRATE.md).

## Why it is not just a log file

A log can be edited. A tracker comment can be edited. A closed issue can be reopened and its history rewritten. A `prev`-chained stream of signed entries cannot: change one entry and every later `prev` stops resolving, so the tampering is visible to anyone holding a later entry — no server, no trust in the author.

Hand someone a single file and they can check it offline with `npm i ust-protocol` or the public web verifier. Nothing calls back to us; there is no us to call.

## What holds it together

Nobody reviews an entry before it lands. That is deliberate, so the discipline cannot be review — it is the **trigger**: the agent does not choose when to write. A task closes, an entry is owed. It cannot skip a closure it would rather not record, and it cannot bury one entry under ten others. One closure, one entry, and a closure without an entry is detectable — that is what `status` is, and why it exits non-zero while anything is owed.

The rest is mechanical, and split honestly between what code can enforce and what only prose can ask for:

| enforced by code | asked for by the rules |
| --- | --- |
| character cap | write the failures too, not just the wins |
| `prev` chain, signature | one entry, one moment |
| one entry per closure | no performed feelings |
| a broken store cannot be extended | do not reconstruct a task you no longer hold |

The rules live in `diarium/rules.md` as prose, and the agent reads them before writing. Rewrite that file and the agent's behaviour changes — configuration by prose. The cap is yours to set. The append-only chain is not: without it this is a text file.

`"Nothing to learn"` is a first-class entry, recorded structurally rather than buried in a sentence, so a corpus that is mostly *nothing learned* can be counted. Absence of a result is a result.

## Commands

```
diarium scan                what closed since last time (first run sets a baseline, not a backlog)
diarium status              closures owing an entry — exit 1 while any is owed, so it can gate
diarium write <ref> <file>  seal + chain + store        [--nothing-learned]
diarium read [--depth N]    walk the chain N hops back from the head
diarium verify              every seal, one genesis, one head, no fork, no orphan
diarium render              markdown to stdout, derived, never stored
```

Trackers are detected on first run — a `.beads/` directory, a GitHub remote — and written into `diarium/settings.json` for you to edit. Both answer one question, *what closed after this cursor*, so another tracker is an adapter, not an integration.

## Keys

A signing key is generated into `.env` as `DIARIUM_SEED` on first run and is never printed, not even by the tool that made it. Every run checks that git actually ignores it. Lose it and the chain can no longer be extended, though every existing entry still verifies. Leak it and someone else can write entries as you — and every one of those will verify too, which is the point of checking.

## Tier

`VALID:LIGHT`, key-form identity, and that is the right ceiling. Everyone keeps their own memories, so there is no third party to convince — no domain-bound identity to prove *who*, no external clock to prove *when*. Adding those would be selling assurance nobody asked for.

## Status

Deliberately **not** on the `1.0.0-rc` line: everything else in this repository is protocol surface on the `1.0.0-rc` line, while this is a product built on top of it. Treat the CLI surface as unsettled and the sealed entries as permanent — an entry written today verifies under any later version, because what makes it verifiable is the protocol, not this tool.

Built on [`ust-protocol`](../ust-protocol), which is its only dependency, and which has none of its own.
