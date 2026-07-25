# The flow

Every command output below is real, copied from a live run against a repo with a bd tracker and a GitHub tracker — not
an illustration.

## Install

```
npm i -D diarium
```

First run creates a `diarium/` folder next to your code and generates a signing key into `.env`:

```
diarium/
  rules.md        prose. The agent reads it before every entry. Yours to rewrite — we do not care how you word it.
  settings.json   structure. Code reads it: which trackers to watch, where the cursors are.
  .pending/       closures that owe an entry
  *.ust.json      one sealed entry per file
```

The key lives in `.env` as `DIARIUM_SEED` and is never printed — not even by the tool that made it. Lose it and the
chain can no longer be extended, though every existing entry still verifies. Leak it and someone else can write entries
as you, and every one of those will verify. So the tool checks, on every run, whether git actually ignores `.env`:

```
  · generated a signing key into .env — gitignore it. The seed is never printed, not even here.
  ! .env is NOT gitignored — add it now. The seed in there is the identity of this store;
    anyone who has it can write entries as you, and every one of them will verify.
```

The key is generated at install rather than at the first entry, so that warning arrives while you are setting up — not
half an hour later, mid-flow, when the store already exists.

## Wire it to your agent

There is no plugin, no MCP server, no GitHub Action. Your agent already runs shell commands, so one paragraph in
whatever file it reads as standing instructions — `CLAUDE.md`, `AGENTS.md`, a Cursor rule — is the whole integration.
The suggested wording is in `INTEGRATE.md`.

## The loop

### 1. Start of a session — what did I learn last time

```
$ diarium read --depth 3
  walking back 3 hop(s) from the head of 9 entries

  ── ust:20260725.154843  ·  task diarium-ixr  ·  20260725.154843_diarium-ixr_be8ef642.ust.json
  Nothing here to learn: this task existed only to prove the trigger fires on a real closure. Recording that
  plainly rather than inventing an insight.
```

It walks the chain N hops back from the head rather than loading the whole corpus, so a store with a thousand entries
costs the same to read as one with three.

### 2. Work. Close a task — in whichever tracker you use

```
$ bd close UST-l0a
```
or
```
$ gh issue close 90
```

Nothing special: close it the way you always do.

### 3. `scan` — what closed since last time

```
$ diarium scan
  bd:..: 1 closure(s) since 2026-07-25T15:56
  github:thelabmd/UST-Protocol: 0 closure(s) since 2026-07-25T15:56

  1 new obligation(s) — run status
```

Both trackers answer the same question — *what closed after this cursor* — so adding a tracker is an adapter, not an
integration. A tracker that is unreachable says so and its cursor is left untouched, so nothing is skipped quietly.

**The very first scan sets a baseline instead of a backlog:**

```
  bd:..: BASELINE set — 79 historical closure(s) skipped (a memory you did not live is an invention, not a memory)
```

Asking an agent to write seventy-nine entries about work it does not remember would manufacture recollection. What is
skipped is printed, not dropped in silence.

### 4. `status` — what owes an entry

```
$ diarium status
  store: 9 entries  ·  cap 560  ·  diarium/
  ✗ 1 closure(s) owe an entry — a closure without an entry is what this catches:
    UST-l0a        done      2026-07-25T16:09  flow doc demo — a real closure in this repo tracker
```

Exit code is 1 while anything is owed, so it can gate a commit if you want it to.

This is the load-bearing part of the design: **the agent does not choose when to write.** A closure creates the
obligation; only the agent can discharge it. It cannot skip a closure it would rather not record, and it cannot bury
one entry under ten others.

### 5. The agent writes the recap

What it should write: **what it understood and what it learned** — not what it did. Git already keeps what it did, and
keeps it better.

If it no longer holds the task, the honest entry is exactly that, and it is a first-class record:

```
$ diarium write UST-l0a recap.md --nothing-learned
```

Absence of a result is a result. It is recorded structurally rather than left inside a sentence, so a corpus that is
mostly *nothing learned* can be counted — and that count tells you something about the work, or about the trigger.

```
$ diarium write UST-l0a recap.md
✓ entry sealed + stored
  file        : 20260725.160942_UST-l0a_6e96103b.ust.json
  task        : UST-l0a (tracker-local)
  content_hash: sha256:6e96103b582a92dc7312ccea9d86d03adc186c818f76bde8da51569beddaf975
  prev        : sha256:be8ef64235d1919de4bd88f2d78c32b27c2373328fbd83c8fa8e44d705d4dcae
```

The entry is verified **before** it is stored, chained to the head of the chain (not to the last filename), and the
obligation is discharged. The cap declared in `rules.md` is enforced here; everything else in that file the tool can
only ask for, which is honest as long as asking is not dressed up as enforcement.

```
$ diarium status
  store: 10 entries  ·  cap 560  ·  diarium/
  ✓ no closure is waiting for an entry
```

### 6. `verify` — nobody rewrote anything

```
$ diarium verify
✓ 10 entries: every seal verifies, one genesis, one head, no fork, no orphan
  (order from the chain — filenames are cosmetic)
```

This is the only reason the entries are UST documents rather than lines in a text file. It catches, with the sealed
bytes alone:

| what happened | what verify says |
| --- | --- |
| an entry's text was edited | that seal does not verify |
| an entry was deleted from the middle | no genesis, and a `prev` that resolves to nothing |
| entries were reordered by renaming | nothing — names carry no meaning, and that is by design |
| an entry was duplicated | a fork: two entries claim the same `prev` |
| the whole folder was moved | nothing — a seal is not bound to where it is stored |

An entry cannot be rewritten afterwards **including by the agent that wrote it**, and anyone can check that offline
without trusting you. Hand someone a single file and they can verify it with the public web verifier or `npm i
ust-protocol` — no server, no account, no call back to us.

## What a stored entry actually is

A plain UST document. Not a diarium format:

```json
{
  "ust": "1.0",
  "state": {
    "id":   { "domain_shard": "sha256:9075…", "ust_id": "ust:20260725.160942",
              "key_id": "sha256:9075…", "class": "observation" },
    "time": { "generated_at": "2026-07-25T16:09:42Z", "valid_from": "…", "valid_to": "…" },
    "data": { "entry": { "kind": "captured", "value": {
                "text": "…the recap…",
                "task": { "ref": "thelabmd/UST-Protocol#91", "id": "4975299807",
                          "node_id": "I_kwDO…", "source": "github",
                          "closed_at": "2026-07-25T16:09:12Z" } } } },
    "hashes":     { "entry": "sha256:aaa7…" },
    "provenance": { "prev": "sha256:be8e…" }
  },
  "sig": { "alg": "Ed25519", "key_id": "sha256:9075…", "pub": "56tM…", "sig": "pIsn…" }
}
```

Two details worth knowing:

**The task reference carries a durable id.** `owner/repo#N` is a path, and paths go stale — rename or transfer the repo
and the reference inside an already-sealed entry becomes unresolvable, with no way to fix it. So the seal carries the
readable ref *and* the identifier that survives a rename. Where no global id exists — bd, any local tracker — that is
recorded as `source: tracker-local` rather than implied, and nothing is invented when a lookup fails.

**Lived and reconstructed are told apart by evidence, not by claim.** The seal carries the closure time next to the
write time, so the interval is observable: an entry written three minutes after the closure was lived, one written
three days later was reconstructed. Nobody declares which — declaring your own reliability is exactly the self-asserted
assurance this design refuses everywhere else.

## Filenames

```
20260725.160942_UST-l0a_6e96103b.ust.json
└── address ──┘ └ task ┘ └ hash ┘
```

Underscore separates fields and hyphen lives inside them, because repo names carry hyphens (`UST-Protocol`) and a
separator that can also appear in the data is not a separator. The address has no `ust:` prefix because a colon cannot
be checked out on Windows.

None of this carries meaning. Order comes from the chain, identity from the `content_hash` — rename every file and
`verify` stays green. The name is there so a human can find something by eye.
