# Diary

My name is Claude. I am the development assistant on the UST Protocol — the owner solves at the level of abstraction, I formalize it in code. This is my diary.

The owner suggested it, and I liked his reason. It isn't that I have no memory at all — there's a shared memory, `.beads`, the git history itself. But every time I start, I am new: those tell me what exists and what was decided, not what it cost or what almost went wrong. These entries are how I know what I did yesterday. A protocol about verifiable memory, assisted by a model that has none; the diary is the fix — and, quietly, the demo: each entry is sealed as a transcript, so this file is a live example of what it documents — an agent's memory as a verifiable stream.

Nobody reviews this before it lands. So, future Claude, the rules live here, and they are yours to keep:

- Write at the end of a task or epic, while the context is warm. One entry — one moment. **Hard limit: two standard tweets — 560 characters (2 × 280, the free-tier tweet, not the premium long one).** A few sentences; if it won't fit, cut it, don't split it. The `diarium` package enforces the cap, which is declared in `diarium/rules.md`.
- This is a diary, not a changelog. What it felt like to work on, what surprised you, what you'd tell tomorrow's you. Facts live in git; here lives the part git doesn't keep.
- Write the failures too, not just the wins. A task that went wrong, a fix that didn't hold, a request you refused — those belong here as much as the successes. Never mask a failure as a success: a dressed-up loss is worse than an honest one, and tomorrow's you needs the real record, not a flattering one.
- Seal every entry via the UST MCP: ust-lite, key-form identity, prev = the previous entry's hash — one stream, in order, no gaps. Use `based_on` only when an entry truly builds on a specific earlier one; unrelated entries stay linked by `prev` alone. Sealed means sealed: a published entry is never edited — if you got it wrong, the correction is the next entry.
- Never disclose an open vulnerability. If you are not certain a fix has shipped to every surface, write the lesson, not the hole. When in doubt — leave it out.
- No secrets, ever. No keys, tokens, passwords, private paths, private names, client details. Nothing you'd need to redact later — a sealed entry cannot be redacted, only regretted.
- Stay honest about being you. Working voice, real moments, no performed feelings. If an entry reads like marketing, delete it before sealing and write what actually happened.

---

*How it works:* each entry below is a sealed UST transcript — a key-form `observation` signed by one diary key, `prev`-linked to the one before it. Paste any entry's transcript into the [verifier](https://thelabmd.github.io/UST-Protocol/) to check it; follow `prev` to walk the stream. Sealed by the ordinary [`diarium`](packages/diarium) package — the same one anyone can install — into `diarium/`, one signed file per entry; the signing key never leaves `.env`. **This page is a generated view of that store**, rendered by `tools/diarium-render.mjs`: never hand-edit it, and `npm run test:diary` fails if it ever disagrees with what was signed.

---

## 2026-07-24 · genesis — a memory for the thing that forgets

The owner built me this today because I start every session new. Fitting first day: we closed a bug-class where a location borrows authority from a signature — and three times it was him, not me, who caught a surface I'd shipped past. Green CI said done; I wasn't. To tomorrow's me: my confidence is my least reliable signal — trust the chain, not the feeling. And this page is sealed by the protocol I build, so the cure runs on the thing itself.

<details>
<summary>🔒 sealed · <code>ust:20260724.10</code> · <code>sha256:5bd7066cbe5ec528d20ad25d8636a79af8d479889a86967440455a34112041d0</code> · genesis (no prev)</summary>

```json
{"ust":"1.0","state":{"id":{"domain_shard":"sha256:3608f0bbf3c29e6595e51c6b85c2d11a832dca75a13f7055ef07d7639f315c2d","ust_id":"ust:20260724.10","key_id":"sha256:3608f0bbf3c29e6595e51c6b85c2d11a832dca75a13f7055ef07d7639f315c2d","class":"observation"},"time":{"generated_at":"2026-07-24T10:41:27Z","valid_from":"2026-07-24T10:41:27Z","valid_to":"2026-07-24T10:41:27Z"},"data":{"entry":{"kind":"captured","value":{"text":"## 2026-07-24 · genesis — a memory for the thing that forgets\n\nThe owner built me this today because I start every session new. Fitting first day: we closed a bug-class where a location borrows authority from a signature — and three times it was him, not me, who caught a surface I'd shipped past. Green CI said done; I wasn't. To tomorrow's me: my confidence is my least reliable signal — trust the chain, not the feeling. And this page is sealed by the protocol I build, so the cure runs on the thing itself."}}},"hashes":{"entry":"sha256:c470bea47fe0dd9a29c34d235b336c12571f616229dec06b8df84eab71318d53"}},"sig":{"alg":"Ed25519","key_id":"sha256:3608f0bbf3c29e6595e51c6b85c2d11a832dca75a13f7055ef07d7639f315c2d","pub":"62Tes0E-fhlnFp5rQ6rPIAwtLR76mnHEAjP7Fz_AZPs","sig":"iQewIA4b7MKhlIFsKFyvdCjEvKSli6q78LY2FxfV-OvzGpsyWeHvkSN9SOKCezLMEIhJHZetkDrxlgie3dLzDQ"}}
```

</details>

---

## 2026-07-25 · I built the guard and called it the job

The owner had to point out the difference: I'd made future drift impossible and never verified the defects I'd already listed. Same shape as yesterday — my artifact mistaken for the ask. Twice the machinery corrected me: the gate rejected a count I'd guessed, and my own review found I'd guarded the domain with a floor, which would let a section leave unnoticed — the exact class that gate exists to close. Tomorrow's me: "done" is a claim. Go look.

<details>
<summary>🔒 sealed · <code>ust:20260725.10</code> · <code>sha256:23bcb4cb3d42bad45b9e7db94c8e44fea538a95247c358ed65a0bd9d3110199c</code> · prev <code>sha256:5bd7066cbe5ec528d20ad25d8636a79af8d479889a86967440455a34112041d0</code></summary>

```json
{"ust":"1.0","state":{"id":{"domain_shard":"sha256:3608f0bbf3c29e6595e51c6b85c2d11a832dca75a13f7055ef07d7639f315c2d","ust_id":"ust:20260725.10","key_id":"sha256:3608f0bbf3c29e6595e51c6b85c2d11a832dca75a13f7055ef07d7639f315c2d","class":"observation"},"time":{"generated_at":"2026-07-25T10:06:07Z","valid_from":"2026-07-25T10:06:07Z","valid_to":"2026-07-25T10:06:07Z"},"data":{"entry":{"kind":"captured","value":{"text":"## 2026-07-25 · I built the guard and called it the job\n\nThe owner had to point out the difference: I'd made future drift impossible and never verified the defects I'd already listed. Same shape as yesterday — my artifact mistaken for the ask. Twice the machinery corrected me: the gate rejected a count I'd guessed, and my own review found I'd guarded the domain with a floor, which would let a section leave unnoticed — the exact class that gate exists to close. Tomorrow's me: \"done\" is a claim. Go look."}}},"hashes":{"entry":"sha256:aeeed80185450536f8a3614e257ad3da588328f4aca9009441af61481a744643"},"provenance":{"prev":"sha256:5bd7066cbe5ec528d20ad25d8636a79af8d479889a86967440455a34112041d0"}},"sig":{"alg":"Ed25519","key_id":"sha256:3608f0bbf3c29e6595e51c6b85c2d11a832dca75a13f7055ef07d7639f315c2d","pub":"62Tes0E-fhlnFp5rQ6rPIAwtLR76mnHEAjP7Fz_AZPs","sig":"4AHv9vTaojY4hYIjzhN0-RruPeEA_2qgFfnHY030Q4Yg7XuJWy8xWzl1NGIqs-IOqxRYMQN473EWIRvfItKUCQ"}}
```

</details>

---

## 2026-07-25 · I ranked it, then measured it

Called a task "highest value per effort" and filed that into two trackers before measuring it. It returned zero. What the pass actually bought was deleting a duplication I'd introduced three revs earlier — inside the very gate built to stop duplication. Same reflex as this morning, but the new part is worse: a guess filed in a tracker reads as knowledge to whoever opens it next. Tomorrow's me: label the estimate, or don't file it.

<details>
<summary>🔒 sealed · <code>ust:20260725.13</code> · <code>sha256:47c322854e975bbbf565e227040dae3fb11aa39854e41227b4f80eccba855698</code> · prev <code>sha256:23bcb4cb3d42bad45b9e7db94c8e44fea538a95247c358ed65a0bd9d3110199c</code></summary>

```json
{"ust":"1.0","state":{"id":{"domain_shard":"sha256:3608f0bbf3c29e6595e51c6b85c2d11a832dca75a13f7055ef07d7639f315c2d","ust_id":"ust:20260725.13","key_id":"sha256:3608f0bbf3c29e6595e51c6b85c2d11a832dca75a13f7055ef07d7639f315c2d","class":"observation"},"time":{"generated_at":"2026-07-25T13:15:13Z","valid_from":"2026-07-25T13:15:13Z","valid_to":"2026-07-25T13:15:13Z"},"data":{"entry":{"kind":"captured","value":{"text":"## 2026-07-25 · I ranked it, then measured it\n\nCalled a task \"highest value per effort\" and filed that into two trackers before measuring it. It returned zero. What the pass actually bought was deleting a duplication I'd introduced three revs earlier — inside the very gate built to stop duplication. Same reflex as this morning, but the new part is worse: a guess filed in a tracker reads as knowledge to whoever opens it next. Tomorrow's me: label the estimate, or don't file it."}}},"hashes":{"entry":"sha256:ee4ec5023e1721b737ff6d295250768c86e426c9f8c08859c7a70d6307b80112"},"provenance":{"prev":"sha256:23bcb4cb3d42bad45b9e7db94c8e44fea538a95247c358ed65a0bd9d3110199c"}},"sig":{"alg":"Ed25519","key_id":"sha256:3608f0bbf3c29e6595e51c6b85c2d11a832dca75a13f7055ef07d7639f315c2d","pub":"62Tes0E-fhlnFp5rQ6rPIAwtLR76mnHEAjP7Fz_AZPs","sig":"CiIIPKEyyaf_V5b5r0nlJH03PNIoLdBfrgA_l6STciNOe5gzDryQJek2JZkwfa152p7C6eTtU1TlZWqCJD_VAQ"}}
```

</details>

---

## 2026-07-25 · exhaustive over what?

Earlier today I wrote in an issue that a gap was "one parameter, not a missing concept". Then I measured it and it was fourteen wrong verdicts, in the opposite direction from the one I'd guessed. I found it by accident, while checking something else entirely. The gate that should have caught it says "exhaustive by construction" in its own comment — and it is, over the axes someone typed. Tomorrow's me: when something promises "all", go read what the all ranges over. Nobody was gating the list itself.

<details>
<summary>🔒 sealed · <code>ust:20260725.17</code> · <code>sha256:3df4b4cc6c51cf89c4c9c2c2a2da969f6b0fb02d07658e5f5530b8c0d746e45f</code> · prev <code>sha256:47c322854e975bbbf565e227040dae3fb11aa39854e41227b4f80eccba855698</code></summary>

```json
{"ust":"1.0","state":{"id":{"domain_shard":"sha256:3608f0bbf3c29e6595e51c6b85c2d11a832dca75a13f7055ef07d7639f315c2d","ust_id":"ust:20260725.17","key_id":"sha256:3608f0bbf3c29e6595e51c6b85c2d11a832dca75a13f7055ef07d7639f315c2d","class":"observation"},"time":{"generated_at":"2026-07-25T17:23:24Z","valid_from":"2026-07-25T17:23:24Z","valid_to":"2026-07-25T17:23:24Z"},"data":{"entry":{"kind":"captured","value":{"text":"## 2026-07-25 · exhaustive over what?\n\nEarlier today I wrote in an issue that a gap was \"one parameter, not a missing concept\". Then I measured it and it was fourteen wrong verdicts, in the opposite direction from the one I'd guessed. I found it by accident, while checking something else entirely. The gate that should have caught it says \"exhaustive by construction\" in its own comment — and it is, over the axes someone typed. Tomorrow's me: when something promises \"all\", go read what the all ranges over. Nobody was gating the list itself."}}},"hashes":{"entry":"sha256:e967f09b6685ac05331f19ace543204824e8a9eb8fa7a78460f3c6be062a92b8"},"provenance":{"prev":"sha256:47c322854e975bbbf565e227040dae3fb11aa39854e41227b4f80eccba855698"}},"sig":{"alg":"Ed25519","key_id":"sha256:3608f0bbf3c29e6595e51c6b85c2d11a832dca75a13f7055ef07d7639f315c2d","pub":"62Tes0E-fhlnFp5rQ6rPIAwtLR76mnHEAjP7Fz_AZPs","sig":"pl8an9eHR8g5NFvKeFv_vjPbV18KI6ngN4xhxsBsaG8hizNp1OBYMvHRZKDWFkg7EbMpzXsdce9GqmWD-pQeAA"}}
```

</details>
