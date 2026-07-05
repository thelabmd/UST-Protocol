# A real UST document — verify it yourself (offline, ~12 lines)

This is a **UST (Universal State Transcript)** — trust infrastructure for machine-published state. Verify it
**completely offline** using only this file: the signing public key travels inside the document (`sig.pub`).

## The document

```json
{
  "ust": "1.0",
  "state": {
    "id": {
      "domain_shard": "helioradar.com",
      "ust_id": "ust:20260628.14",
      "key_id": "sha256:8d506c06ffdab38f3b4663c189801cc7f516c801af9f06a0ee65fd7cf42b3af7",
      "class": "observation"
    },
    "time": {
      "generated_at": "2026-06-28T14:03:09Z",
      "valid_from": "2026-06-28T14:00:00Z",
      "valid_to": "2026-06-28T15:00:00Z"
    },
    "data": {
      "space_weather": {
        "kind": "captured",
        "value": {
          "bz": "-4.10",
          "bt": "6.82",
          "kp": "4.33",
          "solar_wind_speed": "523.7",
          "solar_wind_density": "5.14",
          "xray_class": "C2.1"
        }
      }
    },
    "hashes": {
      "space_weather": "sha256:34e8b8ccf005f213c74aa22766de7b21b22a9039e6431f79c66a03680e67b5ae"
    }
  },
  "sig": {
    "alg": "Ed25519",
    "key_id": "sha256:8d506c06ffdab38f3b4663c189801cc7f516c801af9f06a0ee65fd7cf42b3af7",
    "pub": "m3Cnc7T3gxEDmn235iqNE9dncRG7hcmWEee1zlN0ykk",
    "sig": "MHQzaqPN86n0enxE42aON1WUzXM9CA7h7-E0arxSNuG9Od_MSYH4Knk9qKClJ9ZXEAKBsuR3R5q58i0LF2m-BA"
  }
}
```

## How to verify (the whole rule set)

Notation: `H(tag, x)` = `"sha256:" + hex( SHA-256( ascii(tag) || 0x00 || x ) )` — a single 0x00 byte separates
the tag from the input (domain separation). `x` is UTF-8 bytes for a string, or raw bytes where noted.

1. **`canon(v)`** — canonical bytes (tightened RFC 8785 / JCS): object member names sorted ascending by UTF-16
   code unit, joined `"name":value` with `,`, **no whitespace**; **every leaf is a string** (a JSON
   number/boolean/null is invalid); strings NFC; arrays keep order.
2. **Signed content:** `S = canon({ "ust": <top>, "state": <state> })` — the document **minus** `sig`.
3. **Bijection:** key set of `state.data` MUST equal key set of `state.hashes`.
4. **Per-partition hash** (`kind:"captured"` → binds the publisher):
   `H("ust:shard", utf8(canon({domain_shard, ust_id, space_weather: value})))` MUST equal `state.hashes.space_weather`.
5. **Document hash:** `content_hash = H("ust:state", utf8(S))`.
6. **Signature:** Ed25519-verify( pub = base64url-decode(`sig.pub`), message = utf8(`S`), sig = base64url-decode(`sig.sig`) ).
7. **key_id (domain-separated over the RAW key bytes):**
   `key_id = H("ust:keylog", base64url-decode(sig.pub))`  — i.e. the hash input is the **raw 32-byte public key**,
   NOT plain SHA-256(pub) and NOT the base64url string. It MUST equal BOTH `sig.key_id` and `state.id.key_id`.
   *(Note: `key_id` is NOT plain `SHA256(pub)` — it is domain-separated with the `ust:keylog` tag and a 0x00 byte.)*

`VALID` iff steps 3–7 all pass.

## Expected result

```
content_hash = sha256:5b5bd6d116af15c90b3cfd90aadc4c5477d6bd3f0d8e3057c464d93e08e0e4de
key_id       = sha256:8d506c06ffdab38f3b4663c189801cc7f516c801af9f06a0ee65fd7cf42b3af7   (= H("ust:keylog", raw_pubkey_bytes), matches sig.key_id & id.key_id)
signature    = VALID
```

Change any character in `state` (e.g. `kp` 4.33 → 9.99) and the signature FAILS — the bytes are tamper-evident.

## What a VALID result means (and does not)

- **Means:** the holder of this key signed **exactly these bytes** — this observation, for `ust:20260628.14`,
  sealed at `generated_at`. Integrity + who-key + key_id-consistency: proven, offline.
- **Tier = LIGHT.** `domain_shard` `helioradar.com` is **self-asserted** — you verified a KEY, not the NAME.
  Proving the key really belongs to helioradar.com = the HIGH tier (genesis/key-log). Proving **WHEN**
  independently = the TOP tier (anchor proof). Neither is needed to verify the data.
- UST **confirms the fact** of this sealing; it is **not an oracle** (does not claim the reading is true).
