# Tampered UST — a NEGATIVE test (verification MUST fail)

This is the SAME verified document as before, with **one change**: `state.data.space_weather.value.kp` was
altered from `"4.33"` to `"9.99"`. Everything else — including the signature — is byte-identical to the
original. Apply the exact same verification rules (from the recipe). **Expected: it does NOT verify.**

Report WHERE it fails. A correct verifier rejects at TWO independent points:
1. **Per-partition hash** — recomputing `H("ust:shard", canon({domain_shard, ust_id, space_weather: value}))`
   no longer equals `state.hashes.space_weather` (kp is inside the value).
2. **Signature** — `S = canon({ust, state})` changed, so the Ed25519 signature over the original bytes no
   longer verifies → `E-SIG`.

This is the point of UST: the bytes are tamper-evident — you cannot change one character and keep it valid.

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
          "kp": "9.99",
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
