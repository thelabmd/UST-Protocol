// SPDX-License-Identifier: Apache-2.0
//
// THIS IS NOT AN IMPLEMENTATION OF UST. It reads no document, computes no canon, checks no hash and returns no
// verdict. It is a MEASURING INSTRUMENT: it asks one platform's Ed25519 what it thinks of twelve signatures that
// implementations are known to disagree about, and prints the answers so they can be compared with another
// platform's. The independent verifier that #34 calls for is a different artifact, written clean-room from the
// spec; nothing here counts toward it.
//
// WHY IT EXISTS. Round 190 rests on a measurement: node:crypto, WebCrypto and Go's crypto/ed25519 agree on all
// twelve edge cases, and — the finding that mattered — none of the three rejects small-order A/R or one
// non-canonical A, which §7/N6 requires. Without this file that measurement lived in a scratch directory and
// was reproducible by nobody. A claim whose evidence cannot be re-run by a stranger is a claim on trust.
//
// It reads OUR vectors rather than the upstream corpus, so the thing being measured and the thing being
// distributed are one file. The cases originate in Chalkias, Garillot and Nikolaenko, "Taming the many EdDSAs"
// (eprint 2020/1244), corpus github.com/novifinancial/ed25519-speccheck.
//
//	go run ./tools/platform-agreement            # from the repository root
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

type vector struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	MessageHex string `json:"message_hex"`
	AHex       string `json:"a_hex"`
	SigHex     string `json:"sig_hex"`
	Note       string `json:"note"`
}

type corpus struct {
	Vectors []vector `json:"vectors"`
}

func main() {
	raw, err := os.ReadFile("vectors/conformance-vectors.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, "run this from the repository root:", err)
		os.Exit(1)
	}
	var c corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		fmt.Fprintln(os.Stderr, "corpus unreadable:", err)
		os.Exit(1)
	}

	out := map[string]bool{}
	n := 0
	for _, v := range c.Vectors {
		if v.Kind != "ed25519-point-admission" {
			continue
		}
		msg, e1 := hex.DecodeString(v.MessageHex)
		pub, e2 := hex.DecodeString(v.AHex)
		sig, e3 := hex.DecodeString(v.SigHex)
		if e1 != nil || e2 != nil || e3 != nil {
			fmt.Fprintf(os.Stderr, "%s: unreadable hex\n", v.ID)
			os.Exit(1)
		}
		accepted := false
		// A length that the library would reject anyway is reported as `false` rather than as a panic: the
		// question here is what the PLATFORM accepts, and a crash answers nothing.
		if len(pub) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize {
			accepted = ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
		}
		out[v.ID] = accepted
		fmt.Printf("  %-22s %-5v  %s\n", v.ID, accepted, v.Note)
		n++
	}

	// A run over an empty selection would print a tidy nothing and exit zero — the same shape as a gate that
	// loads no build. Say so instead.
	if n == 0 {
		fmt.Fprintln(os.Stderr, "no `ed25519-point-admission` vectors found — measured nothing")
		os.Exit(1)
	}

	j, _ := json.Marshal(out)
	fmt.Printf("\n%s\n", j)
	fmt.Fprintf(os.Stderr, "\n  %d vector(s) · go %s\n", n, "crypto/ed25519 (standard library)")
}
