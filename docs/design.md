# Design notes

The full design document (survey of librustzcash, orchard, PCZT and FROST;
leakage analysis; plan) lives outside the repo. This file records the
decisions the code depends on.

## Decisions

- **Pool.** Ironwood (NU6.3) is the target. It shares Orchard's keys,
  addresses and circuit (`orchard::ValuePool::Ironwood`) but has its own tree,
  nullifier set and quantum-recoverable note format (ZIP 2005).
- **Transaction format.** PCZT (ZIP 374) carries every spend. In v6
  transactions the anchor is outside the sighash, so signers can sign before a
  prover picks the anchor.
- **Keys.** Always ZIP 2005 `use_qsk = true`. Non-recoverable keys are never
  created.
- **Wire protocol.** Protobuf + gRPC in `zd-proto`, so an Elixir coordinator
  can be added later.
- **Trust.** Provers receive the account FVK inside each PCZT (ZIP 374 Privacy
  Implications), so they run inside the customer's trust boundary.

## Key ceremony (FROST t of n)

1. Agree `CeremonyParams` (t, n, ids, network, label); transcript id =
   BLAKE2b-256 of the encoding.
2. Shared `sk` by commit-reveal (`zd_keys::ceremony`).
3. FROST DKG over RedPallas. If ỹ(ak) = 1, every participant negates its
   share and the group key.
4. Derive `nk`, `qsk`, `qk`, `rivk_ext` and the FVK (`zd_keys::AccountKeys`).
5. Broadcast `fvk_hash`; the quorum signs the transcript as a test.
6. `AccountExport` (UFVK, `qk`) to wallet state; `ViewingExport` (UIVK) to
   detectors and address services.
7. Each participant backs up its share, `sk`, `ak`, and `use_qsk = true`.

## RedPallas FROST (`zd-frost`)

`reddsa` 0.6 (Sep 2026) removed its `frost` feature, and the ciphersuite has
not yet been published from the ZcashFoundation `frost` repository (#963).
`zd-frost` carries a port of the `reddsa` 0.5.2 ciphersuite onto
`pasta_curves` 0.6 with every upstream constant unchanged; a test checks that
keys, commitments, shares and signatures are byte-identical to `reddsa` 0.5.2,
so we can switch to the upstream crate without migrating key material.
`frost-core` 3.0 still uses `rand_core` 0.6, so only the 0.6 RNG traits appear
in `zd-frost`'s API.

**Fixed randomizer.** A PCZT fixes `alpha` (and so `rk`) per spend before
signing. `frost-rerandomized` 3.0 only supports a caller-chosen randomizer
through a deprecated function (frost #1094), because a coordinator that picks
the randomizer after seeing commitments gains power. `zd_frost::spend` instead
binds each signer's nonces to `(sighash, alpha)` from a PCZT it has already
checked, and refuses a signing package for any other message, so `alpha` is
fixed before any commitment exists. One signing run per Orchard spend.

**Ceremony.** `zd_frost::ceremony` merges the `sk` commit-reveal with the DKG:
round 1 broadcasts the `sk` commitment and DKG round 1 package; round 2 sends
the `sk` reveal and DKG round 2 package point to point over confidential
channels (anyone who sees every reveal learns `sk`, hence `nk` and `qsk`);
then each participant derives the account and broadcasts `fvk_hash`.

## PCZT roles (`zd-pczt`)

- A signer finds its spends by `rk == ak + [alpha] G`, not by trusting the
  `fvk` field; a spend whose `fvk` names the account but whose `rk` does not
  match is rejected, as is any PCZT that still carries `dummy_sk`.
- Signing and proving run in parallel on the same PCZT; signatures are applied
  to the proved PCZT (the sighash does not cover proofs or, in v6, the anchor).
- FROST signs every spend of a transaction in the same two rounds, one
  `zd_frost::spend` session per spend.
- Policy checks (Verifier role: outputs, values, recipients) stay with the
  signer service and must run before round 1.

## Detectors (`zd-detect`) and address servers (`zd-address`)

- Detectors hold the external and internal IVKs only. They trial-decrypt
  lightwalletd compact actions in both pools (Ironwood with the v3 note
  domain, Orchard with v2), report each opened note with its commitment tree
  position, and forward every nullifier, since an IVK cannot compute
  nullifiers. Memos are not in compact actions; wallet state fetches the full
  transaction when it needs one.
- Address servers hold the external IVK. Server `i` owns diversifier indices
  whose top byte is `i` (2^80 each) and must persist its counter. Addresses
  are revision 0 unified addresses (`u1...`) with a single Orchard receiver,
  the form deployed wallets parse today.

## FROST signer service (`zd_services::frost`)

Chosen 2026-11-24: FROST rounds use our own gRPC (`FrostParticipant` in
`spend.proto`), not frostd, so every role speaks one protocol.

- Wallet state calls the account's `Signer` (the coordinator) exactly as for
  a 1/1 signer.
- Round 1 (`Commit`) goes to every member with the redacted PCZT. Each member
  finds its spends, runs its own policy, and only then creates nonces bound to
  the sighash and each spend's alpha. It returns one commitment per spend and
  a digest of the sighash so the coordinator can detect disagreement.
- The coordinator keeps the first `threshold` members by identifier, tells
  the others to drop their nonces, and runs round 2 (`Sign`) with exactly
  those. A member's nonces for a job are consumed by its first `Sign`,
  whatever the outcome; a second `Commit` for the same job is refused.
- The coordinator holds no secrets. It can deny service but cannot get a
  signature over a PCZT a member's policy rejected.
