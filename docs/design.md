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

## Known gap: RedPallas FROST ciphersuite

`reddsa` 0.6 (Sep 2026) removed its `frost` feature, and the ciphersuite has
not yet been published from the ZcashFoundation `frost` repository. The last
published `frost-core` (3.0.0) depends on `rand_core` 0.6, while `orchard`
0.16 uses `rand_core` 0.10. Step 3 therefore needs either the upstream
release or a local ciphersuite crate; it is the next piece of work.
