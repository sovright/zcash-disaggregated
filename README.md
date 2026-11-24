# zcash-disaggregated

Libraries and network protocols for a Zcash shielded wallet split across
machines, for the Ironwood pool (NU6.3) and Orchard:

| Role | Holds | Redundancy |
| --- | --- | --- |
| Detector | UIVK | any 1 of n finds incoming notes |
| Address service | external UIVK | disjoint diversifier ranges, no coordination |
| Wallet state | UFVK, commitment trees, `qk` | builds PCZTs |
| Prover | per job: the PCZT (includes the FVK) | any 1 of n |
| Signer | `ask` (1/1 HSM) or a FROST share | 1/1 or t of n |

Spends travel as PCZTs ([ZIP 374](https://zips.z.cash/zip-0374)). Every key is
created on the [ZIP 2005](https://zips.z.cash/zip-2005) `use_qsk = true` path,
so FROST- and HSM-held funds stay quantum-recoverable.

Design notes: [docs/design.md](docs/design.md).

## Crates

- `zd-proto`: protobuf messages and gRPC services between roles
  (`crates/zd-proto/proto/zd/v1`). Compiled with `protox`, so no `protoc` is
  needed. Other languages (for example an Elixir coordinator) can use the
  `.proto` files directly.
- `zd-keys`: ZIP 2005 key derivation (`nk`, `qsk`, `qk`, `rivk_ext`), the
  commit-reveal ceremony for the shared `sk`, and FVK assembly from a FROST or
  HSM `ak`. Cross-checked against `orchard` 0.16.
- `zd-frost`, `zd-pczt`, `zd-detect`, `zd-address`: FROST RedPallas, the PCZT
  signer and prover roles, trial decryption, and address minting.
- `zd-services`: gRPC services for the prover, signers (1/1 and FROST),
  address service, detector daemon and key ceremony.
- `zd-wallet`: wallet state. Checks detector reports against the FVK, tracks
  spends, keeps the commitment trees, and builds and finishes sends.
- `zd-node`: the `zd` binary, one subcommand per role. See
  [docs/deploy.md](docs/deploy.md).

## Status

Early. Not audited. Do not use with mainnet funds.

## Build

```sh
cargo test --all
```
