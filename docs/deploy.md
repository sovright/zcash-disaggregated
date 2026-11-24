# Deploying with `zd`

`zd` runs every role. Build it with `cargo build --release -p zd-node`
(the binary is `target/release/zd`), or use the `Dockerfile`.

Not audited. Use testnet or regtest.

## TLS

Every server and client takes the same global flags:

- `--cert`, `--key`: this process's certificate and key (used as server and
  as client identity).
- `--ca`: CA that peers must chain to. On a server this turns on mTLS.

Use `https://` URLs for TLS peers. Without these flags a server warns that it
is serving in the clear.

## 1. Key ceremony (FROST t of n)

Each participant, on their own machine:

```sh
zd identity keygen --instance member-1 --id 1 --out identity.toml > p1.toml
```

`identity.toml` is secret. Send `p1.toml` (public) to the organizer, who
writes the parameters every participant must use:

```sh
zd ceremony params --threshold 2 --network test --label treasury \
  --participant p1.toml --participant p2.toml --participant p3.toml \
  --out params.toml
zd ceremony relay --params params.toml --listen 0.0.0.0:7105
```

The relay holds no secrets; it sees signed broadcasts and sealed round 2
messages. Each participant checks the printed transcript id out of band, then:

```sh
zd ceremony join --relay https://relay:7105 --params params.toml \
  --identity identity.toml --me 1 --out keys/
```

This writes:

- `keys/account.toml`: UFVK, UIVK, internal IVK, `qk`, FROST public key
  package. Identical for every participant. Distribute to wallet state,
  detectors, the address service and the coordinator.
- `keys/frost-member.toml` (secret): this participant's key package.
- `keys/recovery.toml` (secret): the shared `sk` and `qsk` for ZIP 2005
  recovery. Store offline.

## 2. Signing

Each member runs `zd frost-member --key-package keys/frost-member.toml`. One
coordinator serves the `Signer` API to wallet state:

```sh
zd frost-coordinator --account account.toml \
  --member https://m1:7103 --member https://m2:7103 --member https://m3:7103
```

For a 1/1 account, `zd signer --account account.toml --signing-key signer.toml`,
where `signer.toml` holds `fingerprint` and the normalized `ask`.

## 3. Proving

`zd prover --concurrency 2`. Proving keys take a while to build at start.
Provers see the FVK and note data of each job, so run them inside the trust
boundary.

## 4. Wallet state

```sh
zd wallet add-account --db wallet.db --account account.toml --birthday 3500000
zd wallet serve --db wallet.db --network test \
  --lightwalletd https://lightwalletd.example:9067 \
  --prover https://prover:7101 --signer https://coordinator:7102
```

It serves `WalletIngest` (for detectors) and `Wallet` (for your systems) on
one port, default 7100. On start it rebuilds the commitment trees from the
earliest birthday, so notes become spendable once it has caught up.

## 5. Detectors and addresses

```sh
zd detector --lightwalletd https://lightwalletd.example:9067 \
  --wallet https://wallet:7100 --account account.toml \
  --state detector.height --from 3500000
zd address --server-id 1 --account account.toml --counters counters/
zd new-address --server https://address:7104 --account account.toml
```

`--account` and `--lightwalletd` can be repeated. One detector scans for all
its accounts; with several lightwalletd servers it fails over to the next on
any error, backing off up to a minute. Its position is saved in `--state`
after each batch, and it handles reorgs itself (see `docs/design.md`). Run
several detectors, ideally against different lightwalletd operators; wallet
state deduplicates. To add an account with an older birthday, run a detector
for it with its own `--state` and `--from`. Give each address server a
distinct `--server-id`.

## 6. Sending

```sh
zd wallet balance --wallet https://wallet:7100 --account account.toml
zd wallet send --wallet https://wallet:7100 --account account.toml \
  --to utest1... --amount 100000 --memo "invoice 42" --broadcast
```

Without `--broadcast`, the raw transaction is printed and the notes stay held
under its txid.
