//! On-disk formats. Everything is TOML with hex for binary fields.
//!
//! Files holding secrets are written with mode 0600 and say so in their
//! header comment. In production, the 1/1 signer's `ask` and FROST key
//! packages belong in an HSM or KMS; these files are the interface for a
//! first deployment and for tests.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zcash_protocol::consensus::NetworkType;
use zd_proto::v1::{AccountRef, CeremonyParams, CeremonyParticipant, Network, Role, RoleIdentity};

pub fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let s = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&s).with_context(|| format!("parsing {}", path.display()))
}

/// Writes `contents` atomically (temp file, fsync, rename, fsync dir).
pub fn write_atomic(path: &Path, contents: &[u8], secret: bool) -> Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let tmp: PathBuf = dir.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("zd")
    ));
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        if secret {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        #[cfg(not(unix))]
        let _ = secret;
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

pub fn write<T: Serialize>(path: &Path, header: &str, value: &T, secret: bool) -> Result<()> {
    let body = toml::to_string_pretty(value)?;
    write_atomic(path, format!("{header}\n{body}").as_bytes(), secret)
}

pub fn unhex<const N: usize>(what: &str, s: &str) -> Result<[u8; N]> {
    hex::decode(s)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("{what} must be {N} bytes of hex"))
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum NetName {
    Main,
    Test,
    Regtest,
}

impl NetName {
    pub fn network_type(self) -> NetworkType {
        match self {
            NetName::Main => NetworkType::Main,
            NetName::Test => NetworkType::Test,
            NetName::Regtest => NetworkType::Regtest,
        }
    }
    pub fn proto(self) -> Network {
        match self {
            NetName::Main => Network::Mainnet,
            NetName::Test => Network::Testnet,
            NetName::Regtest => Network::Regtest,
        }
    }
}

/// `account.toml`: an account's public and viewing material. Not secret in
/// the cryptographic sense, but the UFVK reveals every transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountFile {
    pub network: NetName,
    pub label: String,
    /// BLAKE2b-256 fingerprint of the UFVK, the account's id on the wire.
    pub fingerprint: String,
    pub ufvk: String,
    pub uivk: String,
    /// 64-byte internal-scope IVK, for detectors.
    pub internal_ivk: String,
    /// ZIP 2005 `qk`.
    #[serde(default)]
    pub qk: String,
    /// FROST public key package, for the coordinator.
    #[serde(default)]
    pub public_key_package: String,
}

impl AccountFile {
    pub fn new(
        network: NetName,
        label: &str,
        fvk: &orchard::keys::FullViewingKey,
        qk: Option<[u8; 32]>,
        public_key_package: Option<Vec<u8>>,
    ) -> Self {
        let nt = network.network_type();
        let ufvk = zd_address::keys::ufvk(fvk, nt);
        AccountFile {
            network,
            label: label.into(),
            fingerprint: hex::encode(zd_address::keys::fingerprint(&ufvk)),
            uivk: zd_address::keys::uivk(fvk, nt),
            internal_ivk: hex::encode(fvk.to_ivk(orchard::keys::Scope::Internal).to_bytes()),
            qk: qk.map(hex::encode).unwrap_or_default(),
            public_key_package: public_key_package.map(hex::encode).unwrap_or_default(),
            ufvk,
        }
    }

    pub fn fingerprint(&self) -> Result<[u8; 32]> {
        let fp = unhex::<32>("fingerprint", &self.fingerprint)?;
        if !self.ufvk.is_empty() && zd_address::keys::fingerprint(&self.ufvk) != fp {
            bail!("account file fingerprint does not match its UFVK");
        }
        Ok(fp)
    }

    pub fn account_ref(&self) -> Result<AccountRef> {
        Ok(AccountRef {
            ufvk_fingerprint: self.fingerprint()?.to_vec(),
            network: self.network.proto() as i32,
        })
    }

    pub fn external_ivk(&self) -> Result<orchard::keys::IncomingViewingKey> {
        let (net, ivk) =
            zd_address::keys::parse_uivk(&self.uivk).ok_or_else(|| anyhow!("bad uivk"))?;
        if net != self.network.network_type() {
            bail!("uivk is for another network");
        }
        Ok(ivk)
    }

    pub fn internal_ivk(&self) -> Result<orchard::keys::IncomingViewingKey> {
        let b = hex::decode(&self.internal_ivk)
            .ok()
            .and_then(|b| <[u8; 64]>::try_from(b).ok())
            .ok_or_else(|| anyhow!("internal_ivk must be 64 bytes of hex"))?;
        Option::from(orchard::keys::IncomingViewingKey::from_bytes(&b))
            .ok_or_else(|| anyhow!("internal_ivk is not a valid IVK"))
    }

    pub fn qk(&self) -> Result<Option<[u8; 32]>> {
        if self.qk.is_empty() {
            Ok(None)
        } else {
            unhex::<32>("qk", &self.qk).map(Some)
        }
    }
}

pub const SECRET_HEADER: &str =
    "# SECRET. Anyone with this file can act as this key holder. Keep it at mode 0600.";

/// `frost-member.toml`: one member's FROST key package. Secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberFile {
    pub fingerprint: String,
    pub key_package: String,
}

/// `recovery.toml`: the shared ZIP 2005 secrets. Secret; offline storage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryFile {
    pub fingerprint: String,
    /// Shared spending secret: derives `nk` and `qsk`.
    pub sk: String,
    /// Quantum spending key, for post-quantum recovery.
    pub qsk: String,
}

/// `signer.toml`: a 1/1 signer's spend authorizing key. Secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignerKeyFile {
    pub fingerprint: String,
    /// `ask`, already normalized so that the y-coordinate of `ak` is even.
    pub ask: String,
}

/// `identity.toml`: a ceremony participant's long-lived keys. Secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityFile {
    pub instance: String,
    pub signing_key: String,
    pub encryption_key: String,
}

impl IdentityFile {
    pub fn from_identity(id: &zd_services::ceremony::Identity) -> Self {
        IdentityFile {
            instance: id.instance.clone(),
            signing_key: hex::encode(id.signing.to_bytes()),
            encryption_key: hex::encode(id.encryption.to_bytes()),
        }
    }

    pub fn identity(&self) -> Result<zd_services::ceremony::Identity> {
        Ok(zd_services::ceremony::Identity {
            signing: ed25519_dalek::SigningKey::from_bytes(&unhex::<32>(
                "signing_key",
                &self.signing_key,
            )?),
            encryption: x25519_dalek::StaticSecret::from(unhex::<32>(
                "encryption_key",
                &self.encryption_key,
            )?),
            instance: self.instance.clone(),
        })
    }
}

/// One `[[participant]]` entry of `params.toml`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParticipantEntry {
    pub id: u32,
    pub instance: String,
    /// Ed25519 public key.
    pub signing_key: String,
    /// X25519 public key.
    pub encryption_key: String,
}

impl ParticipantEntry {
    pub fn from_identity(id: u32, identity: &zd_services::ceremony::Identity) -> Self {
        ParticipantEntry {
            id,
            instance: identity.instance.clone(),
            signing_key: hex::encode(identity.signing.verifying_key().to_bytes()),
            encryption_key: hex::encode(identity.encryption_key()),
        }
    }
}

/// `params.toml`: what every ceremony participant agrees on out of band.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParamsFile {
    pub threshold: u32,
    pub network: NetName,
    pub label: String,
    /// 32 random bytes, so that two ceremonies never share a transcript.
    pub nonce: String,
    #[serde(rename = "participant")]
    pub participants: Vec<ParticipantEntry>,
}

impl ParamsFile {
    pub fn proto(&self) -> Result<CeremonyParams> {
        Ok(CeremonyParams {
            threshold: self.threshold,
            network: self.network.proto() as i32,
            account_label: self.label.clone(),
            nonce: unhex::<32>("nonce", &self.nonce)?.to_vec(),
            participants: self
                .participants
                .iter()
                .map(|p| {
                    Ok(CeremonyParticipant {
                        id: p.id,
                        identity: Some(RoleIdentity {
                            role: Role::CeremonyParticipant as i32,
                            public_key: unhex::<32>("signing_key", &p.signing_key)?.to_vec(),
                            instance: p.instance.clone(),
                        }),
                        encryption_key: unhex::<32>("encryption_key", &p.encryption_key)?.to_vec(),
                    })
                })
                .collect::<Result<_>>()?,
        })
    }
}

/// A detector's saved position.
#[derive(Debug, Serialize, Deserialize)]
struct CursorFile {
    next: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prev_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reorg_epoch: Option<u64>,
}

/// Reads a detector cursor, if the file exists. A bare decimal height (the
/// earlier format) is accepted too.
pub fn read_cursor(path: &Path) -> Result<Option<zd_services::detector::Cursor>> {
    let s = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if let Ok(next) = s.trim().parse::<u64>() {
        return Ok(Some(zd_services::detector::Cursor::starting_at(next)));
    }
    let f: CursorFile =
        toml::from_str(&s).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(zd_services::detector::Cursor {
        next: f.next,
        prev_hash: f
            .prev_hash
            .map(|h| hex::decode(h).context("prev_hash hex"))
            .transpose()?,
        reorg_epoch: f.reorg_epoch,
    }))
}

/// Saves a detector cursor atomically.
pub fn write_cursor(path: &Path, c: &zd_services::detector::Cursor) -> Result<()> {
    let f = CursorFile {
        next: c.next,
        prev_hash: c.prev_hash.as_ref().map(hex::encode),
        reorg_epoch: c.reorg_epoch,
    };
    write_atomic(path, toml::to_string(&f)?.as_bytes(), false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zd_services::detector::Cursor;

    #[test]
    fn cursor_round_trips_and_reads_old_format() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("detector.state");
        assert_eq!(read_cursor(&p).unwrap(), None);

        std::fs::write(&p, "3500000\n").unwrap();
        assert_eq!(
            read_cursor(&p).unwrap(),
            Some(Cursor::starting_at(3_500_000))
        );

        let c = Cursor {
            next: 3_500_100,
            prev_hash: Some(vec![7; 32]),
            reorg_epoch: Some(4),
        };
        write_cursor(&p, &c).unwrap();
        assert_eq!(read_cursor(&p).unwrap(), Some(c));
        write_cursor(&p, &Cursor::starting_at(9)).unwrap();
        assert_eq!(read_cursor(&p).unwrap(), Some(Cursor::starting_at(9)));
    }
}
