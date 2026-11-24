//! The t-of-n key ceremony: a FROST DKG for `ask` run alongside the
//! commit-reveal shared `sk`, producing a ZIP 2005 quantum-recoverable account.
//!
//! The two protocols share rounds, so the whole ceremony is two message rounds
//! plus a confirmation:
//!
//! | Round | Sent                                              | Channel                  |
//! |-------|---------------------------------------------------|--------------------------|
//! | 1     | `sk` commitment + DKG round 1 package             | broadcast                |
//! | 2     | `sk` contribution + DKG round 2 package           | point to point, confidential |
//! | 3     | `fvk_hash` of the derived account                 | broadcast                |
//!
//! Every participant reveals its `sk` contribution only after receiving every
//! commitment, so no one can choose `sk`. Reveals must travel on the same
//! confidential channels as DKG round 2 packages: anyone who sees all of them
//! learns `sk`, and with it `nk` and `qsk`.
//!
//! The DKG's post-processing hook already negates the group key and every
//! share when ỹ(ak) = 1, so the resulting `ak` is a valid Orchard spend
//! validating key.

use std::collections::{BTreeMap, BTreeSet};

use rand_core::{CryptoRng, RngCore};
use zd_keys::{AccountKeys, Qsk, ceremony::SharedSk};
use zeroize::Zeroizing;

use crate::{
    Error, Identifier,
    keys::{
        KeyPackage, PublicKeyPackage,
        dkg::{self, round1, round2},
    },
};

/// Why the ceremony stopped. Any error means the ceremony must be restarted
/// with a fresh transcript.
#[derive(Debug, thiserror::Error)]
pub enum CeremonyError {
    /// The parameters are inconsistent (threshold, ids, or `me`).
    #[error("invalid ceremony parameters: {0}")]
    InvalidParams(&'static str),
    /// A message from this participant is missing.
    #[error("missing message from participant {0}")]
    Missing(u16),
    /// A message came from someone who is not a participant (or from ourselves).
    #[error("unexpected message from participant {0}")]
    Unexpected(u16),
    /// Commit-reveal of `sk` failed (a reveal did not match its commitment).
    #[error(transparent)]
    SharedSk(#[from] zd_keys::ceremony::CeremonyError),
    /// The FROST DKG failed (bad proof of knowledge, bad share, ...).
    #[error(transparent)]
    Dkg(#[from] Error),
    /// The derived account is invalid.
    #[error(transparent)]
    Account(#[from] zd_keys::Error),
    /// A participant derived a different account.
    #[error("participant {0} derived a different account")]
    ConfirmationMismatch(u16),
}

/// Ceremony parameters, identical at every participant.
#[derive(Clone, Debug)]
pub struct CeremonyConfig {
    /// `zd_keys::ceremony::transcript_id` of the encoded `CeremonyParams`.
    pub transcript_id: [u8; 32],
    /// Signers needed to authorize a spend.
    pub threshold: u16,
    /// Every participant's FROST identifier (nonzero, distinct).
    pub participants: Vec<u16>,
    /// This participant's identifier.
    pub me: u16,
}

impl CeremonyConfig {
    fn validate(&self) -> Result<BTreeSet<u16>, CeremonyError> {
        let ids: BTreeSet<u16> = self.participants.iter().copied().collect();
        if ids.len() != self.participants.len() {
            return Err(CeremonyError::InvalidParams("duplicate participant id"));
        }
        if ids.contains(&0) {
            return Err(CeremonyError::InvalidParams("participant id 0"));
        }
        if !ids.contains(&self.me) {
            return Err(CeremonyError::InvalidParams("me is not a participant"));
        }
        if self.threshold < 2 || usize::from(self.threshold) > ids.len() {
            return Err(CeremonyError::InvalidParams("need 2 <= threshold <= n"));
        }
        Ok(ids)
    }

    fn others(&self) -> impl Iterator<Item = u16> + '_ {
        self.participants.iter().copied().filter(|i| *i != self.me)
    }
}

fn ident(id: u16) -> Identifier {
    Identifier::try_from(id).expect("validated nonzero")
}

/// Round 1 broadcast: commitment to our `sk` contribution and the DKG round 1
/// package.
#[derive(Clone, Debug)]
pub struct Round1Broadcast {
    /// `zd_keys::ceremony::commit(transcript_id, me, contribution)`.
    pub sk_commit: [u8; 32],
    /// DKG round 1 package (commitments and proof of knowledge).
    pub dkg: round1::Package,
}

/// Round 2 message to one recipient. Must be sent confidentially.
#[derive(Clone, Debug)]
pub struct Round2Message {
    /// Our `sk` contribution (the same for every recipient).
    pub sk_reveal: [u8; 32],
    /// The DKG round 2 package for this recipient.
    pub dkg: round2::Package,
}

/// State kept between round 1 and round 2. Never sent.
pub struct Round1State {
    config: CeremonyConfig,
    contribution: Zeroizing<[u8; 32]>,
    sk_commit: [u8; 32],
    dkg_secret: round1::SecretPackage,
}

/// State kept between round 2 and the end. Never sent.
pub struct Round2State {
    config: CeremonyConfig,
    contribution: Zeroizing<[u8; 32]>,
    sk_commits: BTreeMap<u32, [u8; 32]>,
    dkg_round1: BTreeMap<Identifier, round1::Package>,
    dkg_secret: round2::SecretPackage,
}

/// Starts the ceremony: picks our `sk` contribution and runs DKG part 1.
pub fn start<R: RngCore + CryptoRng>(
    config: CeremonyConfig,
    rng: &mut R,
) -> Result<(Round1State, Round1Broadcast), CeremonyError> {
    let ids = config.validate()?;
    let n = u16::try_from(ids.len()).map_err(|_| CeremonyError::InvalidParams("too many"))?;

    let mut contribution = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(contribution.as_mut());
    let sk_commit =
        zd_keys::ceremony::commit(&config.transcript_id, config.me.into(), &contribution);

    let (dkg_secret, dkg) = dkg::part1(ident(config.me), n, config.threshold, rng)?;

    Ok((
        Round1State {
            config,
            contribution,
            sk_commit,
            dkg_secret,
        },
        Round1Broadcast { sk_commit, dkg },
    ))
}

fn check_senders<T>(config: &CeremonyConfig, msgs: &BTreeMap<u16, T>) -> Result<(), CeremonyError> {
    for id in msgs.keys() {
        if *id == config.me || !config.participants.contains(id) {
            return Err(CeremonyError::Unexpected(*id));
        }
    }
    for id in config.others() {
        if !msgs.contains_key(&id) {
            return Err(CeremonyError::Missing(id));
        }
    }
    Ok(())
}

impl Round1State {
    /// Takes every other participant's round 1 broadcast and returns one
    /// round 2 message per recipient.
    pub fn round2(
        self,
        received: &BTreeMap<u16, Round1Broadcast>,
    ) -> Result<(Round2State, BTreeMap<u16, Round2Message>), CeremonyError> {
        check_senders(&self.config, received)?;

        let mut sk_commits: BTreeMap<u32, [u8; 32]> = received
            .iter()
            .map(|(id, m)| (u32::from(*id), m.sk_commit))
            .collect();
        sk_commits.insert(self.config.me.into(), self.sk_commit);

        let dkg_round1: BTreeMap<Identifier, round1::Package> = received
            .iter()
            .map(|(id, m)| (ident(*id), m.dkg.clone()))
            .collect();
        let (dkg_secret, mut dkg_out) = dkg::part2(self.dkg_secret, &dkg_round1)?;

        let mut out = BTreeMap::new();
        for id in self.config.others() {
            let dkg = dkg_out
                .remove(&ident(id))
                .ok_or(CeremonyError::Missing(id))?;
            out.insert(
                id,
                Round2Message {
                    sk_reveal: *self.contribution,
                    dkg,
                },
            );
        }

        Ok((
            Round2State {
                config: self.config,
                contribution: self.contribution,
                sk_commits,
                dkg_round1,
                dkg_secret,
            },
            out,
        ))
    }
}

impl Round2State {
    /// Takes the round 2 message every other participant sent us, and derives
    /// our key share and the account.
    pub fn finish(
        self,
        received: &BTreeMap<u16, Round2Message>,
    ) -> Result<ParticipantKeys, CeremonyError> {
        check_senders(&self.config, received)?;

        let mut reveals: BTreeMap<u32, [u8; 32]> = received
            .iter()
            .map(|(id, m)| (u32::from(*id), m.sk_reveal))
            .collect();
        reveals.insert(self.config.me.into(), *self.contribution);
        let participants: Vec<u32> = self
            .config
            .participants
            .iter()
            .map(|i| (*i).into())
            .collect();
        let sk = zd_keys::ceremony::combine(
            &self.config.transcript_id,
            &participants,
            &self.sk_commits,
            &reveals,
        );
        for r in reveals.values_mut() {
            zeroize::Zeroize::zeroize(r);
        }
        let sk = sk?;

        let dkg_round2: BTreeMap<Identifier, round2::Package> = received
            .iter()
            .map(|(id, m)| (ident(*id), m.dkg.clone()))
            .collect();
        let (key_package, public_key_package) =
            dkg::part3(&self.dkg_secret, &self.dkg_round1, &dkg_round2)?;

        let ak: [u8; 32] = public_key_package
            .verifying_key()
            .serialize()?
            .try_into()
            .expect("Pallas points are 32 bytes");
        let (account, qsk) = AccountKeys::derive(sk.as_bytes(), ak)?;

        Ok(ParticipantKeys {
            transcript_id: self.config.transcript_id,
            key_package,
            public_key_package,
            sk,
            qsk,
            account,
        })
    }
}

/// What one participant holds after the ceremony.
///
/// Back up `key_package`, `sk` and `public_key_package`; `qsk` and the
/// account are re-derivable from them. Per ZIP 2005, `qsk` (and therefore
/// `sk`) must be stored at least as securely as the `ask` share.
pub struct ParticipantKeys {
    transcript_id: [u8; 32],
    key_package: KeyPackage,
    public_key_package: PublicKeyPackage,
    sk: SharedSk,
    qsk: Qsk,
    account: AccountKeys,
}

impl ParticipantKeys {
    /// The ceremony transcript these keys came from.
    pub fn transcript_id(&self) -> &[u8; 32] {
        &self.transcript_id
    }
    /// This participant's FROST key share.
    pub fn key_package(&self) -> &KeyPackage {
        &self.key_package
    }
    /// The group key (`ak`) and every participant's verifying share.
    pub fn public_key_package(&self) -> &PublicKeyPackage {
        &self.public_key_package
    }
    /// The shared `sk` (yields `nk` and `qsk`, never `ask`).
    pub fn sk(&self) -> &SharedSk {
        &self.sk
    }
    /// The ZIP 2005 quantum spending key.
    pub fn qsk(&self) -> &Qsk {
        &self.qsk
    }
    /// The account's public-side keys and FVK.
    pub fn account(&self) -> &AccountKeys {
        &self.account
    }
    /// The value to broadcast in the confirmation round.
    pub fn fvk_hash(&self) -> [u8; 32] {
        self.account.fvk_hash()
    }

    /// Checks every other participant's confirmation against ours. Only
    /// export the account after this passes for all participants.
    pub fn check_confirmations(
        &self,
        participants: &[u16],
        me: u16,
        received: &BTreeMap<u16, [u8; 32]>,
    ) -> Result<(), CeremonyError> {
        let mine = self.fvk_hash();
        for id in participants.iter().copied().filter(|i| *i != me) {
            let theirs = received.get(&id).ok_or(CeremonyError::Missing(id))?;
            if *theirs != mine {
                return Err(CeremonyError::ConfirmationMismatch(id));
            }
        }
        for id in received.keys() {
            if *id == me || !participants.contains(id) {
                return Err(CeremonyError::Unexpected(*id));
            }
        }
        Ok(())
    }
}
