//! The key ceremony over gRPC: a relay that routes messages, and the
//! participant side that runs `zd_frost::ceremony` through it.
//!
//! The relay is trusted only to deliver messages. Every message is a
//! [`SignedEnvelope`] signed by a participant's Ed25519 key from
//! `CeremonyParams`, which every participant receives out of band and checks
//! before starting. Round 2 (the `sk` reveal and the DKG share for one
//! recipient) is sealed to the recipient's X25519 key, because whoever reads
//! every round 2 message learns `sk` and enough shares to rebuild `ask`.
//!
//! Sealing: an ephemeral X25519 key agreement with the recipient's key,
//! BLAKE2b-256 key derivation bound to the transcript, both public keys and
//! both participant ids, then ChaCha20-Poly1305. The envelope signature
//! authenticates the sender.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
use ed25519_dalek::{Signer as _, Verifier as _};
use prost::Message;
use rand_core_06::OsRng;
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::transport::Channel;
use tonic::{Request, Response, Status, Streaming};
use zd_frost::ceremony::{
    self as dkg, CeremonyConfig, ParticipantKeys, Round1Broadcast, Round2Message,
};
use zd_frost::keys::dkg::{round1, round2};
use zd_proto::v1::{
    CeremonyMessage, CeremonyParams, CeremonyRound1, CeremonyRound2Plaintext, CeremonySealedRound2,
    FvkConfirmation, Role, RoleIdentity, SignedEnvelope, ceremony_message::Body,
    key_ceremony_client::KeyCeremonyClient, key_ceremony_server::KeyCeremony,
};

/// `type_url` of every ceremony envelope.
pub const TYPE_URL: &str = "zd.v1.CeremonyMessage";

/// Ceremony failures. Any of them means starting over with fresh params.
#[derive(Debug, thiserror::Error)]
pub enum CeremonyServiceError {
    /// Params are malformed or do not name this participant's keys.
    #[error("bad params: {0}")]
    Params(String),
    /// A message failed signature, decoding or routing checks.
    #[error("bad message: {0}")]
    Message(String),
    /// A participant aborted.
    #[error("participant {0} aborted: {1}")]
    Aborted(u32, String),
    /// The relay connection failed.
    #[error("relay: {0}")]
    Relay(String),
    /// The ceremony itself failed.
    #[error(transparent)]
    Ceremony(#[from] dkg::CeremonyError),
}

type E = CeremonyServiceError;

/// A participant's long-lived keys.
pub struct Identity {
    /// Signs every message.
    pub signing: ed25519_dalek::SigningKey,
    /// Opens round 2 messages sealed to this participant.
    pub encryption: x25519_dalek::StaticSecret,
    /// Instance name, for `RoleIdentity`.
    pub instance: String,
}

impl Identity {
    /// Fresh random keys.
    pub fn generate(instance: impl Into<String>) -> Self {
        Identity {
            signing: ed25519_dalek::SigningKey::generate(&mut OsRng),
            encryption: x25519_dalek::StaticSecret::random_from_rng(OsRng),
            instance: instance.into(),
        }
    }

    /// The `RoleIdentity` to list in `CeremonyParams`.
    pub fn role_identity(&self) -> RoleIdentity {
        RoleIdentity {
            role: Role::CeremonyParticipant as i32,
            public_key: self.signing.verifying_key().to_bytes().to_vec(),
            instance: self.instance.clone(),
        }
    }

    /// The X25519 key to list in `CeremonyParams`.
    pub fn encryption_key(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.encryption).to_bytes()
    }
}

/// Transcript id of a parameter set.
pub fn transcript_id(params: &CeremonyParams) -> [u8; 32] {
    zd_keys::ceremony::transcript_id(&params.encode_to_vec())
}

fn signed_bytes(type_url: &str, payload: &[u8]) -> Vec<u8> {
    let mut m = b"zd.v1.SignedEnvelope".to_vec();
    m.extend_from_slice(&(type_url.len() as u32).to_le_bytes());
    m.extend_from_slice(type_url.as_bytes());
    m.extend_from_slice(payload);
    m
}

/// Signs a ceremony message.
pub fn seal_envelope(identity: &Identity, msg: &CeremonyMessage) -> SignedEnvelope {
    let payload = msg.encode_to_vec();
    let signature = identity.signing.sign(&signed_bytes(TYPE_URL, &payload));
    SignedEnvelope {
        type_url: TYPE_URL.into(),
        payload,
        sender: Some(identity.role_identity()),
        signature: signature.to_bytes().to_vec(),
        sent_at_unix_ms: 0,
    }
}

/// Verifies an envelope against `params` and returns the sender's id and the
/// message.
pub fn open_envelope(
    env: &SignedEnvelope,
    params: &CeremonyParams,
) -> Result<(u32, CeremonyMessage), CeremonyServiceError> {
    if env.type_url != TYPE_URL {
        return Err(E::Message(format!("unexpected type {}", env.type_url)));
    }
    let key = env
        .sender
        .as_ref()
        .map(|s| s.public_key.as_slice())
        .ok_or_else(|| E::Message("no sender".into()))?;
    let p = params
        .participants
        .iter()
        .find(|p| p.identity.as_ref().map(|i| i.public_key.as_slice()) == Some(key))
        .ok_or_else(|| E::Message("sender is not a participant".into()))?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(
        key.try_into()
            .map_err(|_| E::Message("bad sender key".into()))?,
    )
    .map_err(|_| E::Message("bad sender key".into()))?;
    let sig = ed25519_dalek::Signature::from_slice(&env.signature)
        .map_err(|_| E::Message("bad signature encoding".into()))?;
    vk.verify(&signed_bytes(&env.type_url, &env.payload), &sig)
        .map_err(|_| E::Message(format!("bad signature from participant {}", p.id)))?;
    let msg = CeremonyMessage::decode(env.payload.as_slice())
        .map_err(|e| E::Message(format!("decode: {e}")))?;
    Ok((p.id, msg))
}

fn seal_key(
    shared: &[u8; 32],
    eph: &[u8; 32],
    recipient_key: &[u8; 32],
    transcript: &[u8],
    sender: u32,
    recipient: u32,
) -> zeroize::Zeroizing<[u8; 32]> {
    let mut h = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"ZDisagg_SealKey_")
        .to_state();
    h.update(shared)
        .update(eph)
        .update(recipient_key)
        .update(transcript)
        .update(&sender.to_le_bytes())
        .update(&recipient.to_le_bytes());
    let mut k = zeroize::Zeroizing::new([0u8; 32]);
    k.copy_from_slice(h.finalize().as_bytes());
    k
}

fn aad(transcript: &[u8], sender: u32, recipient: u32) -> Vec<u8> {
    let mut a = transcript.to_vec();
    a.extend_from_slice(&sender.to_le_bytes());
    a.extend_from_slice(&recipient.to_le_bytes());
    a
}

/// Seals a round 2 plaintext to `recipient_key`.
pub fn seal_round2(
    transcript: &[u8; 32],
    sender: u32,
    recipient: u32,
    recipient_key: &[u8; 32],
    plaintext: &CeremonyRound2Plaintext,
) -> CeremonySealedRound2 {
    let eph = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = x25519_dalek::PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&x25519_dalek::PublicKey::from(*recipient_key));
    let key = seal_key(
        shared.as_bytes(),
        &eph_pub,
        recipient_key,
        transcript,
        sender,
        recipient,
    );
    let cipher = ChaCha20Poly1305::new(key.as_ref().into());
    let pt = zeroize::Zeroizing::new(plaintext.encode_to_vec());
    // Each key is used once (fresh ephemeral), so a zero nonce is safe.
    let ciphertext = cipher
        .encrypt(
            &[0u8; 12].into(),
            chacha20poly1305::aead::Payload {
                msg: &pt,
                aad: &aad(transcript, sender, recipient),
            },
        )
        .expect("encryption cannot fail");
    CeremonySealedRound2 {
        transcript_id: transcript.to_vec(),
        sender,
        recipient,
        ephemeral_key: eph_pub.to_vec(),
        ciphertext,
    }
}

/// Opens a round 2 message sealed to `identity`.
pub fn open_round2(
    identity: &Identity,
    sealed: &CeremonySealedRound2,
) -> Result<CeremonyRound2Plaintext, CeremonyServiceError> {
    let eph: [u8; 32] = sealed
        .ephemeral_key
        .as_slice()
        .try_into()
        .map_err(|_| E::Message("bad ephemeral key".into()))?;
    let shared = identity
        .encryption
        .diffie_hellman(&x25519_dalek::PublicKey::from(eph));
    let key = seal_key(
        shared.as_bytes(),
        &eph,
        &identity.encryption_key(),
        &sealed.transcript_id,
        sealed.sender,
        sealed.recipient,
    );
    let cipher = ChaCha20Poly1305::new(key.as_ref().into());
    let pt = zeroize::Zeroizing::new(
        cipher
            .decrypt(
                &[0u8; 12].into(),
                chacha20poly1305::aead::Payload {
                    msg: &sealed.ciphertext,
                    aad: &aad(&sealed.transcript_id, sealed.sender, sealed.recipient),
                },
            )
            .map_err(|_| E::Message(format!("cannot open round 2 from {}", sealed.sender)))?,
    );
    CeremonyRound2Plaintext::decode(pt.as_slice()).map_err(|e| E::Message(format!("decode: {e}")))
}

fn validate_params(params: &CeremonyParams) -> Result<Vec<u16>, CeremonyServiceError> {
    let mut ids = Vec::new();
    for p in &params.participants {
        let id = u16::try_from(p.id)
            .ok()
            .filter(|i| *i != 0)
            .ok_or_else(|| E::Params(format!("participant id {} out of range", p.id)))?;
        if p.encryption_key.len() != 32
            || p.identity.as_ref().map(|i| i.public_key.len()) != Some(32)
        {
            return Err(E::Params(format!("participant {id} has malformed keys")));
        }
        ids.push(id);
    }
    if params.nonce.len() != 32 {
        return Err(E::Params("nonce must be 32 bytes".into()));
    }
    Ok(ids)
}

// ---------------------------------------------------------------------------
// Relay
// ---------------------------------------------------------------------------

type Outbox = mpsc::UnboundedSender<Result<SignedEnvelope, Status>>;

#[derive(Default)]
struct RelayState {
    outboxes: HashMap<u32, Outbox>,
    backlog: HashMap<u32, Vec<SignedEnvelope>>,
}

impl RelayState {
    fn deliver(&mut self, to: u32, env: SignedEnvelope) {
        match self.outboxes.get(&to) {
            Some(tx) if !tx.is_closed() => {
                let _ = tx.send(Ok(env));
            }
            _ => self.backlog.entry(to).or_default().push(env),
        }
    }
}

/// Routes one ceremony's messages. Holds no secrets and sees only signed
/// broadcasts and sealed round 2 messages.
pub struct CeremonyRelay {
    params: CeremonyParams,
    state: Arc<Mutex<RelayState>>,
}

impl CeremonyRelay {
    /// A relay for one ceremony.
    pub fn new(params: CeremonyParams) -> Result<Self, CeremonyServiceError> {
        validate_params(&params)?;
        Ok(CeremonyRelay {
            params,
            state: Arc::default(),
        })
    }
}

#[tonic::async_trait]
impl KeyCeremony for CeremonyRelay {
    type ExchangeStream = UnboundedReceiverStream<Result<SignedEnvelope, Status>>;

    async fn exchange(
        &self,
        request: Request<Streaming<SignedEnvelope>>,
    ) -> Result<Response<Self::ExchangeStream>, Status> {
        let mut inbound = request.into_inner();
        let hello = inbound
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("expected signed params first"))?;
        let (me, msg) = open_envelope(&hello, &self.params)
            .map_err(|e| Status::permission_denied(e.to_string()))?;
        if msg.body != Some(Body::Params(self.params.clone())) {
            return Err(Status::failed_precondition(
                "participant has different params",
            ));
        }

        let (tx, rx) = mpsc::unbounded_channel();
        {
            let mut st = self.state.lock().unwrap();
            for env in st.backlog.remove(&me).unwrap_or_default() {
                let _ = tx.send(Ok(env));
            }
            st.outboxes.insert(me, tx);
        }

        let params = self.params.clone();
        let state = self.state.clone();
        tokio::spawn(async move {
            while let Ok(Some(env)) = inbound.message().await {
                let Ok((sender, msg)) = open_envelope(&env, &params) else {
                    continue;
                };
                if sender != me {
                    continue;
                }
                let mut st = state.lock().unwrap();
                match msg.body {
                    Some(Body::SealedRound2(s)) => {
                        if s.sender == me && params.participants.iter().any(|p| p.id == s.recipient)
                        {
                            st.deliver(s.recipient, env);
                        }
                    }
                    Some(Body::Round1(_) | Body::Confirmation(_) | Body::AbortReason(_)) => {
                        for p in params.participants.iter().filter(|p| p.id != me) {
                            st.deliver(p.id, env.clone());
                        }
                    }
                    _ => {}
                }
            }
        });
        Ok(Response::new(UnboundedReceiverStream::new(rx)))
    }
}

// ---------------------------------------------------------------------------
// Participant
// ---------------------------------------------------------------------------

/// Runs the ceremony as participant `me` through a relay. `params` must be
/// the parameter set every participant agreed on out of band.
pub async fn run_participant(
    mut relay: KeyCeremonyClient<Channel>,
    params: CeremonyParams,
    me: u32,
    identity: &Identity,
) -> Result<ParticipantKeys, CeremonyServiceError> {
    let ids = validate_params(&params)?;
    let mine = params
        .participants
        .iter()
        .find(|p| p.id == me)
        .ok_or_else(|| E::Params("me is not a participant".into()))?;
    if mine.identity.as_ref().map(|i| i.public_key.clone())
        != Some(identity.signing.verifying_key().to_bytes().to_vec())
        || mine.encryption_key != identity.encryption_key()
    {
        return Err(E::Params("params list different keys for me".into()));
    }
    let enc_keys: HashMap<u32, [u8; 32]> = params
        .participants
        .iter()
        .map(|p| {
            (
                p.id,
                p.encryption_key.as_slice().try_into().expect("validated"),
            )
        })
        .collect();
    let tid = transcript_id(&params);
    let config = CeremonyConfig {
        transcript_id: tid,
        threshold: u16::try_from(params.threshold)
            .map_err(|_| E::Params("threshold out of range".into()))?,
        participants: ids.clone(),
        me: u16::try_from(me).map_err(|_| E::Params("id out of range".into()))?,
    };

    let (tx, rx) = mpsc::unbounded_channel();
    let send = |body: Body| {
        let _ = tx.send(seal_envelope(
            identity,
            &CeremonyMessage { body: Some(body) },
        ));
    };
    send(Body::Params(params.clone()));
    let mut inbound = relay
        .exchange(UnboundedReceiverStream::new(rx))
        .await
        .map_err(|e| E::Relay(e.message().into()))?
        .into_inner();

    // Round 1.
    let (state1, b1) = dkg::start(config.clone(), &mut OsRng)?;
    send(Body::Round1(CeremonyRound1 {
        transcript_id: tid.to_vec(),
        participant: me,
        sk_commit: b1.sk_commit.to_vec(),
        dkg_package: b1
            .dkg
            .serialize()
            .map_err(|e| E::Message(format!("serialize: {e}")))?,
    }));

    let mut state1 = Some(state1);
    let mut state2 = None;
    let mut keys: Option<ParticipantKeys> = None;
    let mut r1: BTreeMap<u16, Round1Broadcast> = BTreeMap::new();
    let mut r2: BTreeMap<u16, Round2Message> = BTreeMap::new();
    let mut confs: BTreeMap<u16, [u8; 32]> = BTreeMap::new();
    let n_others = ids.len() - 1;
    let tid_ok = |t: &[u8]| t == tid.as_slice();

    loop {
        // Advance whatever phase is complete.
        if r1.len() == n_others
            && let Some(s1) = state1.take()
        {
            let (s2, out) = s1.round2(&r1)?;
            for (to, m) in out {
                let pt = CeremonyRound2Plaintext {
                    sk_reveal: m.sk_reveal.to_vec(),
                    dkg_package: m
                        .dkg
                        .serialize()
                        .map_err(|e| E::Message(format!("serialize: {e}")))?,
                };
                let to = u32::from(to);
                send(Body::SealedRound2(seal_round2(
                    &tid,
                    me,
                    to,
                    &enc_keys[&to],
                    &pt,
                )));
            }
            state2 = Some(s2);
        }
        if r2.len() == n_others
            && let Some(s2) = state2.take()
        {
            let k = s2.finish(&r2)?;
            send(Body::Confirmation(FvkConfirmation {
                transcript_id: tid.to_vec(),
                participant: me,
                fvk_hash: k.fvk_hash().to_vec(),
            }));
            keys = Some(k);
        }
        if let Some(k) = &keys
            && confs.len() == n_others
        {
            k.check_confirmations(&ids, config.me, &confs)?;
            return Ok(keys.take().expect("checked"));
        }

        let env = inbound
            .message()
            .await
            .map_err(|e| E::Relay(e.message().into()))?
            .ok_or_else(|| E::Relay("relay closed the stream".into()))?;
        let (sender, msg) = open_envelope(&env, &params)?;
        let sid = u16::try_from(sender).expect("validated");
        match msg.body {
            Some(Body::Round1(m)) if tid_ok(&m.transcript_id) && m.participant == sender => {
                let pkg = round1::Package::deserialize(&m.dkg_package)
                    .map_err(|e| E::Message(format!("round 1 from {sender}: {e}")))?;
                let commit = m
                    .sk_commit
                    .as_slice()
                    .try_into()
                    .map_err(|_| E::Message(format!("round 1 from {sender}: bad commit")))?;
                if r1
                    .insert(
                        sid,
                        Round1Broadcast {
                            sk_commit: commit,
                            dkg: pkg,
                        },
                    )
                    .is_some()
                {
                    return Err(E::Message(format!(
                        "participant {sender} sent round 1 twice"
                    )));
                }
            }
            Some(Body::SealedRound2(s))
                if tid_ok(&s.transcript_id) && s.sender == sender && s.recipient == me =>
            {
                let pt = open_round2(identity, &s)?;
                let m =
                    Round2Message {
                        sk_reveal: pt.sk_reveal.as_slice().try_into().map_err(|_| {
                            E::Message(format!("round 2 from {sender}: bad reveal"))
                        })?,
                        dkg: round2::Package::deserialize(&pt.dkg_package)
                            .map_err(|e| E::Message(format!("round 2 from {sender}: {e}")))?,
                    };
                if r2.insert(sid, m).is_some() {
                    return Err(E::Message(format!(
                        "participant {sender} sent round 2 twice"
                    )));
                }
            }
            Some(Body::Confirmation(c)) if tid_ok(&c.transcript_id) && c.participant == sender => {
                let h = c
                    .fvk_hash
                    .as_slice()
                    .try_into()
                    .map_err(|_| E::Message(format!("bad confirmation from {sender}")))?;
                confs.insert(sid, h);
            }
            Some(Body::AbortReason(r)) => return Err(E::Aborted(sender, r)),
            _ => {
                return Err(E::Message(format!(
                    "unexpected or mismatched message from {sender}"
                )));
            }
        }
    }
}
