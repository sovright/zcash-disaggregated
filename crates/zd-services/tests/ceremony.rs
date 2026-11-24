//! Key ceremony through a gRPC relay: three participants connect at
//! different times and all derive the same quantum-recoverable account.

use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};
use zd_proto::v1::{
    CeremonyParams, CeremonyParticipant, CeremonyRound2Plaintext, Network,
    key_ceremony_client::KeyCeremonyClient, key_ceremony_server::KeyCeremonyServer,
};
use zd_services::ceremony::{
    CeremonyRelay, CeremonyServiceError, Identity, open_envelope, open_round2, run_participant,
    seal_envelope, seal_round2, transcript_id,
};

fn params(ids: &[Identity], threshold: u32) -> CeremonyParams {
    CeremonyParams {
        threshold,
        participants: ids
            .iter()
            .enumerate()
            .map(|(i, id)| CeremonyParticipant {
                id: i as u32 + 1,
                identity: Some(id.role_identity()),
                encryption_key: id.encryption_key().to_vec(),
            })
            .collect(),
        network: Network::Testnet as i32,
        account_label: "treasury".into(),
        nonce: vec![7; 32],
    }
}

async fn relay(params: CeremonyParams) -> Channel {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(
        Server::builder()
            .add_service(KeyCeremonyServer::new(CeremonyRelay::new(params).unwrap()))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn three_participants_through_relay() {
    let ids: Vec<Identity> = (0..3)
        .map(|i| Identity::generate(format!("p{i}")))
        .collect();
    let params = params(&ids, 2);
    let ch = relay(params.clone()).await;

    let ids = std::sync::Arc::new(ids);
    let mut tasks = Vec::new();
    for me in 1..=3u32 {
        let (ch, params, ids) = (ch.clone(), params.clone(), ids.clone());
        tasks.push(tokio::spawn(async move {
            // Stagger connections so the relay's backlog is exercised.
            tokio::time::sleep(std::time::Duration::from_millis(50 * u64::from(me))).await;
            run_participant(
                KeyCeremonyClient::new(ch),
                params,
                me,
                &ids[me as usize - 1],
            )
            .await
        }));
    }
    let mut keys = Vec::new();
    for t in tasks {
        keys.push(t.await.unwrap().unwrap());
    }
    let first = &keys[0];
    assert_eq!(first.transcript_id(), &transcript_id(&params));
    for k in &keys {
        assert_eq!(k.fvk_hash(), first.fvk_hash());
        assert_eq!(k.qsk().as_bytes(), first.qsk().as_bytes());
        assert_eq!(k.public_key_package(), first.public_key_package());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_rejects_strangers_and_wrong_params() {
    let ids: Vec<Identity> = (0..2)
        .map(|i| Identity::generate(format!("p{i}")))
        .collect();
    let params = params(&ids, 2);
    let ch = relay(params.clone()).await;

    // Someone not in params.
    let stranger = Identity::generate("x");
    let mut p2 = params.clone();
    p2.participants[0].identity = Some(stranger.role_identity());
    p2.participants[0].encryption_key = stranger.encryption_key().to_vec();
    let err = run_participant(KeyCeremonyClient::new(ch.clone()), p2, 1, &stranger)
        .await
        .err()
        .unwrap();
    assert!(matches!(err, CeremonyServiceError::Relay(_)), "{err}");

    // A real participant with different params (other nonce).
    let mut p3 = params.clone();
    p3.nonce = vec![8; 32];
    let err = run_participant(KeyCeremonyClient::new(ch), p3, 1, &ids[0])
        .await
        .err()
        .unwrap();
    assert!(
        matches!(err, CeremonyServiceError::Relay(ref m) if m.contains("different params")),
        "{err}"
    );
}

#[test]
fn sealed_round2_only_opens_for_recipient() {
    let a = Identity::generate("a");
    let b = Identity::generate("b");
    let c = Identity::generate("c");
    let tid = [5u8; 32];
    let pt = CeremonyRound2Plaintext {
        sk_reveal: vec![1; 32],
        dkg_package: vec![2; 10],
    };
    let sealed = seal_round2(&tid, 1, 2, &b.encryption_key(), &pt);
    assert_eq!(open_round2(&b, &sealed).unwrap(), pt);
    assert!(open_round2(&c, &sealed).is_err());
    // Rebinding to another recipient or sender breaks it.
    let mut moved = sealed.clone();
    moved.sender = 3;
    assert!(open_round2(&b, &moved).is_err());
    let _ = a;
}

#[test]
fn envelopes_are_authenticated() {
    let ids: Vec<Identity> = (0..2)
        .map(|i| Identity::generate(format!("p{i}")))
        .collect();
    let params = params(&ids, 2);
    let msg = zd_proto::v1::CeremonyMessage {
        body: Some(zd_proto::v1::ceremony_message::Body::AbortReason(
            "x".into(),
        )),
    };
    let env = seal_envelope(&ids[1], &msg);
    let (sender, back) = open_envelope(&env, &params).unwrap();
    assert_eq!(sender, 2);
    assert_eq!(back, msg);

    let mut tampered = env.clone();
    tampered.payload.push(0);
    assert!(open_envelope(&tampered, &params).is_err());

    // Claiming to be participant 1 with participant 2's signature fails.
    let mut spoofed = env;
    spoofed.sender = Some(ids[0].role_identity());
    assert!(open_envelope(&spoofed, &params).is_err());
}
