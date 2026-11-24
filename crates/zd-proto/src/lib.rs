//! Wire messages and gRPC services between the roles of a disaggregated
//! Zcash wallet: detectors, address services, wallet state, provers, signers
//! and key-ceremony participants.
//!
//! The protocol is defined in `proto/zd/v1/*.proto` so that non-Rust
//! implementations (for example an Elixir coordinator) can speak it.

/// Version 1 of the protocol.
pub mod v1 {
    tonic::include_proto!("zd.v1");
}

#[cfg(test)]
mod tests {
    use super::v1::*;
    use prost::Message;

    #[test]
    fn note_report_round_trips() {
        let report = NoteReport {
            height: 3_428_143,
            pool: Pool::Ironwood as i32,
            action_index: 1,
            value_zat: 100_000_000,
            note_version: 3,
            ..Default::default()
        };
        let bytes = report.encode_to_vec();
        assert_eq!(NoteReport::decode(bytes.as_slice()).unwrap(), report);
    }

    #[test]
    fn ceremony_message_oneof() {
        let msg = CeremonyMessage {
            body: Some(ceremony_message::Body::SkCommit(SkCommit {
                transcript_id: vec![7; 32],
                participant: 2,
                commitment: vec![9; 32],
            })),
        };
        let decoded = CeremonyMessage::decode(msg.encode_to_vec().as_slice()).unwrap();
        assert!(
            matches!(decoded.body, Some(ceremony_message::Body::SkCommit(c)) if c.participant == 2)
        );
    }
}
