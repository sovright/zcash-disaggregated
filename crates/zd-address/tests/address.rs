use std::collections::HashSet;

use orchard::keys::{DiversifierIndex, FullViewingKey, Scope, SpendingKey};
use zcash_address::unified::{self, Container, Encoding};
use zcash_protocol::consensus::NetworkType;
use zd_address::{AddressServer, Error, INDICES_PER_SERVER, diversifier_index};

fn fvk() -> FullViewingKey {
    FullViewingKey::from(&SpendingKey::from_bytes([9; 32]).unwrap())
}

#[test]
fn servers_mint_distinct_addresses_the_ivk_recognizes() {
    let fvk = fvk();
    let ivk = fvk.to_ivk(Scope::External);
    let mut seen = HashSet::new();
    for server in [0u8, 1, 255] {
        let mut s = AddressServer::new(ivk.clone(), NetworkType::Main, server, 0);
        for i in 0..5u128 {
            let a = s.next_address().unwrap();
            assert!(seen.insert(a.orchard_receiver), "duplicate address");
            assert_eq!(a.diversifier_index[10], server);
            assert_eq!(a.diversifier_index, diversifier_index(server, i).unwrap());

            // Matches orchard's own derivation, and the FVK recognizes it.
            let expected =
                fvk.address_at(DiversifierIndex::from(a.diversifier_index), Scope::External);
            assert_eq!(a.orchard_receiver, expected.to_raw_address_bytes());
            let addr = orchard::Address::from_raw_address_bytes(&a.orchard_receiver).unwrap();
            assert_eq!(fvk.scope_for_address(&addr), Some(Scope::External));

            // Decodes as a mainnet UA with exactly one Orchard receiver.
            let (net, _rev, ua) = unified::Address::decode(&a.unified_address).unwrap();
            assert_eq!(net, NetworkType::Main);
            assert!(a.unified_address.starts_with("u1"));
            assert_eq!(
                ua.items(),
                vec![unified::Receiver::Orchard(a.orchard_receiver)]
            );
        }
        assert_eq!(s.issued(), 5);
    }
}

#[test]
fn resumes_from_persisted_counter() {
    let ivk = fvk().to_ivk(Scope::External);
    let mut a = AddressServer::new(ivk.clone(), NetworkType::Test, 3, 0);
    a.next_address().unwrap();
    let second = a.next_address().unwrap();
    let mut b = AddressServer::new(ivk, NetworkType::Test, 3, 1);
    assert_eq!(b.next_address().unwrap(), second);
    assert!(second.unified_address.starts_with("utest1"));
}

#[test]
fn range_is_bounded() {
    assert_eq!(
        diversifier_index(7, INDICES_PER_SERVER),
        Err(Error::Exhausted(7))
    );
    let last = diversifier_index(7, INDICES_PER_SERVER - 1).unwrap();
    assert_eq!(
        last,
        [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 7
        ]
    );
}
