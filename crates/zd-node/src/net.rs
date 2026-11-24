//! Consensus parameters chosen on the command line.

use zcash_protocol::consensus::{BlockHeight, Network, NetworkType, NetworkUpgrade, Parameters};
use zcash_protocol::local_consensus::LocalNetwork;

use crate::files::NetName;

/// Mainnet, testnet, or a regtest chain with every upgrade at one height.
#[derive(Clone, Copy, Debug)]
pub enum Net {
    Fixed(Network),
    Local(LocalNetwork),
}

impl Net {
    /// `regtest_height` is where every upgrade activates on regtest.
    pub fn new(name: NetName, regtest_height: u32) -> Self {
        match name {
            NetName::Main => Net::Fixed(Network::MainNetwork),
            NetName::Test => Net::Fixed(Network::TestNetwork),
            NetName::Regtest => {
                let h = Some(BlockHeight::from_u32(regtest_height));
                Net::Local(LocalNetwork {
                    overwinter: h,
                    sapling: h,
                    blossom: h,
                    heartwood: h,
                    canopy: h,
                    nu5: h,
                    nu6: h,
                    nu6_1: h,
                    nu6_2: h,
                    nu6_3: h,
                    nu7: None,
                })
            }
        }
    }
}

impl Parameters for Net {
    fn network_type(&self) -> NetworkType {
        match self {
            Net::Fixed(n) => n.network_type(),
            Net::Local(n) => n.network_type(),
        }
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match self {
            Net::Fixed(n) => n.activation_height(nu),
            Net::Local(n) => n.activation_height(nu),
        }
    }
}
