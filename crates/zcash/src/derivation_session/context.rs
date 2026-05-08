// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};

use garbled_circuit::functionality::utils_dep::ProtocolError;

use super::serde_types::{
    SerializableBlock, SerializableCommonRandomness, SerializableScalar,
    SerializableYaoSetup,
};

#[cfg_attr(feature = "session", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Context {
    pub(crate) party_id: u8,
    pub(crate) shamir_share: SerializableScalar,
    pub(crate) seed: [u8; 32],
    pub(crate) yao_setup: Option<SerializableYaoSetup>,
    pub(crate) common_randomness: Option<SerializableCommonRandomness>,
}

impl Context {
    pub(crate) fn party_id(&self) -> u8 {
        self.party_id
    }

    pub(crate) fn shamir_share(&self) -> SerializableScalar {
        self.shamir_share
    }

    pub(crate) fn comm_crs(
        &self,
    ) -> Result<SerializableBlock, ProtocolError> {
        match self
            .yao_setup
            .as_ref()
            .ok_or(ProtocolError::MissingMessage)?
        {
            SerializableYaoSetup::Garbler { comm_crs, .. }
            | SerializableYaoSetup::Evaluator { comm_crs } => Ok(*comm_crs),
        }
    }

    pub(crate) fn derive_32(&self, domain: &[u8], counter: u32) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"zcash-derivation-session-rng-v1");
        hasher.update(domain);
        hasher.update([self.party_id]);
        hasher.update(self.seed);
        hasher.update(counter.to_le_bytes());
        hasher.finalize().into()
    }

    pub(crate) fn derive_block(
        &self,
        domain: &[u8],
        counter: u32,
    ) -> SerializableBlock {
        let bytes = self.derive_32(domain, counter);
        let mut out = [0u8; 16];
        out.copy_from_slice(&bytes[..16]);
        SerializableBlock(out)
    }

    pub(crate) fn setup_garbler(
        &mut self,
        comm_crs: SerializableBlock,
        prf_seed: [u8; 32],
    ) {
        let delta = super::setup_delta_from_seed(prf_seed);
        self.yao_setup = Some(SerializableYaoSetup::Garbler {
            comm_crs,
            prf: Box::new(ChaCha8Rng::from_seed(prf_seed)),
            delta,
            party_id: self.party_id,
        });
    }
}
