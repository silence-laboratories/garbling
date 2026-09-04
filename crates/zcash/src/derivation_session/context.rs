// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use garbled_circuit::functionality::utils_dep::ProtocolError;

use super::serde_types::{
    SecretBytes32, SerializableBlock, SerializableLabelPrf,
    SerializableScalar, SerializableYaoSetup,
};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Context {
    pub(crate) party_id: u8,
    pub(crate) shamir_share: SerializableScalar,
    pub(crate) seed: SecretBytes32,
    pub(crate) yao_setup: Option<SerializableYaoSetup>,
}

impl Context {
    pub(crate) fn party_id(&self) -> u8 {
        self.party_id
    }

    pub(crate) fn shamir_share(&self) -> &SerializableScalar {
        &self.shamir_share
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
            | SerializableYaoSetup::Evaluator { comm_crs, .. } => {
                Ok(comm_crs.clone())
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) fn garble_key(
        &self,
    ) -> Result<SerializableBlock, ProtocolError> {
        match self
            .yao_setup
            .as_ref()
            .ok_or(ProtocolError::MissingMessage)?
        {
            SerializableYaoSetup::Garbler { garble_key, .. }
            | SerializableYaoSetup::Evaluator { garble_key, .. } => {
                Ok(garble_key.clone())
            }
        }
    }

    pub(crate) fn derive_32(&self, domain: &[u8], counter: u32) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"zcash-derivation-session-rng-v1");
        hasher.update(domain);
        hasher.update([self.party_id]);
        hasher.update(self.seed.expose());
        hasher.update(counter.to_le_bytes());
        hasher.finalize().into()
    }

    pub(crate) fn derive_block(
        &self,
        domain: &[u8],
        counter: u32,
    ) -> SerializableBlock {
        let bytes = Zeroizing::new(self.derive_32(domain, counter));
        let mut out = [0u8; 16];
        out.copy_from_slice(&bytes[..16]);
        SerializableBlock(out)
    }

    pub(crate) fn setup_garbler(
        &mut self,
        comm_crs: SerializableBlock,
        prf_seed: [u8; 32],
    ) -> SerializableBlock {
        let (delta, prf, garble_key) = super::setup_delta_from_seed(prf_seed);
        self.yao_setup = Some(SerializableYaoSetup::Garbler {
            comm_crs,
            garble_key: garble_key.clone(),
            prf: Box::new(SerializableLabelPrf::from_prf(&prf)),
            delta,
            party_id: self.party_id,
        });
        garble_key
    }
}

impl Zeroize for Context {
    fn zeroize(&mut self) {
        self.shamir_share.zeroize();
        self.seed.zeroize();
        if let Some(setup) = &mut self.yao_setup {
            setup.zeroize();
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_zeroizes_persisted_secrets() {
        let mut context = Context {
            party_id: 2,
            shamir_share: SerializableScalar([0x11; 32]),
            seed: SecretBytes32([0x22; 32]),
            yao_setup: Some(SerializableYaoSetup::Evaluator {
                comm_crs: SerializableBlock([0x33; 16]),
                garble_key: SerializableBlock([0x44; 16]),
            }),
        };

        context.zeroize();

        assert_eq!(context.shamir_share.0, [0; 32]);
        assert_eq!(context.seed.0, [0; 32]);
        let Some(SerializableYaoSetup::Evaluator {
            comm_crs,
            garble_key,
        }) = &context.yao_setup
        else {
            unreachable!();
        };
        assert_eq!(comm_crs.0, [0; 16]);
        assert_eq!(garble_key.0, [0; 16]);
    }
}
