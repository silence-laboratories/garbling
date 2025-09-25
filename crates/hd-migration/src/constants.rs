use crypto_bigint::U256;
use group::ff::PrimeField;
use k256::Scalar;

pub const SECP256_K1_Q: U256 = U256::from_be_hex(Scalar::MODULUS);

pub const X25519_Q: U256 =
    U256::from_be_hex("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");
