// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use core::fmt;

use chacha20::{
    cipher::{KeyIvInit, StreamCipher, StreamCipherSeek},
    ChaCha8,
};
use rand::{CryptoRng, Error, RngCore, SeedableRng};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const WORD_BYTES: u128 = 4;
const BLOCK_BYTES: u128 = 64;
const LOW_COUNTER_BLOCKS: u128 = 1u128 << 32;
const WORD_POSITION_MASK: u128 = (1u128 << 68) - 1;

/// A zeroizing ChaCha8 PRF compatible with [`rand_chacha::ChaCha8Rng`].
///
/// The stored state matches `rand_chacha`'s stable abstract state: a 256-bit
/// seed, a 64-bit stream identifier, and a position measured in 32-bit words.
/// Cipher instances are short-lived and securely clear their expanded state on
/// drop through the `chacha20/zeroize` feature.
#[derive(Clone)]
pub struct LabelPrf {
    seed: Zeroizing<[u8; 32]>,
    stream: u64,
    word_pos: u128,
}

impl LabelPrf {
    /// Restores a PRF from the state serialized by `ChaCha8Rng`.
    pub fn from_state(seed: [u8; 32], stream: u64, word_pos: u128) -> Self {
        let mut prf = Self::from_seed(seed);
        prf.set_stream(stream);
        prf.set_word_pos(word_pos);
        prf
    }

    /// Returns the portable state needed to resume this PRF.
    pub fn state(&self) -> ([u8; 32], u64, u128) {
        (self.get_seed(), self.get_stream(), self.get_word_pos())
    }

    pub fn get_seed(&self) -> [u8; 32] {
        *self.seed
    }

    pub fn get_stream(&self) -> u64 {
        self.stream
    }

    pub fn set_stream(&mut self, stream: u64) {
        self.stream = stream;
    }

    pub fn get_word_pos(&self) -> u128 {
        self.word_pos
    }

    /// Sets the stream offset in 32-bit words.
    ///
    /// Like `ChaCha8Rng`, offsets wrap after the 68-bit word position encoded
    /// by ChaCha's 64-bit block counter.
    pub fn set_word_pos(&mut self, word_pos: u128) {
        self.word_pos = word_pos & WORD_POSITION_MASK;
    }

    fn generate(&self, output: &mut [u8]) {
        let mut output_offset = 0usize;
        let mut byte_pos = self.word_pos * WORD_BYTES;

        while output_offset < output.len() {
            // rand_chacha lays out the final state words as a 64-bit block
            // counter followed by a 64-bit stream identifier. RustCrypto's
            // IETF layout has a 32-bit counter and a 96-bit nonce, so place the
            // high counter word first in the nonce to obtain the same state.
            let block_pos = (byte_pos / BLOCK_BYTES) as u64;
            let byte_in_block = (byte_pos % BLOCK_BYTES) as u64;
            let low_counter = block_pos as u32;
            let high_counter = (block_pos >> 32) as u32;

            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(&high_counter.to_le_bytes());
            nonce[4..].copy_from_slice(&self.stream.to_le_bytes());

            let mut cipher = ChaCha8::new(
                chacha20::Key::from_slice(self.seed.as_ref()),
                chacha20::Nonce::from_slice(&nonce),
            );
            cipher.seek(u64::from(low_counter) * 64 + byte_in_block);

            // RustCrypto's counter is 32 bits. Stop before it wraps, then
            // rebuild the cipher with the incremented high counter word.
            let bytes_until_wrap =
                (LOW_COUNTER_BLOCKS - u128::from(low_counter)) * BLOCK_BYTES
                    - u128::from(byte_in_block);
            let remaining = output.len() - output_offset;
            let take = if bytes_until_wrap < remaining as u128 {
                bytes_until_wrap as usize
            } else {
                remaining
            };

            let chunk = &mut output[output_offset..output_offset + take];
            chunk.zeroize();
            cipher.apply_keystream(chunk);

            output_offset += take;
            byte_pos += take as u128;
        }
    }

    fn advance(&mut self, words: u128) {
        self.word_pos =
            self.word_pos.wrapping_add(words) & WORD_POSITION_MASK;
    }
}

impl fmt::Debug for LabelPrf {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LabelPrf { .. }")
    }
}

impl PartialEq for LabelPrf {
    fn eq(&self, other: &Self) -> bool {
        self.seed.as_ref() == other.seed.as_ref()
            && self.stream == other.stream
            && self.word_pos == other.word_pos
    }
}

impl Eq for LabelPrf {}

impl SeedableRng for LabelPrf {
    type Seed = [u8; 32];

    fn from_seed(seed: Self::Seed) -> Self {
        Self {
            seed: Zeroizing::new(seed),
            stream: 0,
            word_pos: 0,
        }
    }
}

impl RngCore for LabelPrf {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.generate(&mut bytes);
        self.advance(1);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.generate(&mut bytes);
        self.advance(2);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, output: &mut [u8]) {
        self.generate(output);
        self.advance(output.len().div_ceil(4) as u128);
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(output);
        Ok(())
    }
}

impl CryptoRng for LabelPrf {}

impl Zeroize for LabelPrf {
    fn zeroize(&mut self) {
        self.seed.zeroize();
        self.stream.zeroize();
        self.word_pos.zeroize();
    }
}

impl Drop for LabelPrf {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for LabelPrf {}

#[cfg(test)]
mod tests {
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;
    use zeroize::Zeroize;

    use super::LabelPrf;

    fn assert_same_state(reference: &ChaCha8Rng, actual: &LabelPrf) {
        assert_eq!(actual.get_seed(), reference.get_seed());
        assert_eq!(actual.get_stream(), reference.get_stream());
        assert_eq!(actual.get_word_pos(), reference.get_word_pos());
    }

    #[test]
    fn matches_rand_chacha_for_mixed_rng_calls() {
        for seed_byte in [0, 1, 0x5a, 0xff] {
            let seed = [seed_byte; 32];
            let mut reference = ChaCha8Rng::from_seed(seed);
            let mut actual = LabelPrf::from_seed(seed);

            for len in [0, 1, 3, 4, 5, 15, 16, 17, 63, 64, 65, 255, 256, 257]
            {
                let mut expected = vec![0u8; len];
                let mut obtained = vec![0u8; len];
                reference.fill_bytes(&mut expected);
                actual.fill_bytes(&mut obtained);
                assert_eq!(obtained, expected, "fill_bytes length {len}");
                assert_same_state(&reference, &actual);

                assert_eq!(actual.next_u32(), reference.next_u32());
                assert_eq!(actual.next_u64(), reference.next_u64());
                assert_same_state(&reference, &actual);
            }
        }
    }

    #[test]
    fn matches_rand_chacha_streams_and_counter_boundaries() {
        let seed = [0xa5; 32];
        let positions = [
            0,
            1,
            15,
            16,
            63,
            64,
            (1u128 << 32) * 16 - 2,
            (1u128 << 32) * 16,
            (1u128 << 64) * 16 - 2,
        ];

        for stream in [0, 1, u64::MAX] {
            for word_pos in positions {
                let mut reference = ChaCha8Rng::from_seed(seed);
                reference.set_stream(stream);
                reference.set_word_pos(word_pos);

                let mut actual = LabelPrf::from_state(seed, stream, word_pos);
                let mut expected = [0u8; 32];
                let mut obtained = [0u8; 32];
                reference.fill_bytes(&mut expected);
                actual.fill_bytes(&mut obtained);

                assert_eq!(
                    obtained, expected,
                    "stream {stream}, word {word_pos}"
                );
                assert_same_state(&reference, &actual);
            }
        }
    }

    #[test]
    fn wraps_word_positions_like_rand_chacha() {
        let seed = [7; 32];
        let requested = (1u128 << 100) | 37;
        let mut reference = ChaCha8Rng::from_seed(seed);
        reference.set_word_pos(requested);
        let actual = LabelPrf::from_state(seed, 0, requested);
        assert_same_state(&reference, &actual);
    }

    #[test]
    fn zeroize_clears_portable_state() {
        let mut prf = LabelPrf::from_state([0xa5; 32], u64::MAX, 123);
        prf.zeroize();
        assert_eq!(prf.state(), ([0; 32], 0, 0));
    }
}
