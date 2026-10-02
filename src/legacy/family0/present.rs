// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
//
// The cipher identification and key-schedule constants follow `gijzelaerr/s7commplus`
// (`s7commplus/v1_session_key/real_plc/present.py`, MIT), which identified HarpoS7's
// Monolith9/Monolith10 (`bonk-dev/HarpoS7`, MIT) as this PRESENT-80 variant.
// See `LICENSE-HarpoS7` and `LICENSE-gijzelaerr-s7commplus`.

//! The PRESENT-80 variant behind the real-PLC seed and key derivation.
//!
//! The rounds are standard PRESENT (S-box, P-layer, 31 rounds plus a final key addition),
//! applied to a byte-reversed little-endian block. The key schedule deviates in three fixed
//! ways (see [`round_keys`]).

const SBOX: [u8; 16] = [
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
];

/// XORed into the key register before the schedule proper starts.
const KEY_OFFSET: u128 = 0x87CA_9952_17BA_3185_3DCE;
/// XORed into round key 0, which is taken from the unmodified key.
const FIRST_ROUND_KEY_OFFSET: u64 = 0x0000_0810_0000_0000;
const KEY_MASK: u128 = (1 << 80) - 1;

/// PRESENT's S-box layer then P-layer (bit `i` moves to `16·i mod 63`, bit 63 stays).
fn sp_layer(state: u64) -> u64 {
    let mut s = 0u64;
    for n in 0..16 {
        s |= u64::from(SBOX[((state >> (4 * n)) & 0xF) as usize]) << (4 * n);
    }
    let mut out = 0u64;
    for bit in 0..64 {
        let to = if bit == 63 { 63 } else { 16 * bit % 63 };
        out |= ((s >> bit) & 1) << to;
    }
    out
}

/// The PRESENT-80 key-register update: rotate left 61, S-box the top nibble, add the counter.
fn update(register: u128, counter: u128) -> u128 {
    let r = ((register << 61) | (register >> 19)) & KEY_MASK;
    let top = u128::from(SBOX[(r >> 76) as usize]);
    ((top << 76) | (r & ((1 << 76) - 1))) ^ (counter << 15)
}

/// The 32 round keys for an 80-bit key register. Unlike standard PRESENT, round key 0 comes
/// from `key` itself, the rest of the schedule runs on `key ⊕ KEY_OFFSET`, and bit 6 is
/// flipped after the second update.
fn round_keys(key: u128) -> [u64; 32] {
    let mut keys = [0u64; 32];
    keys[0] = ((key >> 16) as u64) ^ FIRST_ROUND_KEY_OFFSET;
    let mut register = update(key ^ KEY_OFFSET, 1);
    for (counter, slot) in keys.iter_mut().enumerate().skip(1) {
        *slot = (register >> 16) as u64;
        register = update(register, counter as u128 + 1) ^ if counter == 1 { 0x40 } else { 0 };
    }
    keys
}

/// Encrypt one 64-bit block (as HarpoS7 reads it: little endian) under the key register.
pub fn encrypt(block: u64, key: u128) -> u64 {
    let keys = round_keys(key);
    let mut state = block.swap_bytes();
    for &k in &keys[..31] {
        state = sp_layer(state ^ k);
    }
    (state ^ keys[31]).swap_bytes()
}

/// The key register for 10 little-endian bytes: they are read big endian.
fn key_register(half: &[u8]) -> u128 {
    half.iter().fold(0u128, |acc, &b| acc << 8 | u128::from(b))
}

/// Key registers for the low and the high 80 bits of a 160-bit little-endian value.
pub fn key_halves(value: &[u8; 20]) -> (u128, u128) {
    (key_register(&value[..10]), key_register(&value[10..]))
}

/// Concatenate `encrypt(block, key)` results into one 160-bit little-endian value (the third
/// block contributes only its low 32 bits), as three consecutive Monolith9 calls do.
pub fn encrypt_blocks(blocks: [u64; 3], keys: [u128; 3]) -> [u8; 20] {
    let mut out = [0u8; 24];
    for i in 0..3 {
        out[8 * i..8 * i + 8].copy_from_slice(&encrypt(blocks[i], keys[i]).to_le_bytes());
    }
    out[..20].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_present_rounds_are_intact() {
        // With the schedule bypassed, the round function is textbook PRESENT: check the
        // published PRESENT-80 test vector (all-zero key and plaintext → 5579C1387B228445)
        // using the standard key schedule built from the same `update`.
        let mut register: u128 = 0;
        let mut keys = [0u64; 32];
        for (i, k) in keys.iter_mut().enumerate() {
            *k = (register >> 16) as u64;
            register = update(register, i as u128 + 1);
        }
        let mut state = 0u64;
        for &k in &keys[..31] {
            state = sp_layer(state ^ k);
        }
        assert_eq!(state ^ keys[31], 0x5579_C138_7B22_8445);
    }

    #[test]
    fn key_halves_read_each_half_big_endian() {
        let mut v = [0u8; 20];
        v[0] = 0x01;
        v[9] = 0x02;
        v[10] = 0x03;
        let (low, high) = key_halves(&v);
        assert_eq!(low, 0x0100_0000_0000_0000_0002);
        assert_eq!(high, 0x0300_0000_0000_0000_0000);
    }
}
