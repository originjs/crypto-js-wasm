mod utils;

use wasm_bindgen::prelude::*;
use utils::*;

#[wasm_bindgen]
pub fn doCrypt(nWordsReady: u32, blockSize: u32, dataWords: &[u32], hash: &mut [u32]) {
    let mut hashU64: [u64; 8] = [0; 8];
    for i in 0..8 {
        let hashHigh: u64 = hash[i * 2] as u64;
        let hashLow: u64 = hash[i * 2 + 1] as u64;
        hashU64[i] = hashHigh << 32 | hashLow;
    }

    if nWordsReady > 0 {
        let mut offset = 0;
        while offset < nWordsReady {
            doCryptBlock(dataWords, offset, &mut hashU64);
            offset += blockSize;
        }
    }
    for i in 0..8 {
        hash[i * 2] = (hashU64[i] >> 32) as u32;
        hash[i * 2 + 1] = (hashU64[i] & 0xffffffff) as u32;
    }
}

fn doCryptBlock(data: &[u32], offsetU32: u32, hash: &mut [u64]) {
    let K = getK();
    let offset = offsetU32 as usize;

    // Working variables
    let mut a = hash[0];
    let mut b = hash[1];
    let mut c = hash[2];
    let mut d = hash[3];
    let mut e = hash[4];
    let mut f = hash[5];
    let mut g = hash[6];
    let mut h = hash[7];

    let mut W: [u64; 80] = [0; 80];
    // Computation
    for i in 0..80 {
        if i < 16 {
            W[i] = data[offset + i * 2] as u64;
            W[i] = W[i] << 32 | data[offset + i * 2 + 1] as u64;
        } else {
            let gamma0x = W[i - 15];
            let gamma0 = ((gamma0x >> 1) | (gamma0x << 63)) ^ ((gamma0x >> 8) | (gamma0x << 56)) ^ (gamma0x >> 7);
            let gamma1x = W[i - 2];
            let gamma1 = ((gamma1x >> 19) | (gamma1x << 45)) ^ ((gamma1x << 3) | (gamma1x >> 61)) ^ (gamma1x >> 6);
            W[i] = ((gamma0 as u128) + (W[i - 7] as u128) + (gamma1 as u128) + (W[i - 16] as u128)) as u64;
        }

        let ch = (e & f) ^ (!e & g);
        let maj = (a & b) ^ (a & c) ^ (b & c);

        let sigma0 = ((a >> 28) | (a << 36)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39));
        let sigma1 = ((e >> 14) | (e << 50)) ^ ((e >> 18) | (e << 46)) ^ ((e << 23) | (e >> 41));

        let t1 = ((h as u128) + (sigma1 as u128) + (ch as u128) + (K[i] as u128) + (W[i] as u128)) as u64;
        let t2 = ((sigma0 as u128) + (maj as u128)) as u64;

        h = g;
        g = f;
        f = e;
        e = ((d as u128) + (t1 as u128)) as u64;
        d = c;
        c = b;
        b = a;
        a = ((t1 as u128) + (t2 as u128)) as u64;
    }

    // Intermediate hash value
    hash[0] = ((hash[0] as u128) + (a as u128)) as u64;
    hash[1] = ((hash[1] as u128) + (b as u128)) as u64;
    hash[2] = ((hash[2] as u128) + (c as u128)) as u64;
    hash[3] = ((hash[3] as u128) + (d as u128)) as u64;
    hash[4] = ((hash[4] as u128) + (e as u128)) as u64;
    hash[5] = ((hash[5] as u128) + (f as u128)) as u64;
    hash[6] = ((hash[6] as u128) + (g as u128)) as u64;
    hash[7] = ((hash[7] as u128) + (h as u128)) as u64;
}
