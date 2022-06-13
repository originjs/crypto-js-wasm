mod utils;

use std::ptr::null;
use std::cmp;
use wasm_bindgen::prelude::*;
use utils::*;

#[wasm_bindgen]
pub fn doCrypt(doFlush: u8, dataWords: &[u32], dataSigBytes: u32, blockSize: u32, hash: &mut [u32], minBufferSize: u32) -> u32 {
    let blockSizeBytes = blockSize * 4;
    let mut nBlocksReady: f32 = dataSigBytes as f32 / blockSizeBytes as f32;
    if doFlush > 0 {
        nBlocksReady = nBlocksReady.ceil();
    } else {
        nBlocksReady = f32::max(nBlocksReady - minBufferSize as f32, 0_f32);
    }

    let nWordsReady = nBlocksReady as u32 * blockSize;

    if nWordsReady > 0 {
        let mut offset = 0;
        while offset < nWordsReady {
            doCryptBlock(dataWords, offset, hash);
            offset += blockSize;
        }
    }

    nWordsReady
}

fn doCryptBlock(data: &[u32], offsetU32: u32, hash: &mut [u32]) {
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

    let mut W: [u32; 64] = [0; 64];
    // Computation
    for i in 0..64 {
        if i < 16 {
            W[i] = data[offset + i];
        } else {
            let gamma0x = W[i - 15];
            let gamma0  = ((gamma0x << 25) | (gamma0x >> 7)) ^ ((gamma0x << 14) | (gamma0x >> 18)) ^ (gamma0x >> 3);
            let gamma1x = W[i - 2];
            let gamma1  = ((gamma1x << 15) | (gamma1x >> 17)) ^ ((gamma1x << 13) | (gamma1x >> 19)) ^ (gamma1x >> 10);
            W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16];
        }

        let ch  = (e & f) ^ (!e & g);
        let maj = (a & b) ^ (a & c) ^ (b & c);

        let sigma0 = ((a << 30) | (a >> 2)) ^ ((a << 19) | (a >> 13)) ^ ((a << 10) | (a >> 22));
        let sigma1 = ((e << 26) | (e >> 6)) ^ ((e << 21) | (e >> 11)) ^ ((e << 7)  | (e >> 25));

        let t1 = h + sigma1 + ch + K[i] + W[i];
        let t2 = sigma0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // Intermediate hash value
    hash[0] = hash[0] + a;
    hash[1] = hash[1] + b;
    hash[2] = hash[2] + c;
    hash[3] = hash[3] + d;
    hash[4] = hash[4] + e;
    hash[5] = hash[5] + f;
    hash[6] = hash[6] + g;
    hash[7] = hash[7] + h;
}

