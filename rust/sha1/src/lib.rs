use std::ptr::null;
use std::cmp;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn doCrypt(doFlush: u8, hashWords: &mut [u32], dataWords: &[u32], dataSigBytes: u32, blockSize: u32, minBufferSize: u32) -> u32 {
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
            doCryptBlock(dataWords, hashWords, offset);
            offset += blockSize;
        }
    }

    nWordsReady
}

fn doCryptBlock(data: &[u32], hash: &mut [u32], offsetU32: u32) {
    let offset = offsetU32 as usize;
    let mut w: [u32; 80] = [0; 80];
    let mut a: u32 = hash[0];
    let mut b: u32 = hash[1];
    let mut c: u32 = hash[2];
    let mut d: u32 = hash[3];
    let mut e: u32 = hash[4];

    let mut i = 0;
    while i < 80 {
        if i < 16 {
            w[i] = data[offset + i];
        } else {
            let n = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            w[i] = (n << 1) | (n >> 31);
        }

        let mut t: u32 = ((a << 5) | (a >> 27)) + e + w[i];
        if i < 20 {
            t += ((b & c) | (!b & d)) + 0x5a827999;
        } else if i < 40 {
            t += (b ^ c ^ d) + 0x6ed9eba1;
        } else if i < 60 {
            t += ((b & c) | (b & d) | (c & d)) - 0x70e44324;
        } else {
            t += (b ^ c ^ d) - 0x359d3e2a;
        }

        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = t;

        i += 1;
    }

    // Intermediate hash value
    hash[0] = hash[0] + a;
    hash[1] = hash[1] + b;
    hash[2] = hash[2] + c;
    hash[3] = hash[3] + d;
    hash[4] = hash[4] + e;
}
