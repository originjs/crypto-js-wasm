mod utils;

use std::ptr::null;
use std::cmp;
use wasm_bindgen::prelude::*;
use utils::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

extern crate serde_json;
extern crate wasm_bindgen;

#[wasm_bindgen]
extern "C" {}

#[wasm_bindgen]
pub fn md5Process(doFlush: u8, hashWords: &mut [u32], dataWords: &[u32], dataSigBytes: u32, blockSize: u32, minBufferSize: u32) -> u32 {
    let blockSizeBytes = blockSize * 4;
    let mut nBlocksReady: f32 = dataSigBytes as f32 / blockSizeBytes as f32;
    if (doFlush > 0) {
        nBlocksReady = nBlocksReady.ceil();
    } else {
        nBlocksReady = f32::max(nBlocksReady - minBufferSize as f32, 0_f32);
    }

    let nWordsReady = nBlocksReady as u32 * blockSize;

    if (nWordsReady > 0) {
        let mut offset = 0;
        while (offset < nWordsReady) {
            md5DoProcessBlock(dataWords, offset, hashWords);
            offset += blockSize;
        }
    }

    nWordsReady
}

fn md5DoProcessBlock(originalM: &[u32], offsetU32: u32, hashWords: &mut [u32]) {
    let T = getT();
    let offset = offsetU32 as usize;
    let mut M: [u32; 16] = [0_u32; 16];
    for i in 0..16 {
        // Shortcuts
        let offset_i = offset + i;

        let M_offset_i = originalM[offset_i];

        M[offset_i % 16] = (((M_offset_i << 8) | (M_offset_i >> 24)) & 0x00ff00ff) |
            (((M_offset_i << 24) | (M_offset_i >> 8)) & 0xff00ff00);
    }

    let mut a = hashWords[0];
    let mut b = hashWords[1];
    let mut c = hashWords[2];
    let mut d = hashWords[3];

    let M_offset_0 = M[0];
    let M_offset_1 = M[1];
    let M_offset_2 = M[2];
    let M_offset_3 = M[3];
    let M_offset_4 = M[4];
    let M_offset_5 = M[5];
    let M_offset_6 = M[6];
    let M_offset_7 = M[7];
    let M_offset_8 = M[8];
    let M_offset_9 = M[9];
    let M_offset_10 = M[10];
    let M_offset_11 = M[11];
    let M_offset_12 = M[12];
    let M_offset_13 = M[13];
    let M_offset_14 = M[14];
    let M_offset_15 = M[15];

    a = FF(a, b, c, d, M_offset_0, 7, T[0]);
    d = FF(d, a, b, c, M_offset_1, 12, T[1]);
    c = FF(c, d, a, b, M_offset_2, 17, T[2]);
    b = FF(b, c, d, a, M_offset_3, 22, T[3]);
    a = FF(a, b, c, d, M_offset_4, 7, T[4]);
    d = FF(d, a, b, c, M_offset_5, 12, T[5]);
    c = FF(c, d, a, b, M_offset_6, 17, T[6]);
    b = FF(b, c, d, a, M_offset_7, 22, T[7]);
    a = FF(a, b, c, d, M_offset_8, 7, T[8]);
    d = FF(d, a, b, c, M_offset_9, 12, T[9]);
    c = FF(c, d, a, b, M_offset_10, 17, T[10]);
    b = FF(b, c, d, a, M_offset_11, 22, T[11]);
    a = FF(a, b, c, d, M_offset_12, 7, T[12]);
    d = FF(d, a, b, c, M_offset_13, 12, T[13]);
    c = FF(c, d, a, b, M_offset_14, 17, T[14]);
    b = FF(b, c, d, a, M_offset_15, 22, T[15]);

    a = GG(a, b, c, d, M_offset_1, 5, T[16]);
    d = GG(d, a, b, c, M_offset_6, 9, T[17]);
    c = GG(c, d, a, b, M_offset_11, 14, T[18]);
    b = GG(b, c, d, a, M_offset_0, 20, T[19]);
    a = GG(a, b, c, d, M_offset_5, 5, T[20]);
    d = GG(d, a, b, c, M_offset_10, 9, T[21]);
    c = GG(c, d, a, b, M_offset_15, 14, T[22]);
    b = GG(b, c, d, a, M_offset_4, 20, T[23]);
    a = GG(a, b, c, d, M_offset_9, 5, T[24]);
    d = GG(d, a, b, c, M_offset_14, 9, T[25]);
    c = GG(c, d, a, b, M_offset_3, 14, T[26]);
    b = GG(b, c, d, a, M_offset_8, 20, T[27]);
    a = GG(a, b, c, d, M_offset_13, 5, T[28]);
    d = GG(d, a, b, c, M_offset_2, 9, T[29]);
    c = GG(c, d, a, b, M_offset_7, 14, T[30]);
    b = GG(b, c, d, a, M_offset_12, 20, T[31]);

    a = HH(a, b, c, d, M_offset_5, 4, T[32]);
    d = HH(d, a, b, c, M_offset_8, 11, T[33]);
    c = HH(c, d, a, b, M_offset_11, 16, T[34]);
    b = HH(b, c, d, a, M_offset_14, 23, T[35]);
    a = HH(a, b, c, d, M_offset_1, 4, T[36]);
    d = HH(d, a, b, c, M_offset_4, 11, T[37]);
    c = HH(c, d, a, b, M_offset_7, 16, T[38]);
    b = HH(b, c, d, a, M_offset_10, 23, T[39]);
    a = HH(a, b, c, d, M_offset_13, 4, T[40]);
    d = HH(d, a, b, c, M_offset_0, 11, T[41]);
    c = HH(c, d, a, b, M_offset_3, 16, T[42]);
    b = HH(b, c, d, a, M_offset_6, 23, T[43]);
    a = HH(a, b, c, d, M_offset_9, 4, T[44]);
    d = HH(d, a, b, c, M_offset_12, 11, T[45]);
    c = HH(c, d, a, b, M_offset_15, 16, T[46]);
    b = HH(b, c, d, a, M_offset_2, 23, T[47]);

    a = II(a, b, c, d, M_offset_0, 6, T[48]);
    d = II(d, a, b, c, M_offset_7, 10, T[49]);
    c = II(c, d, a, b, M_offset_14, 15, T[50]);
    b = II(b, c, d, a, M_offset_5, 21, T[51]);
    a = II(a, b, c, d, M_offset_12, 6, T[52]);
    d = II(d, a, b, c, M_offset_3, 10, T[53]);
    c = II(c, d, a, b, M_offset_10, 15, T[54]);
    b = II(b, c, d, a, M_offset_1, 21, T[55]);
    a = II(a, b, c, d, M_offset_8, 6, T[56]);
    d = II(d, a, b, c, M_offset_15, 10, T[57]);
    c = II(c, d, a, b, M_offset_6, 15, T[58]);
    b = II(b, c, d, a, M_offset_13, 21, T[59]);
    a = II(a, b, c, d, M_offset_4, 6, T[60]);
    d = II(d, a, b, c, M_offset_11, 10, T[61]);
    c = II(c, d, a, b, M_offset_2, 15, T[62]);
    b = II(b, c, d, a, M_offset_9, 21, T[63]);

    hashWords[0] = (hashWords[0] + a) | 0;
    hashWords[1] = (hashWords[1] + b) | 0;
    hashWords[2] = (hashWords[2] + c) | 0;
    hashWords[3] = (hashWords[3] + d) | 0;
}

fn FF(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32, t: u32) -> u32 {
    let n: u32 = a + ((b & c) | (!b & d)) + x + t;
    ((n << s) | (n >> (32 - s))) + b
}

fn GG(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32, t: u32) -> u32 {
    let n: u32 = a + ((b & d) | (c & !d)) + x + t;
    ((n << s) | (n >> (32 - s))) + b
}

fn HH(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32, t: u32) -> u32 {
    let n: u32 = a + (b ^ c ^ d) + x + t;
    ((n << s) | (n >> (32 - s))) + b
}

fn II(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32, t: u32) -> u32 {
    let n: u32 = a + (c ^ (b | !d)) + x + t;
    ((n << s) | (n >> (32 - s))) + b
}
