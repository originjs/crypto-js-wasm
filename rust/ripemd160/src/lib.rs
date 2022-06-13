mod utils;

use crate::utils::{getHL, getHR, getSL, getSR, getZL, getZR};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn doProcess(nWordsReady: usize, blockSize: usize, dataWords: &mut [u32], H: &mut [u32]) {
    // Process blocks
    if nWordsReady > 0 {
        let mut offset = 0;
        while offset < nWordsReady {
            doProcessBlock(dataWords, offset, H);
            offset += blockSize;
        }
    }
}

fn doProcessBlock(dataWords: &mut [u32], offset: usize, H: &mut [u32]) {
    // Swap endian
    for i in 0..16 {
        // Shortcuts
        let offset_i = offset + i;
        let data_offset_i = dataWords[offset_i];

        // Swap
        dataWords[offset_i] = (((data_offset_i << 8) | (data_offset_i >> 24)) & 0x00ff00ff)
            | (((data_offset_i << 24) | (data_offset_i >> 8)) & 0xff00ff00);
    }
    // Shortcut
    let hl = getHL();
    let hr = getHR();
    let zl = getZL();
    let zr = getZR();
    let sl = getSL();
    let sr = getSR();

    // Working letiables
    let mut al = H[0];
    let mut ar = H[0];
    let mut bl = H[1];
    let mut br = H[1];
    let mut cl = H[2];
    let mut cr = H[2];
    let mut dl = H[3];
    let mut dr = H[3];
    let mut el = H[4];
    let mut er = H[4];

    // Computation
    let mut t: u32 = 0;
    for i in 0..80 {
        t = (al + dataWords[offset + zl[i] as usize]) | 0;
        if i < 16 {
            t += f1(bl, cl, dl) + hl[0];
        } else if i < 32 {
            t += f2(bl, cl, dl) + hl[1];
        } else if i < 48 {
            t += f3(bl, cl, dl) + hl[2];
        } else if i < 64 {
            t += f4(bl, cl, dl) + hl[3];
        } else {
            // if (i<80) {
            t += f5(bl, cl, dl) + hl[4];
        }
        t = t | 0;
        t = rotl(t, sl[i]);
        t = (t + el) | 0;
        al = el;
        el = dl;
        dl = rotl(cl, 10);
        cl = bl;
        bl = t;

        t = (ar + dataWords[offset + zr[i] as usize]) | 0;
        if i < 16 {
            t += f5(br, cr, dr) + hr[0];
        } else if i < 32 {
            t += f4(br, cr, dr) + hr[1];
        } else if i < 48 {
            t += f3(br, cr, dr) + hr[2];
        } else if i < 64 {
            t += f2(br, cr, dr) + hr[3];
        } else {
            // if (i<80) {
            t += f1(br, cr, dr) + hr[4];
        }
        t = t | 0;
        t = rotl(t, sr[i]);
        t = (t + er) | 0;
        ar = er;
        er = dr;
        dr = rotl(cr, 10);
        cr = br;
        br = t;
    }
    // Intermediate hash value
    t = (H[1] + cl + dr) | 0;
    H[1] = (H[2] + dl + er) | 0;
    H[2] = (H[3] + el + ar) | 0;
    H[3] = (H[4] + al + br) | 0;
    H[4] = (H[0] + bl + cr) | 0;
    H[0] = t;
}

fn f1(x: u32, y: u32, z: u32) -> u32 {
    (x) ^ (y) ^ (z)
}

fn f2(x: u32, y: u32, z: u32) -> u32 {
    ((x) & (y)) | ((!x) & (z))
}

fn f3(x: u32, y: u32, z: u32) -> u32 {
    ((x) | (!(y))) ^ (z)
}

fn f4(x: u32, y: u32, z: u32) -> u32 {
    ((x) & (z)) | ((y) & (!(z)))
}

fn f5(x: u32, y: u32, z: u32) -> u32 {
    (x) ^ ((y) | (!(z)))
}

fn rotl(x: u32, n: u32) -> u32 {
    (x << n) | (x >> (32 - n))
}
