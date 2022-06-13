mod utils;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn doProcess(
    nWordsReady: usize,
    blockSize: usize,
    dataWords: &mut [u32],
    X: &mut [u32],
    C: &mut [u32],
    mut b: u32,
) -> u32 {
    // Process blocks
    if nWordsReady > 0 {
        let mut offset = 0;
        while offset < nWordsReady {
            b = doProcessBlock(dataWords, offset, X, C, b);
            offset += blockSize;
        }
    }

    b
}

fn nextState(X: &mut [u32], C: &mut [u32], mut b: u32) -> u32 {
    let mut C_: [u32; 8] = [0; 8];
    // Save old counter values
    for i in 0..8 {
        C_[i] = C[i];
    }

    // Calculate new counter values
    C[0] = (C[0] + 0x4d34d34d + b) | 0;
    C[1] = (C[1] + 0xd34d34d3 + (if C[0] < C_[0] { 1 } else { 0 })) | 0;
    C[2] = (C[2] + 0x34d34d34 + (if C[1] < C_[1] { 1 } else { 0 })) | 0;
    C[3] = (C[3] + 0x4d34d34d + (if C[2] < C_[2] { 1 } else { 0 })) | 0;
    C[4] = (C[4] + 0xd34d34d3 + (if C[3] < C_[3] { 1 } else { 0 })) | 0;
    C[5] = (C[5] + 0x34d34d34 + (if C[4] < C_[4] { 1 } else { 0 })) | 0;
    C[6] = (C[6] + 0x4d34d34d + (if C[5] < C_[5] { 1 } else { 0 })) | 0;
    C[7] = (C[7] + 0xd34d34d3 + (if C[6] < C_[6] { 1 } else { 0 })) | 0;
    b = if C[7] < C_[7] { 1 } else { 0 };

    let mut G: [u32; 8] = [0; 8];
    // Calculate the g-values
    for i in 0..8 {
        let gx = X[i] + C[i];

        // Construct high and low argument for squaring
        let ga = gx & 0xffff;
        let gb = gx >> 16;

        // Calculate high and low result of squaring
        let gh = ((((ga * ga) >> 17) + ga * gb) >> 15) + gb * gb;
        let gl = (((gx & 0xffff0000) * gx) | 0) + (((gx & 0x0000ffff) * gx) | 0);

        // High XOR low
        G[i] = gh ^ gl;
    }

    // Calculate new state values
    X[0] = (G[0] + ((G[7] << 16) | (G[7] >> 16)) + ((G[6] << 16) | (G[6] >> 16))) | 0;
    X[1] = (G[1] + ((G[0] << 8) | (G[0] >> 24)) + G[7]) | 0;
    X[2] = (G[2] + ((G[1] << 16) | (G[1] >> 16)) + ((G[0] << 16) | (G[0] >> 16))) | 0;
    X[3] = (G[3] + ((G[2] << 8) | (G[2] >> 24)) + G[1]) | 0;
    X[4] = (G[4] + ((G[3] << 16) | (G[3] >> 16)) + ((G[2] << 16) | (G[2] >> 16))) | 0;
    X[5] = (G[5] + ((G[4] << 8) | (G[4] >> 24)) + G[3]) | 0;
    X[6] = (G[6] + ((G[5] << 16) | (G[5] >> 16)) + ((G[4] << 16) | (G[4] >> 16))) | 0;
    X[7] = (G[7] + ((G[6] << 8) | (G[6] >> 24)) + G[5]) | 0;

    b
}

fn doProcessBlock(
    dataWords: &mut [u32],
    offset: usize,
    X: &mut [u32],
    C: &mut [u32],
    mut b: u32,
) -> u32 {
    // Iterate the system
    b = nextState(X, C, b);

    let mut S: [u32; 4] = [0; 4];
    // Generate four keystream words
    S[0] = X[0] ^ (X[5] >> 16) ^ (X[3] << 16);
    S[1] = X[2] ^ (X[7] >> 16) ^ (X[5] << 16);
    S[2] = X[4] ^ (X[1] >> 16) ^ (X[7] << 16);
    S[3] = X[6] ^ (X[3] >> 16) ^ (X[1] << 16);

    for i in 0..4 {
        // Swap endian
        S[i] = (((S[i] << 8) | (S[i] >> 24)) & 0x00ff00ff)
            | (((S[i] << 24) | (S[i] >> 8)) & 0xff00ff00);

        // Encrypt
        dataWords[offset + i] ^= S[i];
    }

    b
}
