mod utils;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn doProcess(nWordsReady: usize, blockSize: usize, dataWords: &mut [u32], S: &mut [u32]) {
    // Process blocks
    if nWordsReady > 0 {
        let mut offset = 0;
        while offset < nWordsReady {
            doProcessBlock(dataWords, offset, S);
            offset += blockSize;
        }
    }
}

fn generateKeystreamWord(S: &mut [u32]) -> u32 {
    let mut i = S[256] as usize;
    let mut j = S[257] as usize;

    // Generate keystream word
    let mut keystreamWord = 0;
    for n in 0..4 {
        i = (i + 1) % 256;
        j = (j + S[i] as usize) % 256;

        // Swap
        let t = S[i];
        S[i] = S[j];
        S[j] = t;

        keystreamWord |= S[((S[i] + S[j]) % 256) as usize] << (24 - n * 8);
    }

    // Update counters
    S[256] = i as u32;
    S[257] = j as u32;

    keystreamWord
}

fn doProcessBlock(dataWords: &mut [u32], offset: usize, S: &mut [u32]) {
    dataWords[offset] ^= generateKeystreamWord(S);
}
