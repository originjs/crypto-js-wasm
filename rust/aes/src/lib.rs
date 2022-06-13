mod utils;

use wasm_bindgen::prelude::*;
use crate::utils::{getSbox, getInvSbox, getSubMix0, getSubMix1, getSubMix2, getSubMix3, getInvSubMix0, getInvSubMix1, getInvSubMix2, getInvSubMix3, getKeySchedules, getInvKeySchedules};

#[wasm_bindgen]
extern "C" {}

#[wasm_bindgen]
pub fn getKeySchedule(keySize: u32, keyWords: &[u32]) -> Vec<u32> {
    let keySchedule = getKeySchedules(keySize, keyWords);
    keySchedule
}

#[wasm_bindgen]
pub fn getInvKeySchedule(keySize: u32, keyWords: &[u32]) -> Vec<u32> {
    let keySchedule = getKeySchedules(keySize, keyWords);
    let invKeySchedule = getInvKeySchedules(keySize, keyWords, keySchedule);
    invKeySchedule
}

#[wasm_bindgen]
pub fn doEncrypt(mode: &str, nRounds: usize, nWordsReady: usize, blockSize: usize, iv: &[u32], dataWords: &mut [u32],  keySchedule: &[u32]) -> Vec<u32> {
    let mut process: Vec<u32> = Vec::new();
    if nWordsReady > 0 {
        let mut offset: usize = 0;
        match mode.to_lowercase().as_str() {
            "cbc" => {
                let mut prevBlock = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    xorBlock(blockSize, prevBlock, dataWords, offset);
                    encryptBlock(nRounds, dataWords, offset, keySchedule);
                    prevBlock = dataWords[offset..offset + blockSize].to_vec();
                    offset += blockSize;
                }
                process = prevBlock;
            }
            "ecb" => {
                while offset < nWordsReady {
                    encryptBlock(nRounds, dataWords, offset, keySchedule);
                    offset += blockSize;
                }
            }
            "cfb" => {
                let mut prevBlock = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    let mut keystream = prevBlock;
                    encryptBlock(nRounds, &mut keystream, 0, keySchedule);
                    xorBlock(blockSize, keystream.to_owned(), dataWords, offset);
                    prevBlock = dataWords[offset..offset + blockSize].to_vec();
                    offset += blockSize;
                }
                process = prevBlock;
            }
            "ofb" => {
                let mut keystream = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    encryptBlock(nRounds, &mut keystream, 0, keySchedule);
                    xorBlock(blockSize, keystream.to_owned(), dataWords, offset);
                    offset += blockSize;
                }
                process = keystream;
            }
            "ctr" => {
                let mut counter = iv[0..blockSize].to_vec();
                let mut keystream;
                while offset < nWordsReady {
                    keystream = counter.clone();
                    encryptBlock(nRounds, &mut keystream, 0, keySchedule);
                    // Increment counter
                    counter[blockSize - 1] = (counter[blockSize - 1] + 1) | 0;
                    xorBlock(blockSize, keystream.to_owned(), dataWords, offset);
                    offset += blockSize;
                }
                process = counter;
            }
            _ => {}
        }
    }

    process
}

#[wasm_bindgen]
pub fn doDecrypt(mode: &str, nRounds: usize, nWordsReady: usize, blockSize: usize, iv: &[u32], dataWords: &mut [u32], keySchedule: &[u32], invKeySchedule: &[u32]) -> Vec<u32> {
    let mut process: Vec<u32> = Vec::new();
    if nWordsReady > 0 {
        let mut offset: usize = 0;
        match mode.to_lowercase().as_str() {
            "cbc" => {
                let mut prevBlock = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    let thisBlock = dataWords[offset..offset + blockSize].to_vec();
                    decryptBlock(nRounds, dataWords, offset, invKeySchedule);
                    xorBlock(blockSize, prevBlock, dataWords, offset);
                    prevBlock = thisBlock;
                    offset += blockSize;
                }
                process = prevBlock;
            }
            "ecb" => {
                while offset < nWordsReady {
                    decryptBlock(nRounds, dataWords, offset, invKeySchedule);
                    offset += blockSize;
                }
            }
            "cfb" => {
                let mut prevBlock = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    let thisBlock = dataWords[offset..offset + blockSize].to_vec();
                    let keystream = &mut prevBlock;
                    encryptBlock(nRounds, keystream, 0, keySchedule);
                    xorBlock(blockSize, keystream.to_owned(), dataWords, offset);
                    prevBlock = thisBlock;
                    offset += blockSize;
                }
                process = prevBlock;
            }
            "ofb" => {
                let mut keystream = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    encryptBlock(nRounds, &mut keystream, 0, keySchedule);
                    xorBlock(blockSize, keystream.to_owned(), dataWords, offset);
                    offset += blockSize;
                }
                process = keystream;
            }
            "ctr" => {
                let mut counter = iv[0..blockSize].to_vec();
                let mut keystream;
                while offset < nWordsReady {
                    keystream = counter.clone();
                    encryptBlock(nRounds, &mut keystream, 0, keySchedule);
                    // Increment counter
                    counter[blockSize - 1] = (counter[blockSize - 1] + 1) | 0;
                    xorBlock(blockSize, keystream.to_owned(), dataWords, offset);
                    offset += blockSize;
                }
                process = counter;
            }
            _ => {}
        }
    }

    process
}

fn xorBlock(blockSize: usize, block: Vec<u32>, words: &mut [u32], offset: usize) {
    // XOR blocks
    for i in 0..blockSize {
        words[offset + i] ^= &block[i];
    }
}

fn encryptBlock(nRounds: usize, dataWords: &mut [u32], offset: usize, keySchedule: &[u32]) {
    let SUB_MIX_0 = &getSubMix0();
    let SUB_MIX_1 = &getSubMix1();
    let SUB_MIX_2 = &getSubMix2();
    let SUB_MIX_3 = &getSubMix3();
    let SBOX = &getSbox();

    doCryptBlock(nRounds, dataWords, offset, keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX);
}

fn decryptBlock(nRounds: usize, dataWords: &mut [u32], offset: usize, invKeySchedule: &[u32]) {
    // Swap 2nd and 4th rows
    let mut t = dataWords[offset + 1];
    dataWords[offset + 1] = dataWords[offset + 3];
    dataWords[offset + 3] = t;

    let INV_SUB_MIX_0 = &getInvSubMix0();
    let INV_SUB_MIX_1 = &getInvSubMix1();
    let INV_SUB_MIX_2 = &getInvSubMix2();
    let INV_SUB_MIX_3 = &getInvSubMix3();
    let INV_SBOX = &getInvSbox();

    doCryptBlock(nRounds, dataWords, offset, invKeySchedule, INV_SUB_MIX_0, INV_SUB_MIX_1, INV_SUB_MIX_2, INV_SUB_MIX_3, INV_SBOX);

    // Inv swap 2nd and 4th rows
    t = dataWords[offset + 1];
    dataWords[offset + 1] = dataWords[offset + 3];
    dataWords[offset + 3] = t;
}

fn doCryptBlock(nRounds: usize, dataWords: &mut [u32], offset: usize, keySchedule: &[u32], SUB_MIX_0: &[u32], SUB_MIX_1: &[u32], SUB_MIX_2: &[u32], SUB_MIX_3: &[u32], SBOX: &[u32]) {
    // Get input, add round key
    let mut s0 = dataWords[offset] ^ keySchedule[0];
    let mut s1 = dataWords[offset + 1] ^ keySchedule[1];
    let mut s2 = dataWords[offset + 2] ^ keySchedule[2];
    let mut s3 = dataWords[offset + 3] ^ keySchedule[3];

    // Key schedule row counter
    let mut ksRow = 4;

    // Rounds
    for round in 1..nRounds {
        // Shift rows, sub bytes, mix columns, add round key
        let t0 = SUB_MIX_0[(s0 >> 24) as usize] ^ SUB_MIX_1[((s1 >> 16) & 0xff) as usize] ^ SUB_MIX_2[((s2 >> 8) & 0xff) as usize] ^ SUB_MIX_3[(s3 & 0xff) as usize] ^ keySchedule[ksRow];
        ksRow += 1;
        let t1 = SUB_MIX_0[(s1 >> 24) as usize] ^ SUB_MIX_1[((s2 >> 16) & 0xff) as usize] ^ SUB_MIX_2[((s3 >> 8) & 0xff) as usize] ^ SUB_MIX_3[(s0 & 0xff) as usize] ^ keySchedule[ksRow];
        ksRow += 1;
        let t2 = SUB_MIX_0[(s2 >> 24) as usize] ^ SUB_MIX_1[((s3 >> 16) & 0xff) as usize] ^ SUB_MIX_2[((s0 >> 8) & 0xff) as usize] ^ SUB_MIX_3[(s1 & 0xff) as usize] ^ keySchedule[ksRow];
        ksRow += 1;
        let t3 = SUB_MIX_0[(s3 >> 24) as usize] ^ SUB_MIX_1[((s0 >> 16) & 0xff) as usize] ^ SUB_MIX_2[((s1 >> 8) & 0xff) as usize] ^ SUB_MIX_3[(s2 & 0xff) as usize] ^ keySchedule[ksRow];
        ksRow += 1;

        // Update state
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }

    // Shift rows, sub bytes, add round key
    let t0 = ((SBOX[(s0 >> 24) as usize] << 24) | (SBOX[((s1 >> 16) & 0xff) as usize] << 16) | (SBOX[((s2 >> 8) & 0xff) as usize] << 8) | SBOX[(s3 & 0xff) as usize]) ^ keySchedule[ksRow];
    ksRow += 1;
    let t1 = ((SBOX[(s1 >> 24) as usize] << 24) | (SBOX[((s2 >> 16) & 0xff) as usize] << 16) | (SBOX[((s3 >> 8) & 0xff) as usize] << 8) | SBOX[(s0 & 0xff) as usize]) ^ keySchedule[ksRow];
    ksRow += 1;
    let t2 = ((SBOX[(s2 >> 24) as usize] << 24) | (SBOX[((s3 >> 16) & 0xff) as usize] << 16) | (SBOX[((s0 >> 8) & 0xff) as usize] << 8) | SBOX[(s1 & 0xff) as usize]) ^ keySchedule[ksRow];
    ksRow += 1;
    let t3 = ((SBOX[(s3 >> 24) as usize] << 24) | (SBOX[((s0 >> 16) & 0xff) as usize] << 16) | (SBOX[((s1 >> 8) & 0xff) as usize] << 8) | SBOX[(s2 & 0xff) as usize]) ^ keySchedule[ksRow];
    ksRow += 1;

    // Set output
    dataWords[offset] = t0;
    dataWords[offset + 1] = t1;
    dataWords[offset + 2] = t2;
    dataWords[offset + 3] = t3;
}
