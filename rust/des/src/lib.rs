mod utils;

use crate::utils::{getInvSubKeys, getSboxMask, getSboxP, getSubKeys};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn doEncrypt(
    mode: &str,
    nWordsReady: usize,
    blockSize: usize,
    iv: &[u32],
    dataWords: &mut [u32],
    keyWords: &[u32],
) -> Vec<u32> {
    let subKeys = getSubKeys(keyWords);
    let SBOX_P = getSboxP();
    let SBOX_MASK = getSboxMask();
    let mut process: Vec<u32> = Vec::new();
    if nWordsReady > 0 {
        let mut offset: usize = 0;
        match mode.to_lowercase().as_str() {
            "cbc" => {
                let mut prevBlock = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    xorBlock(blockSize, prevBlock, dataWords, offset);
                    doCryptBlock(dataWords, offset, &subKeys, &SBOX_P, &SBOX_MASK);
                    prevBlock = dataWords[offset..offset + blockSize].to_vec();
                    offset += blockSize;
                }
                process = prevBlock;
            }
            "ecb" => {
                while offset < nWordsReady {
                    doCryptBlock(dataWords, offset, &subKeys, &SBOX_P, &SBOX_MASK);
                    offset += blockSize;
                }
            }
            "cfb" => {
                let mut prevBlock = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    let mut keystream = prevBlock;
                    doCryptBlock(&mut keystream, 0, &subKeys, &SBOX_P, &SBOX_MASK);
                    xorBlock(blockSize, keystream.to_owned(), dataWords, offset);
                    prevBlock = dataWords[offset..offset + blockSize].to_vec();
                    offset += blockSize;
                }
                process = prevBlock;
            }
            "ofb" => {
                let mut keystream = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    doCryptBlock(&mut keystream, 0, &subKeys, &SBOX_P, &SBOX_MASK);
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
                    doCryptBlock(&mut keystream, 0, &subKeys, &SBOX_P, &SBOX_MASK);
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
pub fn doDecrypt(
    mode: &str,
    nWordsReady: usize,
    blockSize: usize,
    iv: &[u32],
    dataWords: &mut [u32],
    keyWords: &[u32],
) -> Vec<u32> {
    let subKeys = getSubKeys(keyWords);
    let invSubKeys = getInvSubKeys(&subKeys);
    let SBOX_P = getSboxP();
    let SBOX_MASK = getSboxMask();
    let mut process: Vec<u32> = Vec::new();
    if nWordsReady > 0 {
        let mut offset: usize = 0;
        match mode.to_lowercase().as_str() {
            "cbc" => {
                let mut prevBlock = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    let thisBlock = dataWords[offset..offset + blockSize].to_vec();
                    doCryptBlock(dataWords, offset, &invSubKeys, &SBOX_P, &SBOX_MASK);
                    xorBlock(blockSize, prevBlock, dataWords, offset);
                    prevBlock = thisBlock;
                    offset += blockSize;
                }
                process = prevBlock;
            }
            "ecb" => {
                while offset < nWordsReady {
                    doCryptBlock(dataWords, offset, &invSubKeys, &SBOX_P, &SBOX_MASK);
                    offset += blockSize;
                }
            }
            "cfb" => {
                let mut prevBlock = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    let thisBlock = dataWords[offset..offset + blockSize].to_vec();
                    let keystream = &mut prevBlock;
                    doCryptBlock(keystream, 0, &subKeys, &SBOX_P, &SBOX_MASK);
                    xorBlock(blockSize, keystream.to_owned(), dataWords, offset);
                    prevBlock = thisBlock;
                    offset += blockSize;
                }
                process = prevBlock;
            }
            "ofb" => {
                let mut keystream = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    doCryptBlock(&mut keystream, 0, &subKeys, &SBOX_P, &SBOX_MASK);
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
                    doCryptBlock(&mut keystream, 0, &subKeys, &SBOX_P, &SBOX_MASK);
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
pub fn tripleEncrypt(
    mode: &str,
    nWordsReady: usize,
    blockSize: usize,
    iv: &[u32],
    dataWords: &mut [u32],
    keyWords1: &[u32],
    keyWords2: &[u32],
    keyWords3: &[u32],
) -> Vec<u32> {
    let subKeys1 = getSubKeys(keyWords1);
    let subKeys2 = getSubKeys(keyWords2);
    let subKeys3 = getSubKeys(keyWords3);
    let invSubKeys2 = getInvSubKeys(&subKeys2);
    let SBOX_P = getSboxP();
    let SBOX_MASK = getSboxMask();
    let mut process: Vec<u32> = Vec::new();
    if nWordsReady > 0 {
        let mut offset: usize = 0;
        match mode.to_lowercase().as_str() {
            "cbc" => {
                let mut prevBlock = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    xorBlock(blockSize, prevBlock, dataWords, offset);
                    doCryptBlock(dataWords, offset, &subKeys1, &SBOX_P, &SBOX_MASK);
                    doCryptBlock(dataWords, offset, &invSubKeys2, &SBOX_P, &SBOX_MASK);
                    doCryptBlock(dataWords, offset, &subKeys3, &SBOX_P, &SBOX_MASK);
                    prevBlock = dataWords[offset..offset + blockSize].to_vec();
                    offset += blockSize;
                }
                process = prevBlock;
            }
            "ecb" => {
                while offset < nWordsReady {
                    doCryptBlock(dataWords, offset, &subKeys1, &SBOX_P, &SBOX_MASK);
                    doCryptBlock(dataWords, offset, &invSubKeys2, &SBOX_P, &SBOX_MASK);
                    doCryptBlock(dataWords, offset, &subKeys3, &SBOX_P, &SBOX_MASK);
                    offset += blockSize;
                }
            }
            "cfb" => {
                let mut prevBlock = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    let mut keystream = prevBlock;
                    doCryptBlock(&mut keystream, 0, &subKeys1, &SBOX_P, &SBOX_MASK);
                    doCryptBlock(&mut keystream, 0, &invSubKeys2, &SBOX_P, &SBOX_MASK);
                    doCryptBlock(&mut keystream, 0, &subKeys3, &SBOX_P, &SBOX_MASK);
                    xorBlock(blockSize, keystream.to_owned(), dataWords, offset);
                    prevBlock = dataWords[offset..offset + blockSize].to_vec();
                    offset += blockSize;
                }
                process = prevBlock;
            }
            "ofb" => {
                let mut keystream = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    doCryptBlock(&mut keystream, 0, &subKeys1, &SBOX_P, &SBOX_MASK);
                    doCryptBlock(&mut keystream, 0, &invSubKeys2, &SBOX_P, &SBOX_MASK);
                    doCryptBlock(&mut keystream, 0, &subKeys3, &SBOX_P, &SBOX_MASK);
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
                    doCryptBlock(&mut keystream, 0, &subKeys1, &SBOX_P, &SBOX_MASK);
                    doCryptBlock(&mut keystream, 0, &invSubKeys2, &SBOX_P, &SBOX_MASK);
                    doCryptBlock(&mut keystream, 0, &subKeys3, &SBOX_P, &SBOX_MASK);
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
pub fn tripleDecrypt(
    mode: &str,
    nWordsReady: usize,
    blockSize: usize,
    iv: &[u32],
    dataWords: &mut [u32],
    keyWords1: &[u32],
    keyWords2: &[u32],
    keyWords3: &[u32],
) -> Vec<u32> {
    let subKeys1 = getSubKeys(keyWords1);
    let subKeys2 = getSubKeys(keyWords2);
    let subKeys3 = getSubKeys(keyWords3);
    let invSubKeys1 = getInvSubKeys(&subKeys1);
    let invSubKeys2 = getInvSubKeys(&subKeys2);
    let invSubKeys3 = getInvSubKeys(&subKeys3);
    let SBOX_P = getSboxP();
    let SBOX_MASK = getSboxMask();
    let mut process: Vec<u32> = Vec::new();
    if nWordsReady > 0 {
        let mut offset: usize = 0;
        match mode.to_lowercase().as_str() {
            "cbc" => {
                let mut prevBlock = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    let thisBlock = dataWords[offset..offset + blockSize].to_vec();
                    doCryptBlock(dataWords, offset, &invSubKeys3, &SBOX_P, &SBOX_MASK);
                    doCryptBlock(dataWords, offset, &subKeys2, &SBOX_P, &SBOX_MASK);
                    doCryptBlock(dataWords, offset, &invSubKeys1, &SBOX_P, &SBOX_MASK);
                    xorBlock(blockSize, prevBlock, dataWords, offset);
                    prevBlock = thisBlock;
                    offset += blockSize;
                }
                process = prevBlock;
            }
            "ecb" => {
                while offset < nWordsReady {
                    doCryptBlock(dataWords, offset, &invSubKeys3, &SBOX_P, &SBOX_MASK);
                    doCryptBlock(dataWords, offset, &subKeys2, &SBOX_P, &SBOX_MASK);
                    doCryptBlock(dataWords, offset, &invSubKeys1, &SBOX_P, &SBOX_MASK);
                    offset += blockSize;
                }
            }
            "cfb" => {
                let mut prevBlock = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    let thisBlock = dataWords[offset..offset + blockSize].to_vec();
                    let keystream = &mut prevBlock;
                    doCryptBlock(keystream, 0, &subKeys1, &SBOX_P, &SBOX_MASK);
                    doCryptBlock(keystream, 0, &invSubKeys2, &SBOX_P, &SBOX_MASK);
                    doCryptBlock(keystream, 0, &subKeys3, &SBOX_P, &SBOX_MASK);
                    xorBlock(blockSize, keystream.to_owned(), dataWords, offset);
                    prevBlock = thisBlock;
                    offset += blockSize;
                }
                process = prevBlock;
            }
            "ofb" => {
                let mut keystream = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    doCryptBlock(&mut keystream, 0, &subKeys1, &SBOX_P, &SBOX_MASK);
                    doCryptBlock(&mut keystream, 0, &invSubKeys2, &SBOX_P, &SBOX_MASK);
                    doCryptBlock(&mut keystream, 0, &subKeys3, &SBOX_P, &SBOX_MASK);
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
                    doCryptBlock(&mut keystream, 0, &subKeys1, &SBOX_P, &SBOX_MASK);
                    doCryptBlock(&mut keystream, 0, &invSubKeys2, &SBOX_P, &SBOX_MASK);
                    doCryptBlock(&mut keystream, 0, &subKeys3, &SBOX_P, &SBOX_MASK);
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

fn doCryptBlock(
    dataWords: &mut [u32],
    offset: usize,
    subKeys: &Vec<[u32; 8]>,
    SBOX_P: &Vec<HashMap<u32, u32>>,
    SBOX_dataWordsASK: &[u32; 8],
) {
    // Get input
    let mut lBlock = dataWords[offset];
    let mut rBlock = dataWords[offset + 1];

    // Initial permutation
    exchangeLR(4, 0x0f0f0f0f, &mut lBlock, &mut rBlock);
    exchangeLR(16, 0x0000ffff, &mut lBlock, &mut rBlock);
    exchangeRL(2, 0x33333333, &mut lBlock, &mut rBlock);
    exchangeRL(8, 0x00ff00ff, &mut lBlock, &mut rBlock);
    exchangeLR(1, 0x55555555, &mut lBlock, &mut rBlock);

    // Rounds
    for round in 0..16 {
        let subKey = subKeys[round];
        // Feistel function
        let mut f = 0;
        for i in 0..8 {
            f |= *&SBOX_P[i]
                .get(&((rBlock ^ subKey[i]) & SBOX_dataWordsASK[i]))
                .unwrap();
        }
        let t = lBlock;
        lBlock = rBlock;
        rBlock = t ^ f;
    }

    // Undo swap from last round
    let t = lBlock;
    lBlock = rBlock;
    rBlock = t;

    // Final permutation
    exchangeLR(1, 0x55555555, &mut lBlock, &mut rBlock);
    exchangeRL(8, 0x00ff00ff, &mut lBlock, &mut rBlock);
    exchangeRL(2, 0x33333333, &mut lBlock, &mut rBlock);
    exchangeLR(16, 0x0000ffff, &mut lBlock, &mut rBlock);
    exchangeLR(4, 0x0f0f0f0f, &mut lBlock, &mut rBlock);

    // Set output
    dataWords[offset] = lBlock;
    dataWords[offset + 1] = rBlock;
}

// Swap bits across the left and right words
fn exchangeLR(offset: u32, mask: u32, lBlock: &mut u32, rBlock: &mut u32) {
    let t = ((*lBlock >> offset) ^ *rBlock) & mask;
    *rBlock ^= t;
    *lBlock ^= t << offset;
}

fn exchangeRL(offset: u32, mask: u32, lBlock: &mut u32, rBlock: &mut u32) {
    let t = ((*rBlock >> offset) ^ *lBlock) & mask;
    *lBlock ^= t;
    *rBlock ^= t << offset;
}