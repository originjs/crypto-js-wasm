mod utils;

use crate::utils::{getORIG_P, getORIG_S};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn blowfishInit(key: &[u32], keySize: usize) -> Vec<u32> {
    let mut sbox: Vec<[u32; 256]> = Vec::new();
    for i in 0..4 {
        sbox.push([0; 256]);
    }
    let ORIG_S = getORIG_S();
    for Row in 0..4 {
        for Col in 0..256 {
            sbox[Row][Col] = ORIG_S[Row][Col];
        }
    }
    let mut pbox: [u32; 18] = [0; 18];
    let ORIG_P = getORIG_P();
    let mut keyIndex: usize = 0;
    for index in 0..18 {
        pbox[index] = ORIG_P[index] ^ key[keyIndex];
        keyIndex += 1;
        if keyIndex >= keySize {
            keyIndex = 0;
        }
    }

    let mut Data1 = 0;
    let mut Data2 = 0;
    let mut res: [u32; 2] = [0, 0];
    let mut i: usize = 0;
    while i < 18 {
        res = blowfishEncrypt(&pbox, &sbox, Data1, Data2);
        Data1 = res[0];
        Data2 = res[1];
        pbox[i] = Data1;
        pbox[i + 1] = Data2;
        i += 2;
    }

    for i in 0..4 {
        let mut j: usize = 0;
        while j < 256 {
            res = blowfishEncrypt(&pbox, &sbox, Data1, Data2);
            Data1 = res[0];
            Data2 = res[1];
            sbox[i][j] = Data1;
            sbox[i][j + 1] = Data2;
            j += 2;
        }
    }

    let mut ctx: Vec<u32> = Vec::new();
    for i in 0..18 {
        ctx.push(pbox[i]);
    }
    for i in 0..4 {
        for j in 0..256 {
            ctx.push(sbox[i][j]);
        }
    }

    ctx
}

#[wasm_bindgen]
pub fn doEncrypt(
    mode: &str,
    nWordsReady: usize,
    blockSize: usize,
    iv: &[u32],
    dataWords: &mut [u32],
    P: &[u32],
    S: &[u32],
) -> Vec<u32> {
    let mut pbox: [u32; 18] = [0; 18];
    for i in 0..18 {
        pbox[i] = P[i];
    }
    let mut sbox: Vec<[u32; 256]> = Vec::new();
    for i in 0..4 {
        let mut sboxi: [u32; 256] = [0; 256];
        for j in 0..256 {
            sboxi[j] = S[i * 256 + j];
        }
        sbox.push(sboxi);
    }
    let mut process: Vec<u32> = Vec::new();
    if nWordsReady > 0 {
        let mut offset: usize = 0;
        match mode.to_lowercase().as_str() {
            "cbc" => {
                let mut prevBlock = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    xorBlock(blockSize, prevBlock, dataWords, offset);
                    encryptBlock(dataWords, offset, &pbox, &sbox);
                    prevBlock = dataWords[offset..offset + blockSize].to_vec();
                    offset += blockSize;
                }
                process = prevBlock;
            }
            "ecb" => {
                while offset < nWordsReady {
                    encryptBlock(dataWords, offset, &pbox, &sbox);
                    offset += blockSize;
                }
            }
            "cfb" => {
                let mut prevBlock = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    let mut keystream = prevBlock;
                    encryptBlock(&mut keystream, 0, &pbox, &sbox);
                    xorBlock(blockSize, keystream.to_owned(), dataWords, offset);
                    prevBlock = dataWords[offset..offset + blockSize].to_vec();
                    offset += blockSize;
                }
                process = prevBlock;
            }
            "ofb" => {
                let mut keystream = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    encryptBlock(&mut keystream, 0, &pbox, &sbox);
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
                    encryptBlock(&mut keystream, 0, &pbox, &sbox);
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
    P: &[u32],
    S: &[u32],
) -> Vec<u32> {
    let mut pbox: [u32; 18] = [0; 18];
    for i in 0..18 {
        pbox[i] = P[i];
    }
    let mut sbox: Vec<[u32; 256]> = Vec::new();
    for i in 0..4 {
        let mut sboxi: [u32; 256] = [0; 256];
        for j in 0..256 {
            sboxi[j] = S[i * 256 + j];
        }
        sbox.push(sboxi);
    }
    let mut process: Vec<u32> = Vec::new();
    if nWordsReady > 0 {
        let mut offset: usize = 0;
        match mode.to_lowercase().as_str() {
            "cbc" => {
                let mut prevBlock = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    let thisBlock = dataWords[offset..offset + blockSize].to_vec();
                    decryptBlock(dataWords, offset, &pbox, &sbox);
                    xorBlock(blockSize, prevBlock, dataWords, offset);
                    prevBlock = thisBlock;
                    offset += blockSize;
                }
                process = prevBlock;
            }
            "ecb" => {
                while offset < nWordsReady {
                    decryptBlock(dataWords, offset, &pbox, &sbox);
                    offset += blockSize;
                }
            }
            "cfb" => {
                let mut prevBlock = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    let thisBlock = dataWords[offset..offset + blockSize].to_vec();
                    let keystream = &mut prevBlock;
                    encryptBlock(keystream, 0, &pbox, &sbox);
                    xorBlock(blockSize, keystream.to_owned(), dataWords, offset);
                    prevBlock = thisBlock;
                    offset += blockSize;
                }
                process = prevBlock;
            }
            "ofb" => {
                let mut keystream = iv[0..blockSize].to_vec();
                while offset < nWordsReady {
                    encryptBlock(&mut keystream, 0, &pbox, &sbox);
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
                    encryptBlock(&mut keystream, 0, &pbox, &sbox);
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

fn encryptBlock(dataWords: &mut [u32], offset: usize, pbox: &[u32; 18], sbox: &Vec<[u32; 256]>) {
    let res = blowfishEncrypt(pbox, sbox, dataWords[offset], dataWords[offset + 1]);
    dataWords[offset] = res[0];
    dataWords[offset + 1] = res[1];
}

fn decryptBlock(dataWords: &mut [u32], offset: usize, pbox: &[u32; 18], sbox: &Vec<[u32; 256]>) {
    let res = blowfishDecrypt(pbox, sbox, dataWords[offset], dataWords[offset + 1]);
    dataWords[offset] = res[0];
    dataWords[offset + 1] = res[1];
}

fn blowfishEncrypt(pbox: &[u32; 18], sbox: &Vec<[u32; 256]>, left: u32, right: u32) -> [u32; 2] {
    let mut Xl = left;
    let mut Xr = right;
    let mut temp;

    for i in 0..16 {
        Xl = Xl ^ pbox[i];
        Xr = F(sbox, Xl) ^ Xr;

        temp = Xl;
        Xl = Xr;
        Xr = temp;
    }

    temp = Xl;
    Xl = Xr;
    Xr = temp;

    Xr = Xr ^ pbox[16];
    Xl = Xl ^ pbox[17];

    let res: [u32; 2] = [Xl, Xr];

    res
}

fn blowfishDecrypt(pbox: &[u32; 18], sbox: &Vec<[u32; 256]>, left: u32, right: u32) -> [u32; 2] {
    let mut Xl = left;
    let mut Xr = right;
    let mut temp;

    let mut i: usize = 17;
    while i > 1 {
        Xl = Xl ^ pbox[i];
        Xr = F(sbox, Xl) ^ Xr;

        temp = Xl;
        Xl = Xr;
        Xr = temp;

        i -= 1;
    }

    temp = Xl;
    Xl = Xr;
    Xr = temp;

    Xr = Xr ^ pbox[1];
    Xl = Xl ^ pbox[0];

    let res: [u32; 2] = [Xl, Xr];

    res
}

fn F(sbox: &Vec<[u32; 256]>, x: u32) -> u32 {
    let a = (x >> 24) & 0xFF;
    let b = (x >> 16) & 0xFF;
    let c = (x >> 8) & 0xFF;
    let d = x & 0xFF;

    let mut y = (sbox[0][a as usize] as u64 + sbox[1][b as usize] as u64) as u32;
    y = y ^ sbox[2][c as usize];
    y = (y as u64 + sbox[3][d as usize] as u64) as u32;

    y
}
