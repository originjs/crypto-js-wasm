mod utils;

use std::ptr::null;
use std::cmp;
use wasm_bindgen::prelude::*;
use utils::*;


#[wasm_bindgen]
pub fn doCrypt(doFlush: u8, dataWords: &[u32], dataSigBytes: u32, blockSize: u32, stateData: &mut [u32], minBufferSize: u32) -> u32 {
    let blockSizeBytes = blockSize * 4;
    let mut nBlocksReady: f32 = dataSigBytes as f32 / blockSizeBytes as f32;
    if doFlush > 0 {
        nBlocksReady = nBlocksReady.ceil();
    } else {
        nBlocksReady = f32::max(nBlocksReady - minBufferSize as f32, 0_f32);
    }

    let nWordsReady = nBlocksReady as u32 * blockSize;

    let mut state: [X64Word; 25] = [X64Word { high: 0, low: 0 }; 25];
    for i in 0..25 {
        state[i].high = stateData[i * 2];
        state[i].low = stateData[i * 2 + 1];
    }

    let mut T: [X64Word; 25] = [X64Word { high: 0, low: 0 }; 25];

    let mut i: usize = 0;

    if nWordsReady > 0 {
        let mut offset = 0;
        while offset < nWordsReady {
            doCryptBlock(dataWords, offset, blockSize, &mut state, &mut T);
            offset += blockSize;
        }
    }

    i = 0;
    while i < 25 {
        stateData[i * 2] = state[i].high;
        stateData[i * 2 + 1] = state[i].low;
        i += 1;
    }

    nWordsReady
}

fn doCryptBlock(data: &[u32], offsetU32: u32, blockSize: u32, state: &mut [X64Word; 25], T: &mut [X64Word; 25]) {
    let RHO_OFFSETS = getRhoOffsets();
    let PI_INDEXES = getPiIndexes();
    let ROUND_CONSTANTS = getRoundConstants();
    let offset = offsetU32 as usize;

    let nBlockSizeLanes = (blockSize / 2) as usize;

    let mut i: usize = 0;
    // Absorb
    while i < nBlockSizeLanes {
        // Shortcuts
        let mut data2i  = data[offset + 2 * i];
        let mut data2i1 = data[offset + 2 * i + 1];

        // Swap endian
        data2i = (
            (((data2i << 8)  | (data2i >> 24)) & 0x00ff00ff) |
            (((data2i << 24) | (data2i >> 8))  & 0xff00ff00)
        );
        data2i1 = (
            (((data2i1 << 8)  | (data2i1 >> 24)) & 0x00ff00ff) |
            (((data2i1 << 24) | (data2i1 >> 8))  & 0xff00ff00)
        ); 

        // Absorb message into state
        let lane = &mut state[i];
        lane.high ^= data2i1;
        lane.low  ^= data2i;

        i += 1;
    }

    let mut round: usize = 0;
    // Rounds
    while round < 24 {
        let mut x: usize = 0;
        // Theta
        while x < 5 {
            // Mix column lanes
            let mut tMsw: u32 = 0;
            let mut tLsw: u32 = 0;
            let mut y: usize = 0;
            while y < 5 {
                let lane = &mut state[x + 5 * y];
                tMsw ^= lane.high;
                tLsw ^= lane.low;
                y += 1;
            }

            // Temporary values
            let Tx = &mut T[x];
            Tx.high = tMsw;
            Tx.low  = tLsw;

            x += 1;
        }
        x = 0;
        while x < 5 {
            // Shortcuts
            let Tx4 = &T[(x + 4) % 5];
            let Tx1 = &T[(x + 1) % 5];
            let Tx1Msw = Tx1.high;
            let Tx1Lsw = Tx1.low;

            // Mix surrounding columns
            let tMsw = Tx4.high ^ ((Tx1Msw << 1) | (Tx1Lsw >> 31));
            let tLsw = Tx4.low  ^ ((Tx1Lsw << 1) | (Tx1Msw >> 31));
            let mut y: usize = 0;
            while y < 5 {
                let lane = &mut state[x + 5 * y];
                lane.high ^= tMsw;
                lane.low  ^= tLsw;
                y += 1;
            }
            x += 1;
        }

        // Rho Pi
        for laneIndex in 1..25 {
            let mut tMsw: u32 = 0;
            let mut tLsw: u32 = 0;

            // Shortcuts
            let lane = &mut state[laneIndex];
            let laneMsw = lane.high;
            let laneLsw = lane.low;
            let rhoOffset = RHO_OFFSETS[laneIndex];

            // Rotate lanes
            if rhoOffset < 32 {
                tMsw = (laneMsw << rhoOffset) | (laneLsw >> (32 - rhoOffset));
                tLsw = (laneLsw << rhoOffset) | (laneMsw >> (32 - rhoOffset));
            } else /* if (rhoOffset >= 32) */ {
                tMsw = (laneLsw << (rhoOffset - 32)) | (laneMsw >> (64 - rhoOffset));
                tLsw = (laneMsw << (rhoOffset - 32)) | (laneLsw >> (64 - rhoOffset));
            }

            // Transpose lanes
            let TPiLane = &mut T[PI_INDEXES[laneIndex] as usize];
            TPiLane.high = tMsw;
            TPiLane.low  = tLsw;
        }

        // Rho pi at x = y = 0
        let T0 = &mut T[0];
        let state0 = &mut state[0];
        T0.high = state0.high;
        T0.low  = state0.low;

        x = 0;
        // Chi
        while x < 5 {
            let mut y: usize = 0;
            while y < 5 {
                // Shortcuts
                let laneIndex = x + 5 * y;
                let lane = &mut state[laneIndex];
                let TLane = &T[laneIndex];
                let Tx1Lane = &T[((x + 1) % 5) + 5 * y];
                let Tx2Lane = &T[((x + 2) % 5) + 5 * y];

                // Mix rows
                lane.high = TLane.high ^ (!Tx1Lane.high & Tx2Lane.high);
                lane.low  = TLane.low  ^ (!Tx1Lane.low  & Tx2Lane.low);
                y += 1;
            }
            x += 1;
        }

        // Iota
        let lane = &mut state[0];
        let roundConstant = ROUND_CONSTANTS[round];
        lane.high ^= roundConstant.high;
        lane.low  ^= roundConstant.low;

        round += 1;
    }
}
