#[derive(Copy, Clone, Debug)]
pub struct X64Word {
    pub high: u32,
    pub low: u32,
}

pub fn getRhoOffsets() -> [u32; 25] {
    [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14]
}

pub fn getPiIndexes() -> [u32; 25] {
    [0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4]
}

pub fn getRoundConstants() -> [X64Word; 24] {
    [X64Word {
        high: 0,
        low: 1,
    },
        X64Word {
            high: 0,
            low: 32898,
        },
        X64Word {
            high: 2147483648 as u32,
            low: 32906,
        },
        X64Word {
            high: 2147483648,
            low: 2147516416,
        },
        X64Word {
            high: 0,
            low: 32907,
        },
        X64Word {
            high: 0,
            low: 2147483649,
        },
        X64Word {
            high: 2147483648,
            low: 2147516545,
        },
        X64Word {
            high: 2147483648,
            low: 32777,
        },
        X64Word {
            high: 0,
            low: 138,
        },
        X64Word {
            high: 0,
            low: 136,
        },
        X64Word {
            high: 0,
            low: 2147516425,
        },
        X64Word {
            high: 0,
            low: 2147483658,
        },
        X64Word {
            high: 0,
            low: 2147516555,
        },
        X64Word {
            high: 2147483648,
            low: 139,
        },
        X64Word {
            high: 2147483648,
            low: 32905,
        },
        X64Word {
            high: 2147483648,
            low: 32771,
        },
        X64Word {
            high: 2147483648,
            low: 32770,
        },
        X64Word {
            high: 2147483648,
            low: 128,
        },
        X64Word {
            high: 0,
            low: 32778,
        },
        X64Word {
            high: 2147483648,
            low: 2147483658,
        },
        X64Word {
            high: 2147483648,
            low: 2147516545,
        },
        X64Word {
            high: 2147483648,
            low: 32896,
        },
        X64Word {
            high: 0,
            low: 2147483649,
        },
        X64Word {
            high: 2147483648,
            low: 2147516424,
        }]
}
