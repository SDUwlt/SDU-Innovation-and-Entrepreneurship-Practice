// constants.circom
pragma circom 2.0.0;

// Example placeholder constants.
// IMPORTANT: Replace these placeholders with constants generated per Poseidon2 spec (论文 Table1 / generation method).
// STATE_T: choose 2 or 3 (match user's request)
const STATE_T = 3;
const FULL_ROUNDS = 8;   // 示例值 — 请用论文给的 Rf
const PARTIAL_ROUNDS = 57; // 示例值 — 请用论文给的 Rp
const SBOX_D = 5;

// RC array length = (FULL_ROUNDS + PARTIAL_ROUNDS) * STATE_T
// Fill with sample small numbers for compilation/testing — replace with real large field elements
const RC = [
    1,2,3,
    4,5,6,
    7,8,9
    // ... (must be totalRounds * STATE_T elements)
];

// MDS matrix length = STATE_T * STATE_T  (row-major)
const MDS = [
    1,0,0,
    0,1,0,
    0,0,1
];
