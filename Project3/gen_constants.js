// gen_constants.js
// Node.js skeleton: generate constants.circom for Poseidon2
// NOTE: You MUST implement the exact constant-generation procedure from the Poseidon2 paper.
// This skeleton shows how to produce a circom constants file from computed BigIntegers.

const fs = require('fs');
const BN = require('bn.js'); // npm install bn.js

// --- CONFIG (replace with paper values) ---
const STATE_T = 3;
const FULL_ROUNDS = 8; // replace
const PARTIAL_ROUNDS = 57; // replace
const SBOX_D = 5;
const TOTAL_ROUNDS = FULL_ROUNDS + PARTIAL_ROUNDS;

// prime field modulus for target zk curve (bn128 prime) — choose accordingly
const FIELD_P = new BN("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10);

// Example: dummy RC generation (replace with real PRG per paper)
function exampleGenRC() {
    const rc = [];
    for (let r = 0; r < TOTAL_ROUNDS; r++) {
        for (let i = 0; i < STATE_T; i++) {
            // For demo: just use (r*STATE_T + i + 1) mod p
            rc.push(new BN(r*STATE_T + i + 1));
        }
    }
    return rc;
}

// Example: dummy MDS gen (replace with paper's MDS gen)
function exampleGenMDS() {
    // identity matrix
    const mds = [];
    for (let i = 0; i < STATE_T; i++) {
        for (let j = 0; j < STATE_T; j++) {
            mds.push(new BN(i === j ? 1 : 0));
        }
    }
    return mds;
}

function bnToDecStr(bn) {
    return bn.toString(10);
}

function writeConstants(rc, mds) {
    const rcStr = rc.map(bnToDecStr).join(",\n    ");
    const mdsStr = mds.map(bnToDecStr).join(",\n    ");
    const content = `pragma circom 2.0.0;

const STATE_T = ${STATE_T};
const FULL_ROUNDS = ${FULL_ROUNDS};
const PARTIAL_ROUNDS = ${PARTIAL_ROUNDS};
const SBOX_D = ${SBOX_D};

const RC = [
    ${rcStr}
];

const MDS = [
    ${mdsStr}
];
`;
    fs.writeFileSync("constants.circom", content);
    console.log("Wrote constants.circom");
}

function main() {
    // TODO: Replace exampleGenRC/mds with real generator implementing paper algorithm
    const rc = exampleGenRC();
    const mds = exampleGenMDS();
    writeConstants(rc, mds);
}

main();
