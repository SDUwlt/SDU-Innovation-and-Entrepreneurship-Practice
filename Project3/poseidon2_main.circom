// poseidon2_main.circom
pragma circom 2.0.0;

include "poseidon2_perm.circom";
include "constants.circom"; // generated from the paper or placeholder

// Parameters: adjust t,Rf,Rp,d to match the paper's config for (t=2 or 3, d=5)
template Poseidon2HashCircuit() {
    // For example we implement t=3; if you want t=2 change template instantiation below.
    // Private input: preimage as bits (256 bits) OR as field elements; here we accept two field elements (low, high).
    signal input pre_lo; // field element representing low part of 256-bit
    signal input pre_hi; // field element representing high part of 256-bit (so total 256-bit = hi<<128 | lo)
    signal output pub_hash; // public hash output

    // packing/consistency checks could be added if user gives bits; omitted for brevity

    // sponge state width t
    var t = STATE_T; // STATE_T should be set in constants.circom (2 or 3)
    // instantiate permutation
    component perm = PoseidonPerm(STATE_T, FULL_ROUNDS, PARTIAL_ROUNDS, SBOX_D);

    // initialize state to zero vector of length t
    // We'll construct the absorb state: state[0] = pre_lo, state[1] = pre_hi, other states = 0
    signal stateIn[STATE_T];
    // assign
    stateIn[0] <== pre_lo;
    if (STATE_T >= 2) {
        stateIn[1] <== pre_hi;
    }
    for (var i = 2; i < STATE_T; i++) {
        stateIn[i] <== 0;
    }

    // wire permutation input
    for (var i = 0; i < STATE_T; i++) {
        perm.in[i] <== stateIn[i];
    }

    for (var i = 0; i < STATE_T; i++) {
        // perm.out[i] assigned automatically
    }

    // output: take perm.out[0] as hash
    pub_hash <== perm.out[0];
}

// instantiate
component main = Poseidon2HashCircuit();
