// poseidon2_perm.circom
pragma circom 2.0.0;

/*
 Generic Poseidon-like permutation template.
 - t: state width (number of field elements in state)
 - Rf: number of full rounds (split as Rf/2 before and after)
 - Rp: number of partial rounds
 - d: S-box exponent (e.g., 5)
 - RC and MDS are expected to be provided as constant arrays (in constants.circom)
*/

template PoseidonPerm(t, Rf, Rp, d) {
    signal input in[t];
    signal output out[t];

    // total rounds
    var totalRounds = Rf + Rp;
    // We expect RC as flat array of length totalRounds * t
    // And MDS as t x t matrix in row-major

    // expose constants via include from constants.circom (user must prepare)
    // Example extern arrays:
    // const RC = [...]; // length totalRounds * t
    // const MDS = [...]; // length t * t

    // We'll use index helpers via var/let
    var state = [];
    for (var i = 0; i < t; i++) {
        state.push(in[i]);
    }

    var rcIdx = 0;
    // Half full rounds before and after
    var halfFull = Rf/2;

    for (var r = 0; r < totalRounds; r++) {
        // add round constants
        for (var i = 0; i < t; i++) {
            // state[i] = state[i] + RC[rcIdx];
            state[i] = state[i] + RC[rcIdx + i];
        }
        rcIdx += t;

        // S-box:
        if (r < halfFull || r >= (halfFull + Rp)) {
            // full round: apply S to all elements
            for (var i = 0; i < t; i++) {
                // compute x^d; expand for small d (d assumed small like 5)
                // Circom: to compute x^5 do: x2 = x*x; x4 = x2*x2; x5 = x4 * x;
                signal tmp = state[i];
                signal x2 = tmp * tmp;
                signal x4 = x2 * x2;
                state[i] = x4 * tmp; // x^5
            }
        } else {
            // partial round: apply S only to first state element
            {
                signal tmp = state[0];
                signal x2 = tmp * tmp;
                signal x4 = x2 * x2;
                state[0] = x4 * tmp; // x^5
            }
        }

        // linear layer: state = MDS * state
        var newState = [];
        for (var i = 0; i < t; i++) {
            signal acc = 0;
            for (var j = 0; j < t; j++) {
                // MDS is row-major; element at (i,j) is MDS[i*t + j]
                acc += MDS[i*t + j] * state[j];
            }
            newState.push(acc);
        }
        state = newState;
    }

    for (var i = 0; i < t; i++) {
        out[i] <== state[i];
    }
}
