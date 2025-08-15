pragma circom 2.2.2;

// -------------------- S-Box: x^5 --------------------
template Pow5() {
    signal input in;
    signal output out;

    signal x2;
    signal x4;

    x2 <== in * in;
    x4 <== x2 * x2;
    out <== in * x4;
}

// -------------------- Poseidon2 (t=3, d=5) --------------------
template Poseidon2() {
    // 私有输入（单 block，3 元）
    signal input in[3];
    // 公共输出（哈希值）
    signal output out;

    // 参数
    var t = 3;
    var d = 5;
    var rounds_full = 8;          // full rounds 总数
    var rounds_partial = 57;      // partial rounds 总数
    var total_rounds = rounds_full + rounds_partial; // 65

    // ======= 占位轮常数=======
    var round_constants[65][3] = [
        [1, 2, 3], [4, 5, 6], [7, 8, 9], [10, 11, 12],
        [13, 14, 15], [16, 17, 18], [19, 20, 21], [22, 23, 24],
        [25, 26, 27], [28, 29, 30], [31, 32, 33], [34, 35, 36],
        [37, 38, 39], [40, 41, 42], [43, 44, 45], [46, 47, 48],
        [49, 50, 51], [52, 53, 54], [55, 56, 57], [58, 59, 60],
        [61, 62, 63], [64, 65, 66], [67, 68, 69], [70, 71, 72],
        [73, 74, 75], [76, 77, 78], [79, 80, 81], [82, 83, 84],
        [85, 86, 87], [88, 89, 90], [91, 92, 93], [94, 95, 96],
        [97, 98, 99], [100, 101, 102], [103, 104, 105], [106, 107, 108],
        [109, 110, 111], [112, 113, 114], [115, 116, 117], [118, 119, 120],
        [121, 122, 123], [124, 125, 126], [127, 128, 129], [130, 131, 132],
        [133, 134, 135], [136, 137, 138], [139, 140, 141], [142, 143, 144],
        [145, 146, 147], [148, 149, 150], [151, 152, 153], [154, 155, 156],
        [157, 158, 159], [160, 161, 162], [163, 164, 165], [166, 167, 168],
        [169, 170, 171], [172, 173, 174], [175, 176, 177], [178, 179, 180],
        [181, 182, 183], [184, 185, 186], [187, 188, 189], [190, 191, 192],
        [193, 194, 195]
    ];

    // ======= 占位 MDS=======
    var MDS[3][3] = [
        [2, 3, 1],
        [1, 2, 3],
        [3, 1, 2]
    ];

    // ---------- 预分配所有需要的组件与信号（顶层作用域） ----------
    // S-box 组件数量 = full rounds * t + partial rounds（只对 lane 0）
    var num_sboxes = rounds_full * t + rounds_partial;
    component sbox[num_sboxes];
    var sbox_idx = 0;

    // 每轮后的状态（state[0] 为初始；state[total_rounds] 为最终）
    signal state[total_rounds + 1][t];

    // 加常数之后的中间态
    signal after_constants[total_rounds][t];

    // 过 S-box 之后的中间态
    signal after_sbox[total_rounds][t];

    // ---------- 初始化 ----------
    for (var i = 0; i < t; i++) {
        state[0][i] <== in[i];
    }

    // ---------- 主循环：前 RF/2 轮 full，接着 RP 轮 partial，最后 RF/2 轮 full ----------
    for (var r = 0; r < total_rounds; r++) {
        // 1) 加轮常数
        for (var i = 0; i < t; i++) {
            after_constants[r][i] <== state[r][i] + round_constants[r][i];
        }

        // 2) S-box
        if (r < (rounds_full / 2) || r >= (total_rounds - rounds_full / 2)) {
            // ---- Full rounds：对所有 lane 应用 S-box x^5
            for (var i = 0; i < t; i++) {
                sbox[sbox_idx] = Pow5();
                sbox[sbox_idx].in <== after_constants[r][i];
                after_sbox[r][i] <== sbox[sbox_idx].out;
                sbox_idx++;
            }
        } else {
            // ---- Partial rounds：只对 lane 0 应用 S-box，其余直连
            sbox[sbox_idx] = Pow5();
            sbox[sbox_idx].in <== after_constants[r][0];
            after_sbox[r][0] <== sbox[sbox_idx].out;
            sbox_idx++;

            for (var i = 1; i < t; i++) {
                after_sbox[r][i] <== after_constants[r][i];
            }
        }

        // 3) 线性层（MDS * after_sbox[r]）
        //   state[r+1][i] = Σ_j MDS[i][j] * after_sbox[r][j]
        state[r + 1][0] <== MDS[0][0] * after_sbox[r][0]
                          + MDS[0][1] * after_sbox[r][1]
                          + MDS[0][2] * after_sbox[r][2];

        state[r + 1][1] <== MDS[1][0] * after_sbox[r][0]
                          + MDS[1][1] * after_sbox[r][1]
                          + MDS[1][2] * after_sbox[r][2];

        state[r + 1][2] <== MDS[2][0] * after_sbox[r][0]
                          + MDS[2][1] * after_sbox[r][1]
                          + MDS[2][2] * after_sbox[r][2];
    }

    // 输出
    out <== state[total_rounds][0];
}

// 主组件
component main = Poseidon2();
