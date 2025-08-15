# Poseidon2 zk-SNARK Implementation

## 项目简介

本项目实现了基于 Poseidon2 哈希函数的 zk-SNARK 电路，使用 Circom 2.2.2 编写，支持 Groth16 证明系统。  
Poseidon2 是一种专为零知识证明优化的哈希函数，具有高性能和低约束量特性，适合 zk-SNARK 场景。

---

## Poseidon2 原理概述

Poseidon2 是一种专为 zk-SNARK 和 zk-STARK 场景设计的哈希函数，其核心特点包括：

1. **SPN（Substitution-Permutation Network）结构**  
   Poseidon2 采用 SPN 结构，通过非线性 S-box 与线性 MDS 矩阵交替进行多轮迭代，实现安全的扩散和非线性混合。

2. **轮结构**  
   - **完整轮 (Full Round, RF)**：对状态向量中所有元素应用非线性 S-box，增加安全性。
   - **部分轮 (Partial Round, RP)**：只对第一个状态元素应用 S-box，其他元素保持线性混合，降低约束数量，提高 zk-SNARK 性能。

3. **非线性 S-box**  
   - Poseidon2 常用指数 S-box，如 \(x^5\) 或 \(x^7\)，在电路中可以高效实现。
   - 设计上选择奇数指数，确保在有限域内有唯一逆元素，便于安全性分析。

4. **MDS 矩阵混合**  
   - 每轮 S-box 后通过 MDS 矩阵线性混合所有状态元素，实现最大扩散（Maximum Distance Separable）。
   - 保证任意输入位变化都会影响所有输出，提高碰撞抵抗性。

5. **轮常数**  
   - 每轮加上独立的轮常数（Round Constants），防止固定点攻击和线性关系攻击。
   - 在 zk-SNARK 场景中，这些常数都是公开的，便于验证。

6. **优化特点**  
   - 对部分轮仅应用 S-box 到第一个元素，大幅降低约束数量。
   - 适合电路化实现，尤其在 Circom 或 R1CS 模型下，可以高效生成证明。
---

## 算法与电路实现细节

### 电路定义

- 状态大小 \(t = 3\)
- 非线性指数 \(d = 5\)
- 完整轮数 \(RF = 8\)
- 部分轮数 \(RP = 57\)

```circom
signal input in[3];  // 私有输入
signal output out;   // 公开输出哈希值
```

## Poseidon2 哈希计算流程

1.初始化状态
将输入数组 in 赋值到状态 state[0]：

```circom
for (var i = 0; i < 3; i++) {
    state[0][i] <== in[i];
}
```

2.加轮常数（Add Round Constants）
每轮对状态向量加上对应的轮常数：

```circom
after_constants[r][i] <== state[r][i] + round_constants[r][i];
```

3.S-box 变换
对状态元素应用 S-box ,完整轮对所有元素应用,部分轮只对第一个元素应用，其他保持不变

```circom
component sbox = Pow5();
sbox.in <== after_constants[r][i];
after_sbox[r][i] <== sbox.out;
```

4.MDS 矩阵线性混合
对 S-box 输出应用 MDS 矩阵，混合状态：

```circom
state[r+1][i] <== sum_j(MDS[i][j] * after_sbox[r][j]);
```

5.输出
最终输出状态的第一个元素作为哈希值：

```circom
out <== state[rounds_full + rounds_partial][0];
```

6.S-box 组件实现

```circom
template Pow5() {
    signal input in;
    signal output out;

    signal x2;
    signal x4;

    x2 <== in * in;
    x4 <== x2 * x2;
    out <== in * x4; // x^5
}
```
## 编译与证明流程
1. 编译电路

```bash
circom Poseidon2.circom --r1cs --wasm --sym -o build
```

生成文件：

```bash
build/Poseidon2.r1cs

build/Poseidon2.wasm

build/Poseidon2.sym

build/Poseidon2_js/witness_calculator.js
```

2. 准备输入文件

input.json 需严格匹配 signal input 定义，例如：

```bash
{
  "in": ["123", "456", "789"]
}
```

3. 生成 witness

```bash
cd build
node Poseidon2_js/generate_witness.js Poseidon2.wasm ../input.json witness.wtns
```

成功生成 witness.wtns。

4. Powers of Tau 阶段

```bash
snarkjs powersoftau new bn128 12 pot12_0000.ptau
snarkjs powersoftau contribute pot12_0000.ptau pot12_final.ptau
```

5. Groth16 Setup
```bash
snarkjs groth16 setup Poseidon2.r1cs pot12_final.ptau poseidon2_0000.zkey
snarkjs zkey contribute poseidon2_0000.zkey poseidon2_0001.zkey
```

6. 生成证明
```bash
snarkjs groth16 prove poseidon2_0001.zkey witness.wtns proof.json public.json
```
7. 验证证明
```bash
snarkjs groth16 verify verification_key.json public.json proof.json
```

成功验证后，proof.json 和 public.json 可用于链上或其他验证环境。
