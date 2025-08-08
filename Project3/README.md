# Poseidon2 Hash Circuit in Circom (Groth16)

本项目实现了基于 [Poseidon2](https://eprint.iacr.org/2023/323.pdf) 哈希算法的 Circom 电路，并使用 **Groth16** 零知识证明系统生成证明与验证。

## 📌 项目背景

Poseidon2 是一种专为零知识证明场景优化的哈希函数，具有较低的约束开销与高安全性。本项目实现了 **(n, t, d) = (256, 3, 5)** 或 **(256, 2, 5)** 的 Poseidon2 参数配置，支持在 zkSNARK 电路中对哈希运算进行验证。

**特性：**
- Circom v2 编写，参数化支持不同 `t`、轮数、S-box 指数
- 常量（Round Constants、MDS 矩阵）可按 Poseidon2 论文算法生成
- 支持单 block 吸收模式
- Groth16 证明与验证流程示例

---

## 📐 参数配置

| 参数          | 说明 |
|--------------|------|
| **n**        | 输入位数（256 bits） |
| **t**        | 状态宽度（2 或 3） |
| **d**        | S-box 指数（5） |
| **Rf**       | 全轮数（需按论文 Table1 填写） |
| **Rp**       | 部分轮数（需按论文 Table1 填写） |
| **域**       | zk 曲线基域（默认 bn128） |

> ⚠️ 注意：由于 bn128 基域约 254 位，256-bit 原像需拆分为多个 field 元素输入（示例中拆为 `pre_lo` 与 `pre_hi`）。

---

## 📂 项目结构

├── poseidon2_perm.circom # Poseidon2 通用置换模板
├── poseidon2_main.circom # 主电路：接收原像、计算哈希
├── constants.circom # 常量定义（需用脚本生成）
├── gen_constants.js # 生成 constants.circom 的脚本骨架
└── README.md

---

## 🔧 常量生成

1. 修改 `gen_constants.js` 中的 **常量生成方法**（`exampleGenRC` / `exampleGenMDS`）为 Poseidon2 论文中的真实算法。
2. 设置 `STATE_T`、`FULL_ROUNDS`、`PARTIAL_ROUNDS`、`SBOX_D`、`FIELD_P`。
3. 运行：
   ```bash
   node gen_constants.js

---

## 🔧编译与证明流程
1. 编译电路
circom poseidon2_main.circom --r1cs --wasm --sym -o build
2. 生成 Powers of Tau
snarkjs powersoftau new bn128 12 pot12_0000.ptau
snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="first" -v
3. Groth16 设置
snarkjs groth16 setup build/poseidon2_main.r1cs pot12_0001.ptau poseidon2_final.zkey
snarkjs zkey contribute poseidon2_final.zkey poseidon2_final_2.zkey --name="contrib" -v
snarkjs zkey export verificationkey poseidon2_final_2.zkey verification_key.json
4. 生成 Witness
准备 input.json：
{
  "pre_lo": "12345678901234567890",
  "pre_hi": "9876543210987654321"
}
生成：
node build/poseidon2_main_js/generate_witness.js build/poseidon2_main.wasm input.json witness.wtns
5. 生成证明
snarkjs groth16 prove poseidon2_final_2.zkey witness.wtns proof.json public.json
6. 验证证明
snarkjs groth16 verify verification_key.json public.json proof.json
