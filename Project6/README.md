# DDH-based ΠDDH 协议实现（Google Password Checkup 协议原型）

## 1. 协议背景

本项目参考论文 **[Private Set Intersection with Vectorial Equations](https://eprint.iacr.org/2019/723.pdf)** 中的 Section 3.1（Figure 2），实现了 DDH-based ΠDDH 协议。  
该协议是 Google Password Checkup 中使用的核心构件之一，目标是 **在不泄露非交集信息的情况下，计算两个集合交集元素对应数值的加和**。

场景设定：
- **P1**：持有一组标识符集合 $V = \{v_1, \dots, v_n\}$
- **P2**：持有一组 (标识符, 值) 对 $W = \{(w_1, t_1), \dots, (w_m, t_m)\}$
- 输出：
  - **P2** 最终得到交集 $V \cap W$ 中对应值的总和 $\sum_{w \in V \cap W} t_w$
  - **P1** 除了自身输入外，不得获知任何关于 P2 的信息
  - **P2** 除了总和外，不得获知关于 P1 的额外信息

---

## 2. 协议流程（Figure 2 简化描述）

### 系统参数
- 椭圆曲线群 $G$，基点 $g$（本实现用 SECP256R1 / prime256v1）
- 安全哈希映射 $H : U \rightarrow G$ （此处用 `sha256` 后映射为曲线标量再乘基点，演示用）
- 加法同态加密方案（Paillier）

### 三轮交互流程

1. **Round 1（P1 → P2）**  
   - P1 生成随机 $k_1 \in \mathbb{Z}_q$  
   - 对每个 $v_i \in V$：  
     1. 计算 $s = H(v_i)$ 的标量表示  
     2. 计算 $H(v_i)^{k_1}$ （EC 标量乘）  
   - 发送 $\{H(v_i)^{k_1}\}_{i=1}^n$（打乱顺序）给 P2

2. **Round 2（P2 → P1）**  
   - P2 生成随机 $k_2 \in \mathbb{Z}_q$  
   - 对收到的每个 $H(v_i)^{k_1}$：计算 $(H(v_i)^{k_1})^{k_2} = H(v_i)^{k_1 k_2}$，形成集合 $Z$  
   - 对每个 $(w_j, t_j) \in W$：  
     1. 计算 $H(w_j)^{k_2}$  
     2. 用 Paillier 公钥加密 $t_j$  
   - 将 $Z$（打乱）和 $\{(H(w_j)^{k_2}, \text{Enc}(t_j))\}_{j=1}^m$（打乱）发送给 P1

3. **Round 3（P1 → P2）**  
   - 对每个收到的 $(H(w_j)^{k_2}, \text{Enc}(t_j))$，P1 计算 $(H(w_j)^{k_2})^{k_1} = H(w_j)^{k_1 k_2}$  
   - 若该结果在 $Z$ 中，说明 $w_j \in V \cap W$，则将对应的 $\text{Enc}(t_j)$ 累加到同态和中  
   - P1 对最终密文进行重随机化（加密 0 相加）并返回给 P2

4. **解密输出**  
   - P2 解密收到的同态和密文，得到 $\sum_{w \in V \cap W} t_w$

---

## 3. 本实现的特点与设计取舍

- **椭圆曲线运算**
  - 使用 `cryptography` 库生成基于 SECP256R1 的点  
  - 为了在不引入额外 ECC 运算库（如 tinyec/ecpy）的情况下完成协议，消息中同时传递必要的标量值（`s_k1` / `s_k2`），这样双方可以在本地用标量运算复现目标压缩点并做集合匹配
  - 交集检测用压缩点（X9.62 compressed format）作为比对

- **哈希到曲线**
  - 演示版实现为：
    $s = \text{int}(\text{SHA256}(x)) \bmod q$
    然后取 $s \cdot G$ 作为 $H(x)$
  - 实际安全部署应替换为合规的 [hash-to-curve](https://datatracker.ietf.org/doc/html/rfc9380) 方法

- **加法同态加密**
  - 自实现了纯 Python Paillier（便于无依赖运行）
  - 支持基本的加密、解密、密文加法、重随机化（加密 0 相加）

- **安全性与隐私**
  - 遵循论文的半诚实模型假设
  - 实现了：
    - 消息乱序（shuffle）
    - 同态密文重随机化
  - 未实现：
    - 网络安全传输（此 demo 为内存模拟）
    - 针对恶意模型的防御（需额外零知识证明等）

---

## 4. 代码结构

- **Paillier 实现部分**
  - `generate_paillier_keypair`：密钥对生成
  - `PaillierPublicKey.encrypt` / `PaillierPrivateKey.decrypt`：加解密
  - `PaillierCiphertext.__add__`：密文加法（同态）

- **ECC 工具部分**
  - `hash_to_scalar`：哈希到标量
  - `point_from_scalar`：标量乘基点
  - `compress_point`：压缩点序列化

- **网络模拟部分**
  - `Network`：模拟消息发送与接收（以 tag 分类）

- **协议参与方**
  - `Party1`：P1（发送 Round1，执行 Round3）
  - `Party2`：P2（发送 Round2，解密结果）

- **demo**
  - 初始化测试数据
  - 按三轮顺序执行协议
  - 输出交集加和结果与明文对照

---

## 5. 运行方法

1. 安装依赖：
   ```bash
   pip install cryptography

2. 保存代码为：
   ```bash
   ddh_pisum_ecpoints.py


3. 运行：
   ```bash
   python ddh_pisum_ecpoints.py


4. 预期输出：
   ```bash
   P2 recovered intersection-sum: 70
   Ground-truth intersection-sum: 70
   OK: protocol result matches plaintext sum.

## 6. 验证结果

测试数据：

P1: alice@example.com, bob@example.com, carol@example.com

P2: (bob@example.com, 50), (david@example.com, 30), (carol@example.com, 20)

交集：

bob@example.com → 50

carol@example.com → 20

总和 = 70

程序输出与明文计算一致，说明协议流程与实现逻辑正确。

## 7. 后续可扩展方向

- 更严格的 EC 点运算：用支持任意点标量乘的 ECC 库（tinyec/ecpy/petlib）替代标量传递方案

- 合规 hash-to-curve：采用 RFC 9380 中的 Simplified SWU 或其他安全映射

- 网络化实现：将 P1/P2 分成独立进程并通过 TCP/HTTP 交换消息

- 支持更大集合：引入批量化优化、并行化计算、向量化哈希等

- 恶意模型安全性：添加零知识证明验证输入正确性

<img width="843" height="164" alt="屏幕截图 2025-08-15 010440" src="https://github.com/user-attachments/assets/d013098f-d562-4a69-a033-60897638573a" />
