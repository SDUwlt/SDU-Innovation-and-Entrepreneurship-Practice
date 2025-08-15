# SM2 实现、优化与签名误用 PoC 实验报告

## 1. 项目背景
本项目实现了国密 SM2 公钥密码算法的**签名与验证**，并针对性能与安全进行了多项优化。同时，依据课程提供的参考资料与论文，复现了若干 SM2 签名算法的常见误用场景，通过 PoC（Proof of Concept）展示潜在的安全风险与私钥泄露方式。

---

## 2. 基础实现

### 2.1 椭圆曲线参数
- 曲线：sm2p256v1
- 底层有限域：F\_p
- 基点 G = (Gx, Gy)
- 阶 n

### 2.2 SM2 签名流程（简述）
1. 计算 ZA = SM3(ENTL || ID || a || b || Gx || Gy || Px || Py)
2. 计算 e = SM3(ZA || M)
3. 随机生成 k ∈ [1, n-1]
4. 计算 (x1, y1) = kG
5. 计算 r = (e + x1) mod n
6. 计算 s = ((1 + d)^(-1) * (k - r·d)) mod n
7. 输出签名 (r, s)

### 2.3 验证流程（简述）
1. 验证 r, s ∈ [1, n-1]
2. 计算 e = SM3(ZA || M)
3. 计算 t = (r + s) mod n
4. 计算 (x1', y1') = sG + tP
5. 验证 (r == (e + x1') mod n)

---

## 3. 优化细节

### 3.1 算法优化
- **Jacobian 坐标**：减少模逆运算开销，提高标量乘性能
- **常量时间模逆**：避免分支引入的时间侧信道
- **RFC6979 确定性 k**：基于 SM3 实现，确保同一消息同一密钥生成固定 k，避免随机数质量不佳导致私钥泄露
- **预计算 ZA**：将与公钥绑定的 ZA 预先计算并缓存

### 3.2 安全性增强
- 检查 r=0、s=0、r+k=n 等边界条件，必要时重采样 k
- 严格绑定 ZA 与公钥，防止公钥恢复攻击

<img width="1702" height="199" alt="屏幕截图 2025-08-14 232747" src="https://github.com/user-attachments/assets/669a1cd0-f87a-4304-8d23-f836a1d53b56" />

---

## 4. POC 攻击实验与公式推导

### 4.1 Demo 1：一次性随机数 k 泄漏

**签名公式**：
$s = (k - r d) (1 + d)^{-1} \pmod{n}$

**已知**：r, s, k
**要求**：求  d 

**推导**：
$s(1+d) \equiv k - r d \pmod{n}$

$s + s d \equiv k - r d$

$s - k \equiv -d (s + r)$

$d \equiv (k - s) (s + r)^{-1} \pmod{n}$

**实验结果**：

== Demo 1: leak k => recover d
orig d == rec d ? True


---

### 4.2 Demo 2：同一用户复用同一 k

消息 1：
$s_1 = (k - r_1 d)(1+d)^{-1} \pmod{n}$

消息 2：
$s_2 = (k - r_2 d)(1+d)^{-1} \pmod{n}$

相减：
$(s_1 - s_2)(1+d) \equiv (r_2 - r_1) d$

$s_1 - s_2 \equiv d (r_2 - r_1 - (s_1 - s_2))$

$d \equiv (s_2 - s_1) (s_1 - s_2 + r_1 - r_2)^{-1} \pmod{n}$


**实验结果**：
== Demo 2: reuse k same user on two messages
orig d2 == rec d2 ? True


---

### 4.3 Demo 3：两个用户复用同一 k（k 已知）

用户 A：
$s_A = (k - r_A d_A)(1+d_A)^{-1}$

$d_A \equiv (k - s_A) (s_A + r_A)^{-1} \pmod{n}$

用户 B 同理：
$d_B \equiv (k - s_B) (s_B + r_B)^{-1} \pmod{n}$

**实验结果**：
== Demo 3: two users accidentally reuse k (k known)
recover A ok? True
recover B ok? True


---

### 4.4 Demo 4：同一 d 和 k 用于 ECDSA 与 SM2

ECDSA 签名：
$s_1 = k^{-1}(e_1 + r_1 d) \pmod{n}$

$k \equiv s_1^{-1}(e_1 + r_1 d) \pmod{n}$


SM2 签名：
$s_2 = (k - r_2 d)(1+d)^{-1}$

$k \equiv s_2(1+d) + r_2 d$

令两式相等：
$s_1^{-1}(e_1 + r_1 d) \equiv s_2 + s_2 d + r_2 d$

$e_1 + r_1 d \equiv s_1 s_2 + s_1 s_2 d + s_1 r_2 d$

$e_1 - s_1 s_2 \equiv d (s_1 s_2 + s_1 r_2 - r_1)$

$d \equiv (s_1 s_2 - e_1) (r_1 - s_1 s_2 - s_1 r_2)^{-1} \pmod{n}$


**实验结果**：
== Demo 4: same d & k used for ECDSA and SM2
orig d == rec d ? True

<img width="1024" height="364" alt="image" src="https://github.com/user-attachments/assets/d9be00ea-a6a4-48fa-bf98-13524ff9ec5e" />

---

## 5. 实验结论
- SM2 签名算法在实现过程中，如果随机数 k 泄漏、复用、跨算法共用，都会导致私钥泄露。
- 实验中 4 种 PoC 场景全部成功复现，证明了误用风险的严重性。
- 必须在实现中使用高质量的随机数生成方法（推荐 RFC6979），并确保每次签名使用唯一的 k。
- ZA 必须与公钥绑定，否则可能被利用进行公钥恢复攻击。

---

## 6. 防护建议
1. **使用确定性随机数生成**（RFC6979 + SM3）
2. **严格检测 k 的唯一性**
3. **不跨算法共用 k**
4. **绑定 ZA 与公钥**
5. **在硬件安全模块（HSM）中生成和保存私钥与 k**

## 7. 伪造中本聪的签名

基于secp256k1椭圆曲线实现中本聪风格的比特币数字签名

## 功能概述

- 生成比特币兼容的私钥/公钥对
- 将私钥转换为WIF(钱包导入格式)
- 从公钥生成比特币地址
- 对消息进行ECDSA签名
- 验证签名有效性
- 输出DER编码格式签名

## 算法细节

### 1. 椭圆曲线参数 (secp256k1)


P = 2**256 - 2**32 - 977  # 有限域质数

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # 曲线阶数

A = 0  # 曲线方程 y² = x³ + 7

B = 7

Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798  # 生成点x

Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8  # 生成点y


### 2. 密钥生成流程
私钥生成:

生成256位随机整数

范围: 1 ≤ priv_key < N

公钥派生:

PubKey = privKey × G

G为曲线生成点
×表示椭圆曲线标量乘法

### 3. 地址生成流程

- 公钥序列化(压缩/非压缩格式)

- SHA256哈希

- RIPEMD160哈希

- 添加版本字节(0x00)

- 计算校验和(SHA256(SHA256(data)))

- Base58编码

### 4. ECDSA签名算法
   
签名生成:

  ### ECDSA 签名生成
给定: 私钥 `d`，消息 `m`，随机数 `k`
1. 计算 `e = SHA256(m)`
2. 计算 `(x₁, y₁) = k × G`
3. `r = x₁ mod n`
4. `s = k⁻¹ (e + r × d) mod n`
5. 如果 `s > n/2`，取 `s = n - s`（低 s 值）
6. 返回签名 `(r, s)`

---

### ECDSA 签名验证
给定: 公钥 `Q`，消息 `m`，签名 `(r, s)`
1. 验证 `1 ≤ r, s < n`
2. 计算 `e = SHA256(m)`
3. 计算 `w = s⁻¹ mod n`
4. 计算 `u₁ = e × w mod n`，`u₂ = r × w mod n`
5. 计算 `(x₁, y₁) = u₁ × G + u₂ × Q`
6. 验证 `r ≡ x₁ mod n`

---

### DER 编码格式

30 [长度] 02 [r长度] [r值] 02 [s长度] [s值]

- 所有整数采用大端格式

- 去除前导零字节

- 若最高位为1，需添加前导00字节

### 5.代码结构
```python
class ECPoint:
    # 椭圆曲线点实现
    def __add__()    # 点加法
    def double()     # 点倍乘
    def __rmul__()   # 标量乘法

# 辅助函数
modinv()            # 模逆计算
sha256()            # 哈希函数
base58_encode()     # Base58编码

# 主要功能
generate_private_key()
private_key_to_public_key()
private_key_to_wif()
public_key_to_address()
ecdsa_sign()
ecdsa_verify()
signature_to_der()
```

# 使用示例

```python
# 生成中本聪风格签名
priv_key = generate_private_key()
pub_point = private_key_to_public_key(priv_key)
address = public_key_to_address(pub_point)
message = "The Times 03/Jan/2009..."
r, s = ecdsa_sign(priv_key, message)
der_sig = signature_to_der(r, s)
is_valid = ecdsa_verify(pub_point, message, (r, s))
```
<img width="1706" height="429" alt="image" src="https://github.com/user-attachments/assets/bcc82dde-7462-4e64-8b32-0c0e97490a63" />
