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

