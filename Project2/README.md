# Project2: 图像水印嵌入与提取（DWT + SVD）


---

## 1. 实现原理（概述）

采用 DWT + SVD 的混合域水印方法：

1. 对主图像（cover image）做单层或多层 DWT，得到子带 `LL, LH, HL, HH`。
2. 在低频子带 `LL` 上做 SVD： `LL = U * S * Vt`。
3. 对要嵌入的水印图 `W` 做 SVD： `W = Uw * Sw * Vw_t`（必要时先调整 `W` 大小以匹配某些奇异值长度）。
4. 将水印奇异值按比例 `alpha` 加入主图奇异值：`S' = S + alpha * S_w_padded`。
5. 重构 `LL' = U * diag(S') * Vt`，对四个子带做 IDWT 得到含水印图像 `I_w`。
6. 提取时（半盲示例）：对含水印/被攻击图做 DWT、SVD，得到 `S_a`，并使用预先保存的 `S_original` 与 `alpha` 估算水印奇异值：`S_w_hat = (S_a - S_original) / alpha`，再用 `Uw,Vw` 重构水印。

---

## 2. 关键公式与参数

* DWT：`I -> {LL, LH, HL, HH}`（单层）
* SVD：`A = U * diag(S) * Vt`，`S` 为奇异值向量
* 嵌入：`S' = S + alpha * S_w`（对 `S_w` 做必要的填充或截断）
* 提取（半盲）：`S_w_hat = (S_extracted - S_original) / alpha`

参数建议：

* `wavelet`：`haar` 或 `db1` 起步；`haar` 简单且速度快
* `level`：单层（1）或两层（2）；一般用 `1` 即可
* `alpha`：`0.01 ~ 0.05` 作为起点（对 8-bit 图像）
* 是否对 RGB 三通道分别嵌入：可仅在 Y 通道嵌入以降低可见性和计算量

---

## 3. 代码与用法

- `embed_watermark.py` 实现水印嵌入
- `extract_watermark.py` 用于从含水印图中提取水印
- `robustness_test.py` 对图像执行翻转、平移、裁剪、对比度调整等操作
  
### 依赖（requirements）

```text
numpy
opencv-python
pywt
scikit-image
argparse
```

安装示例：

```bash
pip install numpy opencv-python pywt scikit-image
```

### embed\_watermark.py


将灰度/彩色图像的 LL 子带上的奇异值与水印奇异值按比例混合后重构，生成含水印图。
保存辅助文件以便半盲提取：S_original.npy, Uw.npy, Vw.npy, alpha.txt



### extract\_watermark.py


半盲提取：使用保存的 S_original.npy, Uw.npy, Vw.npy, alpha.txt
从被攻击图像中恢复水印近似。



### robustness\_test.py



对含水印图像执行多种攻击（翻转、平移、裁剪、对比度调整、JPEG、噪声等），
并对每次攻击后的结果进行水印提取，计算 SSIM、MSE、NC（归一化相关性），
将结果保存为 CSV/Markdown 表格并输出提取图像。


---

## 4. 实验与指标说明

* 指标：SSIM（接近 1 越好）、MSE（越小越好）、NC（接近 1 越好）
* 典型发现：
1. 无攻击和翻转攻击下：
   - 水印提取效果很好
   - 说明水印对这些操作鲁棒性强

2. 平移、裁剪、对比度调整攻击：
   - 导致水印质量大幅下降
   - 说明水印对这些变换较脆弱

3. 指标说明：
   - MSE越大代表水印失真越严重
   - SSIM越低代表水印质量下降越多

| 攻击方式       | SSIM    | MSE       |
|----------------|---------|-----------|
| 原图           | 0.9862  | 239.71    |
| 翻转           | 0.9862  | 239.71    |
| 平移           | 0.6764  | 5030.05   |
| 裁剪           | 0.6290  | 2478.16   |
| 对比度增强     | 0.4088  | 17154.21  |

---

## 5. 提高鲁棒性的建议

* 在嵌入中加入**同步模板**或**特征点**（ORB/SIFT）用于提取前配准
* 分块+冗余嵌入，减少局部裁剪的影响
* 先对水印做 ECC（如 BCH），提取后解码
* 使用奇异值的相对量（比值或差值归一化）而不是绝对量，提升对对比度变换的鲁棒性
* 多域嵌入（DWT+DCT+SVD）以兼顾不同攻击类型




<img width="906" height="305" alt="image" src="https://github.com/user-attachments/assets/b1323f06-de73-4a7a-b546-10d507e6c04c" />


