# 文件: embed_watermark.py
import cv2
import pywt
import numpy as np
import os

def embed_watermark(image_path, watermark_path, output_path='results/watermarked.png', alpha=0.1):
    image = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    watermark = cv2.imread(watermark_path, cv2.IMREAD_GRAYSCALE)

    image = cv2.resize(image, (512, 512))
    watermark = cv2.resize(watermark, (128, 128))

    coeffs = pywt.dwt2(image, 'haar')
    LL, (LH, HL, HH) = coeffs

    U, S, V = np.linalg.svd(LL, full_matrices=False)
    Uw, Sw, Vw = np.linalg.svd(watermark, full_matrices=False)

    S_new = S.copy()
    S_new[:Sw.shape[0]] += alpha * Sw
    LL_new = np.dot(U, np.dot(np.diag(S_new), V))

    watermarked = pywt.idwt2((LL_new, (LH, HL, HH)), 'haar')
    watermarked = np.uint8(np.clip(watermarked, 0, 255))

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    cv2.imwrite(output_path, watermarked)
    np.save('results/original_S.npy', S)
    np.save('results/Uw.npy', Uw[:128, :128])
    np.save('results/Vw.npy', Vw[:128, :128])

    print(f"Watermarked image saved to {output_path}")

if __name__ == '__main__':
    embed_watermark('images/lena.png', 'images/watermark.png')
