# 文件: extract_watermark.py
import cv2
import numpy as np
import pywt
import os

def extract_watermark(watermarked_path, alpha=0.1):
    watermarked = cv2.imread(watermarked_path, cv2.IMREAD_GRAYSCALE)
    watermarked = cv2.resize(watermarked, (512, 512))

    S_orig = np.load('results/original_S.npy')
    Uw = np.load('results/Uw.npy')[:128, :128]
    Vw = np.load('results/Vw.npy')[:128, :128]

    coeffs = pywt.dwt2(watermarked, 'haar')
    LL, _ = coeffs

    U, S_emb, V = np.linalg.svd(LL, full_matrices=False)
    Sw_recovered = (S_emb[:128] - S_orig[:128]) / alpha

    extracted = np.dot(Uw, np.dot(np.diag(Sw_recovered), Vw))
    extracted = np.uint8(np.clip(extracted, 0, 255))

    cv2.imwrite('results/extracted_watermark.png', extracted)
    print("Extracted watermark saved to results/extracted_watermark.png")

if __name__ == '__main__':
    extract_watermark('results/watermarked.png')
