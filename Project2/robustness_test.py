# 文件: robustness_test.py
import cv2
import numpy as np
from skimage.metrics import structural_similarity as ssim, mean_squared_error as mse
from extract_watermark import extract_watermark
from embed_watermark import embed_watermark
import shutil

def apply_attack(image, mode):
    if mode == 'flip':
        return cv2.flip(image, 1)
    elif mode == 'translate':
        M = np.float32([[1, 0, 10], [0, 1, 10]])
        return cv2.warpAffine(image, M, (image.shape[1], image.shape[0]))
    elif mode == 'crop':
        h, w = image.shape
        return cv2.resize(image[30:h-30, 30:w-30], (w, h))
    elif mode == 'contrast':
        return cv2.convertScaleAbs(image, alpha=1.5, beta=0)
    else:
        return image

def evaluate(original, extracted):
    s = ssim(original, extracted)
    e = mse(original, extracted)
    return s, e

def run_tests():
    embed_watermark('images/lena.png', 'images/watermark.png')
    original_watermark = cv2.imread('images/watermark.png', cv2.IMREAD_GRAYSCALE)
    original_watermark = cv2.resize(original_watermark, (128, 128))

    attacks = ['none', 'flip', 'translate', 'crop', 'contrast']
    results = []

    for attack in attacks:
        watermarked = cv2.imread('results/watermarked.png', cv2.IMREAD_GRAYSCALE)
        if attack != 'none':
            attacked = apply_attack(watermarked, attack)
        else:
            attacked = watermarked

        attacked_path = f'results/watermarked_{attack}.png'
        cv2.imwrite(attacked_path, attacked)

        shutil.copyfile(attacked_path, 'results/watermarked.png')  # 用于提取
        extract_watermark('results/watermarked.png')

        extracted = cv2.imread('results/extracted_watermark.png', cv2.IMREAD_GRAYSCALE)
        extracted = cv2.resize(extracted, (128, 128))

        s, e = evaluate(original_watermark, extracted)
        print(f"Attack: {attack:10} | SSIM: {s:.4f} | MSE: {e:.2f}")
        results.append((attack, s, e))

if __name__ == '__main__':
    run_tests()
