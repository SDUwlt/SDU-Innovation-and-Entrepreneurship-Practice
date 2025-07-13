# 文件: utils.py
import cv2
import numpy as np
import pywt

def dwt2(image):
    coeffs = pywt.dwt2(image, 'haar')
    return coeffs

def idwt2(coeffs):
    return pywt.idwt2(coeffs, 'haar')

def svd(matrix):
    return np.linalg.svd(matrix, full_matrices=False)

def merge_singular_values(S_img, S_wm, alpha=0.1):
    return S_img + alpha * S_wm

def recover_singular_values(S_emb, S_img, alpha=0.1):
    return (S_emb - S_img) / alpha

def clip_and_uint8(matrix):
    return np.uint8(np.clip(matrix, 0, 255))

def resize_gray_image(img_path, size):
    image = cv2.imread(img_path, cv2.IMREAD_GRAYSCALE)
    return cv2.resize(image, size)

def save_image(path, image):
    cv2.imwrite(path, image)

def load_grayscale_image(path):
    return cv2.imread(path, cv2.IMREAD_GRAYSCALE)
