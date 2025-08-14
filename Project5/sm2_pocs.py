# sm2_pocs.py
# PoCs for SM2 misuse scenarios described in your PDF.
# Usage: python3 sm2_pocs.py

import random
from sm2_basic import keygen, sm2_sign, sm2_verify, j_mul, G, n, sm3
from sm2_basic import inv_mod, ZA
from sm2_basic import sm3 as sm3func

# 1) leak k -> recover d
def recover_d_from_k(r, s, k):
    # d = (k - s) * inv(s + r) mod n
    denom = (s + r) % n
    return ((k - s) * inv_mod(denom, n)) % n

# 2) reuse k same user
def recover_d_from_two_same_k(r1, s1, r2, s2):
    # d = (s2 - s1) * inv(s1 - s2 + r1 - r2) mod n
    num = (s2 - s1) % n
    den = (s1 - s2 + r1 - r2) % n
    return (num * inv_mod(den, n)) % n

# 3) reuse k different users (if k known)
def recover_d_given_k_and_sig(k, r, s):
    return ((k - s) * inv_mod((s + r) % n, n)) % n

# 4) same d & same k used for ECDSA and SM2 -> recover d
# We'll use 'ecdsa' lib to create ECDSA signature on same scalar k (demo).
try:
    from ecdsa import SigningKey, SECP256k1
    ECDSA_AVAILABLE = True
except Exception:
    ECDSA_AVAILABLE = False

def demo():
    print("== Demo 1: leak k => recover d")
    d, P = keygen()
    ID = b"A"
    M = b"poC-leak"
    k = random.randrange(1, n)
    # produce signature with fixed k (use sm2_sign with fixed k implementation)
    # We'll recreate sign formula here to control k:
    Z = ZA(ID, P)
    e = sm3func(Z + M)
    e_int = int.from_bytes(e, 'big')
    x1,y1 = j_mul(G, k)
    r = (e_int + x1) % n
    s = (inv_mod(1 + d, n) * (k - r*d)) % n
    d_rec = recover_d_from_k(r, s, k)
    print("orig d == rec d ?", d == d_rec)

    print("\n== Demo 2: reuse k same user on two messages")
    d2, P2 = keygen()
    ID2 = b"B"
    M1 = b"m1"; M2 = b"m2"
    k2 = random.randrange(1, n)
    Z1 = ZA(ID2, P2); e1 = int.from_bytes(sm3func(Z1 + M1), 'big')
    x1,y1 = j_mul(G, k2); r1 = (e1 + x1) % n
    s1 = (inv_mod(1 + d2, n) * (k2 - r1*d2)) % n
    Z2 = ZA(ID2, P2); e2 = int.from_bytes(sm3func(Z2 + M2), 'big')
    x2,y2 = j_mul(G, k2); r2 = (e2 + x2) % n
    s2 = (inv_mod(1 + d2, n) * (k2 - r2*d2)) % n
    d2_rec = recover_d_from_two_same_k(r1, s1, r2, s2)
    print("orig d2 == rec d2 ?", d2 == d2_rec)

    print("\n== Demo 3: two users accidentally reuse k (k known) ==")
    dA, PA = keygen(); dB, PB = keygen()
    IDA, IDB = b"Alice", b"Bob"
    M_A, M_B = b"aaa", b"bbb"
    k = random.randrange(1, n)
    # A sig:
    Za = ZA(IDA, PA); ea = int.from_bytes(sm3func(Za + M_A), 'big')
    ra,_ = j_mul(G, k); ra = (ea + ra) % n
    sa = (inv_mod(1 + dA, n) * (k - ra*dA)) % n
    # B sig:
    Zb = ZA(IDB, PB); eb = int.from_bytes(sm3func(Zb + M_B), 'big')
    rb,_ = j_mul(G, k); rb = (eb + rb) % n
    sb = (inv_mod(1 + dB, n) * (k - rb*dB)) % n
    print("recover A ok?", recover_d_given_k_and_sig(k, ra, sa) == dA)
    print("recover B ok?", recover_d_given_k_and_sig(k, rb, sb) == dB)

    print("\n== Demo 4: same d & k used for ECDSA and SM2 (requires 'ecdsa' package)")
    if not ECDSA_AVAILABLE:
        print("ecdsa package not installed. pip install ecdsa to run this demo.")
        return
    # Create a random private scalar d, and fixed k
    d, P = keygen()
    k = random.randrange(1, n)
    msg = b"cross-algo"
    # ECDSA (secp256k1) using the same scalar k -- note: this demo assumes using same scalar on another curve; historically paper's cross-algo assumes same underlying group or same usage pattern.
    # For demonstrative algebra we compute an ECDSA-like s1 with same k (on same group for algebraic recovery); use simplified model:
    # r1 = x_k mod n
    xk, _ = j_mul(G, k)
    r1 = xk % n
    e1 = int.from_bytes(sm3func(msg), 'big')
    s1 = (inv_mod(k, n) * (e1 + d * r1)) % n

    # SM2 signature with same d,k
    Z = ZA(b"U", P)
    e2 = int.from_bytes(sm3func(Z + msg), 'big')
    x2, _ = j_mul(G, k)
    r2 = (e2 + x2) % n
    s2 = (inv_mod(1 + d, n) * (k - r2*d)) % n

    # recover formula from PDF:
    num = (s1 * s2 - e1) % n
    den = (r1 - (s1 * s2) - (s1 * r2)) % n
    d_rec = (num * inv_mod(den % n, n)) % n
    print("orig d == rec d ?", d == d_rec)

if __name__ == "__main__":
    demo()
