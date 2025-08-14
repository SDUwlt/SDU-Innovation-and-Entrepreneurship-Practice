# sm2_basic.py
# Pure-Python SM3 + SM2 basic implementation.
# Usage:
#   python3 sm2_basic.py
# This will generate a keypair, produce a deterministic signature, and verify it.

import struct, random, sys
from typing import Tuple, Optional

# ---------------- SM3 ----------------
IV = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
]

def _rotl(x, n): 
    n &=31
    return ((x << n) | (x >> (32-n))) & 0xFFFFFFFF
def _P0(x): return x ^ _rotl(x, 9) ^ _rotl(x,17)
def _P1(x): return x ^ _rotl(x,15) ^ _rotl(x,23)
def _FF(j,x,y,z):
    return (x ^ y ^ z) if j<=15 else ((x & y) | (x & z) | (y & z))
def _GG(j,x,y,z):
    return (x ^ y ^ z) if j<=15 else ((x & y) | (~x & z))

def sm3_compress(V, block):
    w = list(struct.unpack(">16I", block))
    for j in range(16,68):
        wj = _P1(w[j-16] ^ w[j-9] ^ _rotl(w[j-3],15)) ^ _rotl(w[j-13],7) ^ w[j-6]
        w.append(wj & 0xFFFFFFFF)
    w1 = [(w[j] ^ w[j+4]) & 0xFFFFFFFF for j in range(64)]
    A,B,C,D,E,F,G,H = V
    for j in range(64):
        Tj = 0x79CC4519 if j<=15 else 0x7A879D8A
        SS1 = _rotl((_rotl(A,12) + E + _rotl(Tj, j%32)) & 0xFFFFFFFF, 7)
        SS2 = SS1 ^ _rotl(A,12)
        TT1 = (_FF(j,A,B,C) + D + SS2 + w1[j]) & 0xFFFFFFFF
        TT2 = (_GG(j,E,F,G) + H + SS1 + w[j]) & 0xFFFFFFFF
        D = C; C = _rotl(B,9); B = A; A = TT1
        H = G; G = _rotl(F,19); F = E; E = _P0(TT2)
    return [(x ^ y) & 0xFFFFFFFF for x,y in zip(V, [A,B,C,D,E,F,G,H])]

class SM3:
    def __init__(self, data: bytes=b""):
        self.V = IV[:]; self.buf = b""; self.n = 0
        if data: self.update(data)
    def update(self, data: bytes):
        self.n += len(data)
        data = self.buf + data
        for i in range(0, len(data)//64 * 64, 64):
            self.V = sm3_compress(self.V, data[i:i+64])
        self.buf = data[(len(data)//64)*64:]
        return self
    def digest(self) -> bytes:
        ml = self.n * 8
        pad = b"\x80" + b"\x00" * ((56 - (self.n + 1) % 64) % 64) + struct.pack(">Q", ml)
        V = self.V[:]; data = self.buf + pad
        for i in range(0, len(data), 64):
            V = sm3_compress(V, data[i:i+64])
        return b"".join(struct.pack(">I", x) for x in V)
    def hexdigest(self): return self.digest().hex()

def sm3(data: bytes) -> bytes:
    return SM3(data).digest()

def hmac_sm3(key: bytes, msg: bytes) -> bytes:
    block = 64
    if len(key) > block: key = sm3(key)
    key = key.ljust(block, b"\x00")
    o = bytes(b ^ 0x5c for b in key); i = bytes(b ^ 0x36 for b in key)
    return sm3(o + sm3(i + msg))

# ---------------- SM2 curve params (standard) ----------------
p = int("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",16)
a = int("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",16)
b = int("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",16)
Gx = int("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",16)
Gy = int("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",16)
n = int("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",16)
G = (Gx, Gy)

def inv_mod(x, m):
    if x == 0: raise ZeroDivisionError
    a0, a1 = m, x % m; x0, x1 = 0, 1
    while a1:
        q = a0 // a1
        a0, a1 = a1, a0 - q*a1
        x0, x1 = x1, x0 - q*x1
    return x0 % m

# Jacobian coordinates for scalar mul
def to_jac(P):
    if P is None: return (1,1,0)
    x,y = P; return (x,y,1)
def from_jac(J):
    if J is None: return None
    X,Y,Z = J
    if Z == 0: return None
    Zi = inv_mod(Z, p); Zi2 = (Zi*Zi) % p
    return ((X*Zi2)%p, (Y*Zi*Zi2)%p)

def j_double(P):
    if P is None: return None
    X1,Y1,Z1 = P
    if Z1 == 0 or Y1 == 0: return (1,1,0)
    A_ = (X1*X1) % p
    B_ = (Y1*Y1) % p
    C_ = (B_*B_) % p
    D_ = (2*((X1+B_)**2 - A_ - C_)) % p
    E_ = (3*A_ + a*(Z1*Z1 % p)*(Z1*Z1 % p)) % p
    F_ = (E_*E_) % p
    X3 = (F_ - 2*D_) % p
    Y3 = (E_*(D_ - X3) - 8*C_) % p
    Z3 = (2*Y1*Z1) % p
    return (X3, Y3, Z3)

def j_add(P,Q):
    if P is None: return Q
    if Q is None: return P
    X1,Y1,Z1 = P; X2,Y2,Z2 = Q
    if Z1 == 0: return Q
    if Z2 == 0: return P
    Z1Z1 = (Z1*Z1) % p; Z2Z2 = (Z2*Z2) % p
    U1 = (X1*Z2Z2) % p; U2 = (X2*Z1Z1) % p
    S1 = (Y1*Z2*Z2Z2) % p; S2 = (Y2*Z1*Z1Z1) % p
    if U1 == U2:
        if S1 != S2: return (1,1,0)
        return j_double(P)
    H = (U2-U1) % p; I = (2*H)**2 % p; J = (H*I) % p
    r = (2*(S2-S1)) % p; V = (U1*I) % p
    X3 = (r*r - J - 2*V) % p
    Y3 = (r*(V - X3) - 2*S1*J) % p
    Z3 = ((Z1+Z2)**2 - Z1Z1 - Z2Z2) * H % p
    return (X3, Y3, Z3)

def j_mul(P, k):
    if k % n == 0 or P is None: return None
    N = to_jac(P); R = None
    while k:
        if k & 1:
            R = j_add(R, N) if R is not None else N
        N = j_double(N); k >>= 1
    return from_jac(R)

# ZA computation (identity binding)
def int2bytes(x, l): return x.to_bytes(l, 'big')
def ZA(IDA: bytes, PA: Tuple[int,int]) -> bytes:
    entla = (len(IDA)*8).to_bytes(2, 'big')
    return sm3(entla + IDA + int2bytes(a,32) + int2bytes(b,32) + int2bytes(Gx,32) + int2bytes(Gy,32) + int2bytes(PA[0],32) + int2bytes(PA[1],32))

# RFC6979-like deterministic k using HMAC-SM3
def rfc6979_k(x: int, h1: bytes, q=n):
    qlen = q.bit_length(); holen = 32
    bx = x.to_bytes((qlen+7)//8, 'big')
    V = b"\x01"*holen; K = b"\x00"*holen
    K = hmac_sm3(K, V + b"\x00" + bx + h1); V = hmac_sm3(K, V)
    K = hmac_sm3(K, V + b"\x01" + bx + h1); V = hmac_sm3(K, V)
    while True:
        T = b""
        while len(T) < (qlen+7)//8:
            V = hmac_sm3(K, V); T += V
        k = int.from_bytes(T, 'big') % q
        if 1 <= k <= q-1: return k
        K = hmac_sm3(K, V + b"\x00"); V = hmac_sm3(K, V)

# Key gen / sign / verify
def keygen(d: Optional[int]=None):
    if d is None: d = random.randrange(1, n)
    P = j_mul(G, d)
    return d, P

def sm2_sign(d: int, IDA: bytes, M: bytes, PA: Tuple[int,int], deterministic=True):
    Z = ZA(IDA, PA); e = sm3(Z + M); e_int = int.from_bytes(e, 'big')
    while True:
        if deterministic:
            k = rfc6979_k(d, e)
        else:
            k = random.randrange(1, n)
        Pk = j_mul(G, k); x1 = Pk[0]
        r = (e_int + x1) % n
        if r == 0 or r + k == n: continue
        s = (inv_mod(1 + d, n) * (k - r*d)) % n
        if s == 0: continue
        return r, s

def sm2_verify(PA: Tuple[int,int], IDA: bytes, M: bytes, sig: Tuple[int,int]) -> bool:
    r,s = sig
    if not (1 <= r <= n-1 and 1 <= s <= n-1): return False
    Z = ZA(IDA, PA); e = sm3(Z + M); e_int = int.from_bytes(e, 'big')
    t = (r + s) % n
    if t == 0: return False
    X1,Y1 = j_mul(G, s); X2,Y2 = j_mul(PA, t)
    if X1 is None or X2 is None: return False
    # add X1,Y1 and X2,Y2 (affine add)
    if X1 == X2 and (Y1 + Y2) % p == 0: return False
    if X1 == X2 and Y1 == Y2:
        lam = ((3*X1*X1 + a) * inv_mod((2*Y1) % p, p)) % p
    else:
        lam = ((Y2 - Y1) * inv_mod((X2 - X1) % p, p)) % p
    Rx = (lam*lam - X1 - X2) % p
    R = (e_int + Rx) % n
    return R == r

# demo
if __name__ == "__main__":
    d, P = keygen()
    print("priv d:", hex(d))
    print("pub P:", (hex(P[0]), hex(P[1])))
    IDA = b"User"
    M = b"hello sm2"
    sig = sm2_sign(d, IDA, M, P, deterministic=True)
    print("sig r,s:", sig)
    ok = sm2_verify(P, IDA, M, sig)
    print("verify:", ok)
