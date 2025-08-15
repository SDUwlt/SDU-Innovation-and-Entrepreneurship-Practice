import hashlib
import random
import binascii

# secp256k1椭圆曲线参数 (比特币/以太坊使用)
P = 2**256 - 2**32 - 977  # 质数域
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # 曲线阶数
A = 0
B = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

class ECPoint:
    """椭圆曲线点类"""
    def __init__(self, x, y):
        self.x = x
        self.y = y
    
    def __eq__(self, other):
        return self.x == other.x and self.y == other.y
    
    def __add__(self, other):
        """点加法"""
        if self == other:
            return self.double()
        if self.is_infinity():
            return other
        if other.is_infinity():
            return self
        if self.x == other.x:  # P + (-P) = 无穷远点
            return ECPoint(None, None)
        
        p = P
        lam = ((other.y - self.y) * modinv(other.x - self.x, p)) % p
        x3 = (lam * lam - self.x - other.x) % p
        y3 = (lam * (self.x - x3) - self.y) % p
        return ECPoint(x3, y3)
    
    def double(self):
        """点倍乘"""
        if self.is_infinity():
            return self
        p = P
        a = A
        lam = ((3 * self.x * self.x + a) * modinv(2 * self.y, p)) % p
        x3 = (lam * lam - 2 * self.x) % p
        y3 = (lam * (self.x - x3) - self.y) % p
        return ECPoint(x3, y3)
    
    def __rmul__(self, scalar):
        """标量乘法 (支持整数 * ECPoint)"""
        result = ECPoint(None, None)  # 无穷远点
        addend = self
        
        while scalar:
            if scalar & 1:
                result += addend
            addend = addend.double()
            scalar >>= 1
        return result
    
    def is_infinity(self):
        """是否是无穷远点"""
        return self.x is None or self.y is None
    
    def __repr__(self):
        return f"ECPoint({hex(self.x)}, {hex(self.y)})"

def modinv(a, n):
    """模逆元计算"""
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        ratio = high // low
        nm, new = hm - lm * ratio, high - low * ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % n

def sha256(msg, is_bytes=False):
    """SHA256哈希"""
    if not is_bytes:
        msg = msg.encode('utf-8')
    return hashlib.sha256(msg).digest()

def generate_private_key():
    """生成私钥 (32字节随机数)"""
    while True:
        priv_key = random.getrandbits(256)
        if 1 <= priv_key < N:
            return priv_key

def private_key_to_public_key(priv_key):
    """私钥转公钥"""
    G = ECPoint(Gx, Gy)
    pub_point = priv_key * G  # 使用 __rmul__ 方法
    return pub_point

def private_key_to_wif(priv_key, compressed=True):
    """将私钥转换为WIF格式"""
    prefix = b'\x80'
    suffix = b'\x01' if compressed else b''
    priv_bytes = priv_key.to_bytes(32, 'big')
    data = prefix + priv_bytes + suffix
    checksum = sha256(sha256(data, is_bytes=True), is_bytes=True)[:4]
    return base58_encode(data + checksum)

def public_key_to_address(pub_point, compressed=True):
    """公钥转比特币地址"""
    if compressed:
        if pub_point.y % 2 == 0:
            pub_encoded = b'\x02' + pub_point.x.to_bytes(32, 'big')
        else:
            pub_encoded = b'\x03' + pub_point.x.to_bytes(32, 'big')
    else:
        pub_encoded = b'\x04' + pub_point.x.to_bytes(32, 'big') + pub_point.y.to_bytes(32, 'big')
    
    # SHA256 + RIPEMD160
    h = hashlib.new('ripemd160', sha256(pub_encoded, is_bytes=True)).digest()
    # 添加版本字节 (0x00 for mainnet)
    version_h = b'\x00' + h
    # 计算校验和
    checksum = sha256(sha256(version_h, is_bytes=True), is_bytes=True)[:4]
    # Base58编码
    address = base58_encode(version_h + checksum)
    return address

def base58_encode(data):
    """Base58编码"""
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n = int.from_bytes(data, 'big')
    result = []
    while n > 0:
        n, rem = divmod(n, 58)
        result.append(alphabet[rem])
    # 处理前导零
    for byte in data:
        if byte == 0:
            result.append(alphabet[0])
        else:
            break
    return ''.join(reversed(result))

def ecdsa_sign(priv_key, msg):
    """ECDSA签名"""
    z = int.from_bytes(sha256(msg), 'big')
    k = random.randint(1, N-1)  # 临时密钥 (必须保密!)
    
    G = ECPoint(Gx, Gy)
    r_point = k * G
    r = r_point.x % N
    if r == 0:
        return ecdsa_sign(priv_key, msg)  # 重新生成
    
    s = (modinv(k, N) * (z + r * priv_key)) % N
    if s == 0:
        return ecdsa_sign(priv_key, msg)  # 重新生成
    
    # 低S值 (比特币要求)
    if s > N / 2:
        s = N - s
    
    return (r, s)

def ecdsa_verify(pub_point, msg, signature):
    """ECDSA验证"""
    r, s = signature
    if not (1 <= r < N and 1 <= s < N):
        return False
    
    z = int.from_bytes(sha256(msg), 'big')
    w = modinv(s, N)
    u1 = (z * w) % N
    u2 = (r * w) % N
    
    G = ECPoint(Gx, Gy)
    p = u1 * G + u2 * pub_point
    
    if p.is_infinity():
        return False
    
    return r == (p.x % N)

def signature_to_der(r, s):
    """将签名转换为DER格式"""
    def int_to_der_bytes(i):
        """将整数转换为DER字节格式"""
        b = i.to_bytes(32, 'big')
        # 去除前导零
        b = b.lstrip(b'\x00')
        # 如果最高位是1，需要添加前导零
        if b and (b[0] & 0x80):
            b = b'\x00' + b
        return b
    
    r_bytes = int_to_der_bytes(r)
    s_bytes = int_to_der_bytes(s)
    
    # 构建DER序列
    der = b'\x02' + len(r_bytes).to_bytes(1, 'big') + r_bytes
    der += b'\x02' + len(s_bytes).to_bytes(1, 'big') + s_bytes
    der = b'\x30' + len(der).to_bytes(1, 'big') + der
    
    return der

def create_satoshi_signature():
    """创建中本聪风格的签名"""
    # 1. 生成私钥
    priv_key = generate_private_key()
    print(f"Private Key (hex): {hex(priv_key)}")
    print(f"Private Key (WIF): {private_key_to_wif(priv_key)}")
    
    # 2. 生成公钥
    pub_point = private_key_to_public_key(priv_key)
    print(f"Public Key (x): {hex(pub_point.x)}")
    print(f"Public Key (y): {hex(pub_point.y)}")
    
    # 3. 生成比特币地址
    address = public_key_to_address(pub_point)
    print(f"Bitcoin Address: {address}")
    
    # 4. 要签名的消息 (中本聪在创世区块中嵌入的消息)
    message = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
    print(f"\nMessage to sign: {message}")
    
    # 5. 生成签名
    r, s = ecdsa_sign(priv_key, message)
    print(f"\nSignature (r): {hex(r)}")
    print(f"Signature (s): {hex(s)}")
    
    # 6. 转换为DER格式
    der_signature = signature_to_der(r, s)
    print(f"DER Signature: {binascii.hexlify(der_signature).decode()}")
    
    # 7. 验证签名
    is_valid = ecdsa_verify(pub_point, message, (r, s))
    print(f"\nSignature valid: {is_valid}")

if __name__ == "__main__":
    create_satoshi_signature()