# ddh_pisum_demo.py
import os, random, hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from phe import paillier

# --- 工具：hash -> curve point (approximation by scalar*G) ---
def hash_to_scalar(data: bytes, curve: ec.EllipticCurve) -> int:
    # SHA256(data) -> integer mod curve_order
    h = hashlib.sha256(data).digest()
    i = int.from_bytes(h, 'big')
    # get curve order
    if isinstance(curve, ec.SECP256R1):
        # prime256v1 (secp256r1) order:
        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    else:
        # fallback: use a big prime approximation (not ideal)
        order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    return i % order

def scalar_mul_base(scalar: int, curve: ec.EllipticCurve):
    # return public key object representing scalar * G
    private = ec.derive_private_key(scalar % curve.key_size, curve, default_backend())
    # NOTE: ec.derive_private_key expects int < order; we just want a point
    # Safer approach: use elliptic library with scalar mult; here we do:
    priv = ec.derive_private_key(scalar, curve, default_backend())
    pub = priv.public_key()
    return pub

def point_serialize(pub: ec.EllipticCurvePublicKey) -> bytes:
    # compressed point bytes
    return pub.public_bytes(
        encoding=ec.Encoding.X962,
        format=ec.PublicFormat.CompressedPoint
    )

def point_from_scalar(scalar: int, curve: ec.EllipticCurve):
    # build point = scalar * G (using derive_private_key)
    return scalar_mul_base(scalar, curve)

# --- Simulated network messages (in-memory) ---
class Network:
    def __init__(self):
        self.msgs = {}

    def send(self, to, tag, obj):
        self.msgs.setdefault((to, tag), []).append(obj)

    def recv_all(self, to, tag):
        return self.msgs.pop((to, tag), [])

# --- Party implementations following Figure 2 ---
class Party1:
    def __init__(self, items, curve, net: Network):
        self.items = items  # list of identifiers (bytes)
        self.curve = curve
        self.net = net
        # secret exponent k1 (integer)
        # use secure randomness
        self.k1 = int.from_bytes(os.urandom(32), 'big')
        # storage for received set Z in Round2
        self.Z = []
        # received pairs from P2 (H(wj)^k2, Enc(tj))
        self.received_pairs = []

    def round1_send(self):
        # compute H(vi)^k1 for each vi
        out = []
        for v in self.items:
            s = hash_to_scalar(v, self.curve)
            H_vi = point_from_scalar(s, self.curve)       # H(vi) ≈ s*G
            # exponentiate: H(vi)^{k1} -> scalar multiply by k1
            H_vi_k1 = point_from_scalar((s * self.k1) % (1 << 256), self.curve)
            out.append(point_serialize(H_vi_k1))
        random.shuffle(out)
        self.net.send('P2', 'round1', out)

    def round3_receive_and_compute(self, pk):
        # receive Z and pairs
        Z_msgs = self.net.recv_all('P1', 'round2_Z')
        pairs = self.net.recv_all('P1', 'round2_pairs')
        # Z is list of serialized points H(vi)^{k1 k2}
        self.Z = set(Z_msgs[0]) if Z_msgs else set()
        self.received_pairs = pairs[0] if pairs else []

        # For each received pair (H(wj)^k2, AEnc(tj)), compute H(wj)^{k1 k2}
        # by exponentiating first member with k1 (scalar multiply)
        intersection_cts = []
        # We'll use Paillier ciphertext objects directly (same process memory)
        for serialized_point, enc_tj in self.received_pairs:
            # reconstruct point: we used serialization only as bytes for matching, but here for exponentiation we
            # instead compute deterministically from input: we can't invert serialized_point to scalar easily in cryptography API.
            # Simpler: in this simulation P2 will attach also the underlying scalar s_wj so P1 can compute (we do this
            # only for simulation convenience). In real protocol P1 exponentiates the EC point -- in code we'd need EC point operations.
            # Here, assume serialized_point is actually the scalar bytes for s_wj^k2 (we use simplified approach).
            # We'll treat serialized_point as bytes of scalar value for demo.
            # Convert back:
            try:
                s_k2 = int.from_bytes(serialized_point, 'big')
            except:
                s_k2 = 0
            # compute s_k1k2 = s_k2 * k1 (mod large)
            s_k1k2 = (s_k2 * self.k1) % (1 << 256)
            # represent as bytes to compare with Z set (which P1 received in Round2)
            serialized = s_k1k2.to_bytes(32, 'big')
            if serialized in self.Z:
                # in intersection: homomorphically add ciphertexts
                intersection_cts.append(enc_tj)

        if not intersection_cts:
            # produce encryption of 0
            zero_ct = pk.encrypt(0)
            self.net.send('P2', 'round3_result', zero_ct)
            return

        # homomorphically add all ciphertexts (phe supports add via +)
        total_ct = intersection_cts[0]
        for ct in intersection_cts[1:]:
            total_ct = total_ct + ct
        # randomize (re-randomize) ciphertext: phe's ciphertexts are randomized by encrypting 0 and adding
        rand_ct = pk.encrypt(0)
        total_ct = total_ct + rand_ct

        # send randomized ciphertext to P2
        self.net.send('P2', 'round3_result', total_ct)


class Party2:
    def __init__(self, pairs, curve, net: Network):
        self.pairs = pairs  # list of tuples (identifier_bytes, integer_value)
        self.curve = curve
        self.net = net
        self.k2 = int.from_bytes(os.urandom(32), 'big')
        # paillier keypair to be generated in setup
        self.pk = None
        self.sk = None

    def setup_he(self, nbits=1024):
        pub, priv = paillier.generate_paillier_keypair(n_length=nbits)
        self.pk = pub
        self.sk = priv
        # send public key to P1 (in this simulation P1 receives pk directly)
        self.net.send('P1', 'pk', pub)

    def round2_receive_and_send(self):
        # receive Round1 values from P1
        msgs = self.net.recv_all('P2', 'round1')
        if not msgs:
            return
        serialized_list = msgs[0]  # list of serialized H(vi)^{k1} (we used bytes)
        # For each, exponentiate by k2 -> get H(vi)^{k1 k2}
        Z = []
        for b in serialized_list:
            # In this simulation serialized b is zero-padded point bytes; to keep simulation simple we treat as scalar bytes
            s_k1 = int.from_bytes(b, 'big')
            s_k1k2 = (s_k1 * self.k2) % (1 << 256)
            Z.append(s_k1k2.to_bytes(32, 'big'))
        random.shuffle(Z)
        self.net.send('P1', 'round2_Z', Z)

        # For each (wj, tj), compute H(wj)^{k2} and encrypt tj under Paillier
        pairs_to_send = []
        for wj, tj in self.pairs:
            s = hash_to_scalar(wj, self.curve)
            # compute s * k2 (we'll send scalar bytes in this simplified sim)
            s_k2 = (s * self.k2) % (1 << 256)
            serialized = s_k2.to_bytes(32, 'big')
            enc_tj = self.pk.encrypt(tj)
            pairs_to_send.append((serialized, enc_tj))
        random.shuffle(pairs_to_send)
        self.net.send('P1', 'round2_pairs', pairs_to_send)

    def round3_receive_and_output(self):
        # receive total ciphertext
        msgs = self.net.recv_all('P2', 'round3_result')
        if not msgs:
            return None
        total_ct = msgs[0]
        # decrypt
        res = self.sk.decrypt(total_ct)
        return res

# --- Demo run ---
def demo():
    curve = ec.SECP256R1()  # prime256v1 as in the paper
    net = Network()

    # Example datasets
    # P1 has identifiers V
    V = [b'user:alice@example.com', b'user:bob@example.com', b'user:carol@example.com']
    # P2 has pairs (identifier, value)
    W = [
        (b'user:bob@example.com', 50),
        (b'user:david@example.com', 30),
        (b'user:carol@example.com', 20)
    ]

    p1 = Party1(V, curve, net)
    p2 = Party2(W, curve, net)

    # Setup: P2 generates HE keypair and sends pk to P1
    p2.setup_he(nbits=1024)
    # deliver pk to P1
    pk_msgs = net.recv_all('P1', 'pk')
    pk = pk_msgs[0] if pk_msgs else None

    # Round1 (P1 -> P2)
    # For simulation consistency: when serializing we will send scalar*s rather than EC compressed points,
    # so that subsequent code can manipulate scalars easily.
    # So override P1.round1_send to produce scalar bytes (s * k1).
    def p1_round1_send_scalar():
        out = []
        for v in p1.items:
            s = hash_to_scalar(v, curve)
            s_k1 = (s * p1.k1) % (1 << 256)
            out.append(s_k1.to_bytes(32, 'big'))
        random.shuffle(out)
        net.send('P2', 'round1', out)
    p1.round1_send = p1_round1_send_scalar

    # Execute protocol rounds:
    p1.round1_send()
    p2.round2_receive_and_send()
    # P1 must receive Z and pairs and do Round3 using pk
    p1.round3_receive_and_compute(pk)
    # P2 decrypts result
    result = p2.round3_receive_and_output()

    print("P2 recovered intersection-sum:", result)
    # verify with plaintext computation
    true_sum = sum(t for (w, t) in W if w in V)
    print("Ground-truth intersection-sum:", true_sum)
    assert result == true_sum
    print("OK: protocol result matches plaintext sum.")

if __name__ == '__main__':
    demo()
