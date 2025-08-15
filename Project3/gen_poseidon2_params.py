#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generate Poseidon2 parameters for (n,t,d)=(256,2,5) and (256,3,5).
Outputs JSON files: poseidon2_t2.json, poseidon2_t3.json

References:
- Poseidon2 paper: rounds RF=8, RP=56 for (256,2,5) and (256,3,5) [Table 1].
- Internal rounds use only ONE round constant on state[0].
- For t in {2,3}: choose MI as Neptune-style matrix, ensure it's MDS, and set ME = MI.

Prime: use the 255-bit BLS12-381 scalar field (as used widely in ZK systems).
"""

import json
from hashlib import shake_256
from typing import List, Tuple

# ----- Field definition (BLS12-381 scalar field, 255-bit) -----
# p_BLS12 (from the paper appendix/benchmarks)
P = int("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

# ----- Poseidon2 core parameters for our instances -----
D = 5              # S-box exponent d
RF = 8             # full/external rounds (Table 1)
RP = 56            # partial/internal rounds (Table 1)

# Domain separation (free to choose; kept explicit & stable)
DOMAIN = b"Poseidon2-params::v1"

# ---------- Utilities ----------

def bytes_to_int_le(b: bytes) -> int:
    return int.from_bytes(b, "little")

def draw_field_elems(seed: bytes, count: int, p: int) -> List[int]:
    """
    Sample 'count' field elements via SHAKE-256 XOF with domain separation.
    This mirrors the common 'hash-to-field by rejection' style used in Poseidonπ param scripts:
    keep streaming bytes and reduce mod p (mod-reduction bias is negligible with SHAKE stream and 255-bit p,
    but we additionally sample plenty of bits to be safe).
    """
    # We pull 64 bytes per element and reduce mod p; increase if you want stricter min-entropy margins.
    xof = shake_256(seed)
    out = []
    while len(out) < count:
        block = xof.digest(64)
        v = bytes_to_int_le(block) % p
        out.append(v)
        # reinitialize XOF chained with last block to keep streaming distinct chunks deterministically
        xof = shake_256(block)
    return out

def is_invertible(mat: List[List[int]], p: int) -> bool:
    # Compute det via Gaussian elimination mod p.
    n = len(mat)
    A = [row[:] for row in mat]
    det = 1
    for i in range(n):
        # find pivot
        pivot = i
        while pivot < n and A[pivot][i] % p == 0:
            pivot += 1
        if pivot == n:
            return False
        if pivot != i:
            A[i], A[pivot] = A[pivot], A[i]
            det = (-det) % p
        inv = pow(A[i][i], p - 2, p)
        det = (det * A[i][i]) % p
        # normalize row
        for j in range(i, n):
            A[i][j] = (A[i][j] * inv) % p
        # eliminate below
        for r in range(i + 1, n):
            factor = A[r][i]
            if factor:
                for c in range(i, n):
                    A[r][c] = (A[r][c] - factor * A[i][c]) % p
    return det % p != 0

def neptune_matrix(mu: List[int], p: int) -> List[List[int]]:
    """
    MI as in Neptune style:
    diagonal = mu[i], off-diagonal = 1.
    """
    t = len(mu)
    M = [[1] * t for _ in range(t)]
    for i in range(t):
        M[i][i] = mu[i] % p
    return M

def check_mds_t2(mu0: int, mu1: int, p: int) -> bool:
    # Conditions from the paper for t=2:
    # mu0*mu1 - 1 != 0 and mu0, mu1 != 0
    return (mu0 % p != 0) and (mu1 % p != 0) and ((mu0 * mu1 - 1) % p != 0)

def check_mds_t3(mu: List[int], p: int) -> bool:
    # Conditions from the paper for t=3:
    # mu0*mu1*mu2 - mu0 - mu1 - mu2 + 2 != 0
    # and mu_i != 0, mu_i*mu_j - 1 != 0 for i!=j
    mu0, mu1, mu2 = [m % p for m in mu]
    if 0 in (mu0, mu1, mu2):
        return False
    if (mu0 * mu1 - 1) % p == 0: return False
    if (mu0 * mu2 - 1) % p == 0: return False
    if (mu1 * mu2 - 1) % p == 0: return False
    cond = (mu0 * mu1 * mu2 - mu0 - mu1 - mu2 + 2) % p != 0
    return cond

def pick_mu_values(t: int, p: int) -> List[int]:
    """
    Choose small positive integers in [2, p//4] to satisfy the paper's easy MDS conditions for t=2,3.
    The paper notes any selection in {2,3,...,p/4} will satisfy the 'xy != 1' constraints for t=2,3.
    We'll try small set and assert MDS + invertible.
    """
    candidates = [2, 3, 5, 7, 11, 13, 17]
    if t == 2:
        for a in candidates:
            for b in candidates:
                if check_mds_t2(a, b, p):
                    return [a, b]
        raise RuntimeError("Failed to find mu for t=2")
    elif t == 3:
        for a in candidates:
            for b in candidates:
                for c in candidates:
                    mu = [a, b, c]
                    if check_mds_t3(mu, p):
                        return mu
        raise RuntimeError("Failed to find mu for t=3")
    else:
        raise ValueError("This picker is only for t in {2,3}")

def generate_round_constants(p: int, t: int, rf: int, rp: int,
                             d: int, seed_tag: bytes) -> Tuple[List[List[int]], List[int]]:
    """
    Following Poseidonπ approach: derive round constants from XOF(seed || params).
    - external: rf rounds, each with t constants
    - internal: rp rounds, each with ONE constant for state[0] (Poseidon2)
    """
    # Assemble parameter string for domain separation (make it explicit & deterministic)
    param_blob = (
        seed_tag + b"|" +
        f"p={p}".encode() + b"|" +
        f"t={t}".encode() + b"|" +
        f"rf={rf}".encode() + b"|" +
        f"rp={rp}".encode() + b"|" +
        f"d={d}".encode()
    )
    ext_needed = rf * t
    int_needed = rp

    ext_flat = draw_field_elems(param_blob + b"|ext", ext_needed, p)
    int_list = draw_field_elems(param_blob + b"|int", int_needed, p)

    # reshape external to [rf][t]
    external = [ext_flat[i * t:(i + 1) * t] for i in range(rf)]
    internal = int_list  # length rp
    return external, internal

def export_instance(t: int, p: int, rf: int, rp: int, d: int, out_json: str):
    # Pick MI (Neptune-style) and set ME = MI (t in {2,3})
    mu = pick_mu_values(t, p)
    MI = neptune_matrix(mu, p)
    assert is_invertible(MI, p), "MI must be invertible"
    if t == 2:
        assert check_mds_t2(mu[0], mu[1], p), "MI must be MDS for t=2"
    elif t == 3:
        assert check_mds_t3(mu, p), "MI must be MDS for t=3"
    ME = [row[:] for row in MI]  # ME = MI for t in {2,3}

    # Round constants (Poseidonπ method with DS, but Poseidon2 internal only one const per round)
    rc_ext, rc_int = generate_round_constants(
        p=p, t=t, rf=rf, rp=rp, d=d, seed_tag=DOMAIN
    )

    params = {
        "field_modulus_hex": hex(p),
        "field_modulus_dec": str(p),
        "t": t,
        "d": d,
        "RF": rf,
        "RP": rp,
        "matrix_ME": ME,
        "matrix_MI": MI,
        "mu_values": mu,
        "round_constants_external": rc_ext,     # shape [RF][t]
        "round_constants_internal_c0": rc_int,  # length RP; apply only to state[0]
        "notes": {
            "round_constants_method": "SHAKE256 XOF with explicit domain separation; same philosophy as Poseidonπ parameter script.",
            "internal_round_constant_policy": "Poseidon2 uses ONLY one constant on state[0] per internal round."
        }
    }

    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(params, f, ensure_ascii=False, indent=2)

    print(f"✓ Wrote {out_json}")

def main():
    export_instance(t=2, p=P, rf=RF, rp=RP, d=D, out_json="poseidon2_t2.json")
    export_instance(t=3, p=P, rf=RF, rp=RP, d=D, out_json="poseidon2_t3.json")

if __name__ == "__main__":
    main()
