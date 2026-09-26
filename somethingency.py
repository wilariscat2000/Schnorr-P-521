#!/usr/bin/env python3
"""
Schnorr P-521 file-signing tool.

Educational / experimental implementation.

No external cryptographic or elliptic-curve library is used.
The only cryptographic primitives used from Python's standard library are:

    hashlib.sha256
    hmac
    secrets

Everything at the protocol / elliptic-curve level is implemented here.

IMPORTANT:
    The Montgomery ladder below is STRUCTURALLY constant-time:
    its sequence of EC operations does not depend on secret scalar bits.

    Python itself is NOT a constant-time execution environment.
    Python big integers, object allocation, garbage collection,
    interpreter behavior, caches, etc. can still introduce timing leakage.

    Therefore this is NOT suitable for high-value production key storage.
"""


# ============================================================================
# Imports
# ============================================================================

import argparse
import hashlib
import hmac
import os
import secrets
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# ============================================================================
# 0. NIST P-521 PARAMETERS
# ============================================================================
#
# Curve:
#
#     y^2 = x^3 + ax + b mod p
#
# P-521:
#
#     p = 2^521 - 1
#
# The subgroup order n is a 521-bit prime.
#
# Generic Pollard-rho DLP cost:
#
#     O(sqrt(n)) ~= 2^260.5
#
# which exceeds the requested ~256-bit security target.
#
# By contrast, a 256-bit EC group only gives about 128-bit generic
# discrete-log security.
#
# ============================================================================

P = (
    0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
)

A = (
    0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC"
)

B = int(
    "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF1"
    "09E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
    16,
)

GX = int(
    "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3D"
    "BAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
    16,
)

GY = int(
    "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662"
    "C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
    16,
)

G = (GX, GY)

N = int(
    "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
    16,
)

FIELD_BYTES = 66

# Point at infinity.
Point = Optional[tuple[int, int]]
O: Point = None


# ============================================================================
# Utility functions
# ============================================================================

def random_scalar() -> int:
    """
    Cryptographically secure random scalar in [1, N).

    secrets.randbelow() uses an OS-backed cryptographically secure source.

    Do NOT use random.randint() here. The random module uses Mersenne
    Twister and is not suitable for cryptographic secrets.
    """
    return secrets.randbelow(N - 1) + 1


def fixed_width_int(value: int) -> bytes:
    """Encode a field element as exactly 66 big-endian bytes."""
    return value.to_bytes(FIELD_BYTES, "big")


def hex_fixed(value: int) -> str:
    """Uppercase fixed-width hexadecimal representation."""
    return fixed_width_int(value).hex().upper()


# ============================================================================
# 1. MODULAR ARITHMETIC
# ============================================================================

def inv_mod(value: int, modulus: int) -> int:
    """
    Modular inverse using Fermat's little theorem.

        a^(-1) = a^(p-2) mod p

    This is valid because the relevant moduli here are prime.

    This is NOT an EC-library operation; it is ordinary modular
    exponentiation using Python's built-in arbitrary-precision arithmetic.
    """
    value %= modulus

    if value == 0:
        raise ZeroDivisionError("zero has no modular inverse")

    return pow(value, modulus - 2, modulus)


# ============================================================================
# 2. AFFINE ELLIPTIC-CURVE OPERATIONS
# ============================================================================
#
# These are the transparent from-scratch group operations.
#
# Weierstrass curve:
#
#     y^2 = x^3 + ax + b
#
# ============================================================================

def is_on_curve(Q: Point) -> bool:
    """Return True iff Q is on P-521."""
    if Q is O:
        return True

    x, y = Q

    if not (0 <= x < P):
        return False

    if not (0 <= y < P):
        return False

    left = (y * y) % P

    right = (
        x * x * x
        + A * x
        + B
    ) % P

    return left == right


def point_negate(Q: Point) -> Point:
    """
    -(x,y) = (x,-y mod p)
    """
    if Q is O:
        return O

    x, y = Q

    return (
        x,
        (-y) % P,
    )


def point_double(Q: Point) -> Point:
    """
    Affine point doubling.

    For:

        Q = (x1,y1)

    lambda is:

        (3*x1^2 + a) / (2*y1)

    and:

        x3 = lambda^2 - 2*x1
        y3 = lambda(x1-x3) - y1
    """
    if Q is O:
        return O

    x1, y1 = Q

    if y1 == 0:
        return O

    numerator = (
        3 * x1 * x1
        + A
    ) % P

    denominator = (
        2 * y1
    ) % P

    lam = (
        numerator
        * inv_mod(denominator, P)
    ) % P

    x3 = (
        lam * lam
        - 2 * x1
    ) % P

    y3 = (
        lam * (x1 - x3)
        - y1
    ) % P

    return x3, y3


def point_add(Q1: Point, Q2: Point) -> Point:
    """
    Affine point addition.

    Cases:

        O + Q = Q

        Q + O = Q

        Q + Q = 2Q

        Q + (-Q) = O

    Otherwise use the ordinary chord formula.
    """
    if Q1 is O:
        return Q2

    if Q2 is O:
        return Q1

    x1, y1 = Q1
    x2, y2 = Q2

    # Doubling is handled separately.
    if Q1 == Q2:
        return point_double(Q1)

    # Same x coordinate but different y means inverse points.
    if x1 == x2:
        return O

    numerator = (
        y2 - y1
    ) % P

    denominator = (
        x2 - x1
    ) % P

    lam = (
        numerator
        * inv_mod(denominator, P)
    ) % P

    x3 = (
        lam * lam
        - x1
        - x2
    ) % P

    y3 = (
        lam * (x1 - x3)
        - y1
    ) % P

    return x3, y3


def point_subtract(Q1: Point, Q2: Point) -> Point:
    """Q1 - Q2 = Q1 + (-Q2)."""
    return point_add(
        Q1,
        point_negate(Q2),
    )


# ============================================================================
# 3. ORIGINAL DOUBLE-AND-ADD SCALAR MULTIPLICATION
# ============================================================================
#
# This is deliberately retained as a reference implementation.
#
# It is NOT suitable for secret scalars because:
#
#     if k & 1:
#
# makes the executed operation sequence depend on scalar bits.
#
# That is the timing-side-channel problem we are fixing.
#
# ============================================================================

def scalar_mult_double_and_add(
    k: int,
    Q: Point,
) -> Point:
    """
    Original binary double-and-add implementation.

    RETAINED ONLY FOR REGRESSION TESTING.

    Do not use this implementation for secret scalar operations.
    """
    if Q is O or k == 0:
        return O

    if k < 0:
        return scalar_mult_double_and_add(
            -k,
            point_negate(Q),
        )

    result = O
    addend = Q

    while k:
        # SECRET-DEPENDENT BRANCH.
        #
        # This is precisely the branch removed from the production path.
        if k & 1:
            result = point_add(
                result,
                addend,
            )

        addend = point_double(addend)

        k >>= 1

    return result


# ============================================================================
# 4. JACOBIAN OPERATIONS FOR THE MONTGOMERY LADDER
# ============================================================================
#
# Jacobian representation:
#
#     affine x = X / Z^2
#     affine y = Y / Z^3
#
# The ladder performs additions/doublings without an inversion on every
# operation. One final inversion converts back to affine coordinates.
#
# ============================================================================

Jacobian = tuple[int, int, int]


def jacobian_from_affine(Q: Point) -> Jacobian:
    """Convert affine point to Jacobian coordinates."""
    if Q is O:
        return 0, 1, 0

    x, y = Q

    return x, y, 1


def jacobian_to_affine(J: Jacobian) -> Point:
    """Convert Jacobian coordinates back to affine."""
    X, Y, Z = J

    if Z == 0:
        return O

    z_inv = inv_mod(
        Z,
        P,
    )

    z_inv2 = (
        z_inv * z_inv
    ) % P

    x = (
        X * z_inv2
    ) % P

    y = (
        Y
        * z_inv2
        * z_inv
    ) % P

    return x, y


def jacobian_double(J: Jacobian) -> Jacobian:
    """
    Jacobian point doubling.

    No secret-dependent branches are used here for the normal non-infinity
    path.
    """
    X1, Y1, Z1 = J

    # Infinity representation.
    if Z1 == 0:
        return 0, 1, 0

    # Point with y=0 doubles to infinity.
    if Y1 == 0:
        return 0, 1, 0

    Y1_squared = (
        Y1 * Y1
    ) % P

    S = (
        4
        * X1
        * Y1_squared
    ) % P

    Z1_squared = (
        Z1 * Z1
    ) % P

    Z1_fourth = (
        Z1_squared
        * Z1_squared
    ) % P

    M = (
        3 * X1 * X1
        + A * Z1_fourth
    ) % P

    X3 = (
        M * M
        - 2 * S
    ) % P

    Y1_fourth = (
        Y1_squared
        * Y1_squared
    ) % P

    Y3 = (
        M * (S - X3)
        - 8 * Y1_fourth
    ) % P

    Z3 = (
        2 * Y1 * Z1
    ) % P

    return X3, Y3, Z3


def jacobian_add(
    J1: Jacobian,
    J2: Jacobian,
) -> Jacobian:
    """
    Jacobian point addition.

    This is the generic group addition used by the ladder.
    """
    X1, Y1, Z1 = J1
    X2, Y2, Z2 = J2

    if Z1 == 0:
        return J2

    if Z2 == 0:
        return J1

    Z1_squared = (
        Z1 * Z1
    ) % P

    Z2_squared = (
        Z2 * Z2
    ) % P

    U1 = (
        X1 * Z2_squared
    ) % P

    U2 = (
        X2 * Z1_squared
    ) % P

    Z1_cubed = (
        Z1
        * Z1_squared
    ) % P

    Z2_cubed = (
        Z2
        * Z2_squared
    ) % P

    S1 = (
        Y1 * Z2_cubed
    ) % P

    S2 = (
        Y2 * Z1_cubed
    ) % P

    # Equal x coordinates.
    if U1 == U2:

        # Same point.
        if S1 == S2:
            return jacobian_double(J1)

        # Inverse points.
        return 0, 1, 0

    H = (
        U2 - U1
    ) % P

    R = (
        S2 - S1
    ) % P

    H_squared = (
        H * H
    ) % P

    H_cubed = (
        H * H_squared
    ) % P

    V = (
        U1 * H_squared
    ) % P

    X3 = (
        R * R
        - H_cubed
        - 2 * V
    ) % P

    Y3 = (
        R * (V - X3)
        - S1 * H_cubed
    ) % P

    Z3 = (
        H
        * Z1
        * Z2
    ) % P

    return X3, Y3, Z3


# ============================================================================
# 5. ARITHMETIC CONDITIONAL SWAP
# ============================================================================
#
# For bit = 0:
#
#     mask = 0
#
# For bit = 1:
#
#     mask = -1
#
# In Python integers, -1 behaves as an infinite two's-complement word:
#
#     x & -1 == x
#
# and:
#
#     x & ~(-1) == 0
#
# This lets us select between integer coordinates without an if statement
# based on the scalar bit.
#
# ============================================================================

def cswap_int(
    bit: int,
    x: int,
    y: int,
) -> tuple[int, int]:
    """
    Arithmetic conditional swap.

    bit must be 0 or 1.
    """
    mask = -bit

    x_new = (
        (x & ~mask)
        | (y & mask)
    )

    y_new = (
        (y & ~mask)
        | (x & mask)
    )

    return x_new, y_new


def cswap_jacobian(
    bit: int,
    R0: Jacobian,
    R1: Jacobian,
) -> tuple[Jacobian, Jacobian]:
    """
    Conditional swap of two Jacobian points.

    Each coordinate is selected arithmetically.
    """
    X0, Y0, Z0 = R0
    X1, Y1, Z1 = R1

    X0, X1 = cswap_int(
        bit,
        X0,
        X1,
    )

    Y0, Y1 = cswap_int(
        bit,
        Y0,
        Y1,
    )

    Z0, Z1 = cswap_int(
        bit,
        Z0,
        Z1,
    )

    return (
        X0,
        Y0,
        Z0,
    ), (
        X1,
        Y1,
        Z1,
    )


# ============================================================================
# 6. MONTGOMERY-LADDER SCALAR MULTIPLICATION
# ============================================================================
#
# The ladder maintains:
#
#     R0 = current multiple
#     R1 = R0 + Q
#
# At each scalar bit, BOTH:
#
#     R0 + R1
#     2R0 / 2R1
#
# are calculated.
#
# The selected ordering is controlled with cswap rather than:
#
#     if bit:
#
# Thus the scalar's Hamming weight does not change the number of EC
# operations.
#
# We process exactly 521 bits for P-521.
#
# ============================================================================

def scalar_mult_ladder(
    k: int,
    Q: Point,
) -> Point:
    """
    Structurally constant-operation-count scalar multiplication.

    This is the scalar multiplication used by the signing implementation.

    IMPORTANT:
        Python is not a genuinely constant-time language/runtime.
        This function removes the obvious scalar-bit-dependent operation
        schedule but does not guarantee machine-level constant timing.
    """
    if Q is O:
        return O

    if k < 0:
        return scalar_mult_ladder(
            -k,
            point_negate(Q),
        )

    if k >= N:
        k %= N

    # We deliberately process exactly N.bit_length() = 521 bits.
    bit_length = N.bit_length()

    R0 = (
        0,
        1,
        0,
    )

    R1 = jacobian_from_affine(Q)

    previous_bit = 0

    for i in range(
        bit_length - 1,
        -1,
        -1,
    ):
        bit = (
            k >> i
        ) & 1

        # Convert the transition into a swap decision.
        swap = bit ^ previous_bit

        R0, R1 = cswap_jacobian(
            swap,
            R0,
            R1,
        )

        # Both operations are performed regardless of the scalar bit.
        #
        # Before the final swap, one register represents R0 and the other
        # R1 = R0 + Q.
        #
        # Calculate both candidate operations.
        added = jacobian_add(
            R0,
            R1,
        )

        doubled = jacobian_double(
            R0,
        )

        # Put candidates in a fixed arrangement.
        R1 = added
        R0 = doubled

        previous_bit = bit

    # Final swap.
    R0, R1 = cswap_jacobian(
        previous_bit,
        R0,
        R1,
    )

    return jacobian_to_affine(R0)


# Public scalar multiplication used by the rest of the implementation.
scalar_mult = scalar_mult_ladder


# ============================================================================
# 7. POINT SERIALIZATION
# ============================================================================
#
# Exact format:
#
#     0x04
#     || x: 66-byte big-endian
#     || y: 66-byte big-endian
#
# Total:
#
#     1 + 66 + 66 = 133 bytes
#
# Fixed-width encoding is important because every mathematical coordinate
# must have exactly one byte representation.
#
# ============================================================================

POINT_ENCODING_LENGTH = (
    1
    + FIELD_BYTES
    + FIELD_BYTES
)


def serialize_point(Q: Point) -> bytes:
    """Serialize an affine point in SEC1-style uncompressed form."""
    if Q is O:
        raise ValueError(
            "point at infinity cannot be serialized"
        )

    if not is_on_curve(Q):
        raise ValueError(
            "cannot serialize invalid curve point"
        )

    x, y = Q

    return (
        b"\x04"
        + fixed_width_int(x)
        + fixed_width_int(y)
    )


def deserialize_point(data: bytes) -> Point:
    """Parse exactly one P-521 uncompressed point."""
    if len(data) != POINT_ENCODING_LENGTH:
        raise ValueError(
            "invalid P-521 point length"
        )

    if data[0] != 0x04:
        raise ValueError(
            "expected uncompressed point prefix 0x04"
        )

    x = int.from_bytes(
        data[1:1 + FIELD_BYTES],
        "big",
    )

    y = int.from_bytes(
        data[1 + FIELD_BYTES:],
        "big",
    )

    Q = (
        x,
        y,
    )

    if not is_on_curve(Q):
        raise ValueError(
            "point is not on P-521"
        )

    return Q


# ============================================================================
# 8. HMAC-SHA256 DETERMINISTIC NONCE
# ============================================================================
#
# RFC-6979-style construction.
#
# This is analogous to RFC 6979 but intentionally adapted for Schnorr.
#
# Inputs:
#
#     private scalar x
#     SHA-256(message)
#
# Output:
#
#     r in [1, N)
#
# The crucial property is:
#
#     r = deterministic_function(x, message)
#
# so the application does not have to remember to "never reuse r".
#
# ============================================================================

def int2octets(value: int) -> bytes:
    """
    Encode integer as fixed-width 66-byte big-endian data.
    """
    return value.to_bytes(
        FIELD_BYTES,
        "big",
    )


def deterministic_nonce(
    private_key: int,
    message_hash: bytes,
) -> int:
    """
    RFC-6979-style HMAC-SHA256 deterministic nonce generator.

    The construction uses HMAC-SHA256's V/K state and rejection sampling.

    A counter is included in the retry input to make retries unambiguous.
    """
    if not (1 <= private_key < N):
        raise ValueError(
            "private key out of range"
        )

    if len(message_hash) != 32:
        raise ValueError(
            "message_hash must be a SHA-256 digest"
        )

    x_bytes = int2octets(
        private_key
    )

    # Initial RFC-6979-style state.
    V = b"\x01" * 32
    K = b"\x00" * 32

    K = hmac.new(
        K,
        V
        + b"\x00"
        + x_bytes
        + message_hash,
        hashlib.sha256,
    ).digest()

    V = hmac.new(
        K,
        V,
        hashlib.sha256,
    ).digest()

    K = hmac.new(
        K,
        V
        + b"\x01"
        + x_bytes
        + message_hash,
        hashlib.sha256,
    ).digest()

    V = hmac.new(
        K,
        V,
        hashlib.sha256,
    ).digest()

    counter = 0

    while True:
        # We need 521 bits because n is a 521-bit number.
        #
        # Generate 66 bytes and mask off the unused high 7 bits.
        #
        # This produces a uniform candidate in [0, 2^521).
        T = bytearray()

        while len(T) < FIELD_BYTES:
            V = hmac.new(
                K,
                V,
                hashlib.sha256,
            ).digest()

            T.extend(V)

        candidate_bytes = bytes(
            T[:FIELD_BYTES]
        )

        candidate_int = int.from_bytes(
            candidate_bytes,
            "big",
        )

        # 521 bits occupy 66 bytes; 66*8 = 528.
        # Mask off the seven unused high bits.
        candidate_int &= (
            (1 << 521) - 1
        )

        # Required valid nonce range:
        #
        #     1 <= r < N
        #
        # The R=O case is also excluded.
        if (
            1 <= candidate_int < N
        ):
            R = scalar_mult(
                candidate_int,
                G,
            )

            if R is not O:
                return candidate_int

        # Rejection / retry.
        #
        # This is deliberately extremely unlikely for P-521 but is required
        # for a correct bounded generator.
        counter += 1

        K = hmac.new(
            K,
            V
            + b"\x00"
            + counter.to_bytes(
                4,
                "big",
            ),
            hashlib.sha256,
        ).digest()

        V = hmac.new(
            K,
            V,
            hashlib.sha256,
        ).digest()


# ============================================================================
# 9. SCHNORR DIGITAL SIGNATURE
# ============================================================================
#
# Signature:
#
#     m_hash = SHA256(m)
#
#     r = deterministic_nonce(x, m_hash)
#
#     R = rG
#
#     e = SHA256(
#             serialize(R)
#             || serialize(Y)
#             || m_hash
#         ) mod N
#
#     s = r + e*x mod N
#
# Signature:
#
#     (R, s)
#
# Verification:
#
#     e = H(R || Y || m_hash)
#
#     sG == R + eY
#
# ============================================================================

@dataclass(frozen=True)
class SchnorrSignature:
    R: Point
    s: int


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def message_digest(message: bytes) -> bytes:
    """Hash file/message contents."""
    return sha256(message)


def challenge_for_signature(
    R: Point,
    Y: Point,
    message_hash: bytes,
) -> int:
    """
    Message-bound Schnorr challenge.

    The exact message digest is included, so a signature is tied to the
    particular file contents.
    """
    data = (
        serialize_point(R)
        + serialize_point(Y)
        + message_hash
    )

    digest = sha256(data)

    return int.from_bytes(
        digest,
        "big",
    ) % N


def sign_message(
    private_key: int,
    message: bytes,
) -> SchnorrSignature:
    """
    Sign a message using deterministic Schnorr nonce generation.
    """
    if not (1 <= private_key < N):
        raise ValueError(
            "private key out of range"
        )

    Y = scalar_mult(
        private_key,
        G,
    )

    m_hash = message_digest(
        message
    )

    r = deterministic_nonce(
        private_key,
        m_hash,
    )

    R = scalar_mult(
        r,
        G,
    )

    if R is O:
        raise RuntimeError(
            "deterministic nonce produced R=O"
        )

    e = challenge_for_signature(
        R,
        Y,
        m_hash,
    )

    s = (
        r
        + e * private_key
    ) % N

    return SchnorrSignature(
        R=R,
        s=s,
    )


def verify_signature(
    public_key: Point,
    message: bytes,
    signature: SchnorrSignature,
) -> bool:
    """
    Verify:

        sG == R + eY
    """
    if public_key is O:
        return False

    if not is_on_curve(public_key):
        return False

    if signature.R is O:
        return False

    if not is_on_curve(signature.R):
        return False

    if not (0 <= signature.s < N):
        return False

    m_hash = message_digest(
        message
    )

    e = challenge_for_signature(
        signature.R,
        public_key,
        m_hash,
    )

    lhs = scalar_mult(
        signature.s,
        G,
    )

    rhs = point_add(
        signature.R,
        scalar_mult(
            e,
            public_key,
        ),
    )

    return lhs == rhs


# ============================================================================
# 10. PRIVATE / PUBLIC KEY FILE FORMATS
# ============================================================================
#
# PRIVATE:
#
#     132 hex characters + newline
#
# PUBLIC:
#
#     266 hex characters + newline
#
#     04 || X || Y
#
# The private key is deliberately NOT encrypted in this educational tool.
# A real tool should protect it using passphrase-based encryption and ideally
# hardware-backed storage.
#
# ============================================================================

PRIVATE_HEX_LENGTH = (
    FIELD_BYTES * 2
)

PUBLIC_HEX_LENGTH = (
    POINT_ENCODING_LENGTH * 2
)


def write_private_key(
    filename: Path,
    private_key: int,
) -> None:
    """
    Write private scalar as hexadecimal.

    Deliberately plaintext for this exercise.
    """
    if not (1 <= private_key < N):
        raise ValueError(
            "private key out of range"
        )

    filename.write_text(
        hex_fixed(private_key)
        + "\n",
        encoding="ascii",
    )

    # Restrict permissions where supported.
    try:
        os.chmod(
            filename,
            stat.S_IRUSR
            | stat.S_IWUSR,
        )
    except OSError:
        pass


def read_private_key(
    filename: Path,
) -> int:
    data = filename.read_text(
        encoding="ascii"
    ).strip()

    if len(data) != PRIVATE_HEX_LENGTH:
        raise ValueError(
            "invalid private-key length"
        )

    try:
        value = int(
            data,
            16,
        )
    except ValueError:
        raise ValueError(
            "invalid private-key hex"
        )

    if not (1 <= value < N):
        raise ValueError(
            "private key out of range"
        )

    return value


def write_public_key(
    filename: Path,
    public_key: Point,
) -> None:
    data = serialize_point(
        public_key
    )

    filename.write_text(
        data.hex().upper()
        + "\n",
        encoding="ascii",
    )


def read_public_key(
    filename: Path,
) -> Point:
    data = filename.read_text(
        encoding="ascii"
    ).strip()

    if len(data) != PUBLIC_HEX_LENGTH:
        raise ValueError(
            "invalid public-key length"
        )

    try:
        raw = bytes.fromhex(
            data
        )
    except ValueError:
        raise ValueError(
            "invalid public-key hex"
        )

    return deserialize_point(
        raw
    )


# ============================================================================
# 11. SIGNATURE FILE FORMAT
# ============================================================================
#
# Exact textual format:
#
#     SCHNORR-P521-SIG-V1
#     R=<266 hex characters>
#     s=<132 hex characters>
#
# ============================================================================

SIGNATURE_HEADER = (
    "SCHNORR-P521-SIG-V1"
)


def write_signature(
    filename: Path,
    signature: SchnorrSignature,
) -> None:
    R_hex = serialize_point(
        signature.R
    ).hex().upper()

    s_hex = hex_fixed(
        signature.s
    )

    text = (
        SIGNATURE_HEADER
        + "\n"
        + "R="
        + R_hex
        + "\n"
        + "s="
        + s_hex
        + "\n"
    )

    filename.write_text(
        text,
        encoding="ascii",
    )


def read_signature(
    filename: Path,
) -> SchnorrSignature:
    """
    Strict parser.

    Malformed signatures are rejected rather than raising an uncaught
    exception through the CLI.
    """
    text = filename.read_text(
        encoding="ascii"
    )

    lines = text.splitlines()

    if len(lines) != 3:
        raise ValueError(
            "invalid signature format"
        )

    if lines[0] != SIGNATURE_HEADER:
        raise ValueError(
            "invalid signature header"
        )

    if not lines[1].startswith("R="):
        raise ValueError(
            "missing R"
        )

    if not lines[2].startswith("s="):
        raise ValueError(
            "missing s"
        )

    R_hex = lines[1][2:]
    s_hex = lines[2][2:]

    if len(R_hex) != PUBLIC_HEX_LENGTH:
        raise ValueError(
            "invalid R length"
        )

    if len(s_hex) != PRIVATE_HEX_LENGTH:
        raise ValueError(
            "invalid s length"
        )

    try:
        R_bytes = bytes.fromhex(
            R_hex
        )

        s = int(
            s_hex,
            16,
        )
    except ValueError:
        raise ValueError(
            "invalid signature encoding"
        )

    if not (0 <= s < N):
        raise ValueError(
            "s outside subgroup order"
        )

    R = deserialize_point(
        R_bytes
    )

    if R is O:
        raise ValueError(
            "R cannot be infinity"
        )

    return SchnorrSignature(
        R=R,
        s=s,
    )


# ============================================================================
# 12. FILE HELPERS
# ============================================================================

def read_file(
    filename: Path,
) -> bytes:
    return filename.read_bytes()


def signature_filename(
    input_filename: Path,
) -> Path:
    return Path(
        str(input_filename)
        + ".sig"
    )


# ============================================================================
# 13. CLI: KEYGEN
# ============================================================================

def command_keygen(
    args: argparse.Namespace,
) -> int:
    prefix = Path(
        args.out
    )

    private_filename = Path(
        str(prefix)
        + ".priv"
    )

    public_filename = Path(
        str(prefix)
        + ".pub"
    )

    if (
        private_filename.exists()
        or public_filename.exists()
    ):
        if not args.force:
            print(
                "ERROR: key files already exist; "
                "use --force to overwrite",
                file=sys.stderr,
            )

            return 2

    private_key = random_scalar()

    public_key = scalar_mult(
        private_key,
        G,
    )

    write_private_key(
        private_filename,
        private_key,
    )

    write_public_key(
        public_filename,
        public_key,
    )

    print(
        "Generated:"
    )

    print(
        f"  private: {private_filename}"
    )

    print(
        f"  public:  {public_filename}"
    )

    return 0


# ============================================================================
# 14. CLI: SIGN
# ============================================================================

def command_sign(
    args: argparse.Namespace,
) -> int:
    key_prefix = Path(
        args.key
    )

    private_filename = Path(
        str(key_prefix)
        + ".priv"
    )

    input_filename = Path(
        args.file
    )

    output_filename = (
        Path(args.out)
        if args.out
        else signature_filename(
            input_filename
        )
    )

    try:
        private_key = read_private_key(
            private_filename
        )

        message = read_file(
            input_filename
        )

        signature = sign_message(
            private_key,
            message,
        )

        write_signature(
            output_filename,
            signature,
        )

    except (
        OSError,
        ValueError,
        RuntimeError,
    ) as exc:
        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )

        return 2

    print(
        f"SIGNED: {input_filename}"
    )

    print(
        f"SIGNATURE: {output_filename}"
    )

    return 0


# ============================================================================
# 15. CLI: VERIFY
# ============================================================================

def command_verify(
    args: argparse.Namespace,
) -> int:
    public_filename = Path(
        args.pubkey
    )

    input_filename = Path(
        args.file
    )

    signature_filename_arg = Path(
        args.sig
    )

    try:
        public_key = read_public_key(
            public_filename
        )

        message = read_file(
            input_filename
        )

        signature = read_signature(
            signature_filename_arg
        )

        valid = verify_signature(
            public_key,
            message,
            signature,
        )

    except (
        OSError,
        ValueError,
        RuntimeError,
    ):
        # Verification deliberately collapses malformed input into INVALID.
        print("INVALID")
        return 1

    if valid:
        print("VALID")
        return 0

    print("INVALID")
    return 1


# ============================================================================
# 16. CLI ARGUMENT PARSER
# ============================================================================

def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Educational Schnorr P-521 file-signing tool"
        )
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # ------------------------------------------------------------------------
    # keygen
    # ------------------------------------------------------------------------

    keygen = subparsers.add_parser(
        "keygen",
        help="generate a P-521 Schnorr key pair",
    )

    keygen.add_argument(
        "--out",
        required=True,
        help="key-file prefix",
    )

    keygen.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing key files",
    )

    keygen.set_defaults(
        function=command_keygen
    )

    # ------------------------------------------------------------------------
    # sign
    # ------------------------------------------------------------------------

    sign = subparsers.add_parser(
        "sign",
        help="sign a file",
    )

    sign.add_argument(
        "--key",
        required=True,
        help="private-key file prefix",
    )

    sign.add_argument(
        "--file",
        required=True,
        help="file to sign",
    )

    sign.add_argument(
        "--out",
        help="signature filename; defaults to <file>.sig",
    )

    sign.set_defaults(
        function=command_sign
    )

    # ------------------------------------------------------------------------
    # verify
    # ------------------------------------------------------------------------

    verify = subparsers.add_parser(
        "verify",
        help="verify a file signature",
    )

    verify.add_argument(
        "--pubkey",
        required=True,
        help="public-key filename",
    )

    verify.add_argument(
        "--file",
        required=True,
        help="file to verify",
    )

    verify.add_argument(
        "--sig",
        required=True,
        help="signature filename",
    )

    verify.set_defaults(
        function=command_verify
    )

    return parser


# ============================================================================
# 17. STRUCTURAL TESTS
# ============================================================================

def run_self_tests() -> None:
    print()
    print("=" * 72)
    print("SELF TESTS")
    print("=" * 72)

    # ------------------------------------------------------------------------
    # P-521 group sanity
    # ------------------------------------------------------------------------

    print(
        "[1] Checking G is on P-521..."
    )

    assert is_on_curve(G)

    print(
        "    PASS"
    )

    print(
        "[2] Checking 2G addition == doubling..."
    )

    assert (
        point_add(G, G)
        == point_double(G)
    )

    print(
        "    PASS"
    )

    print(
        "[3] Checking nG == O..."
    )

    assert (
        scalar_mult(
            N,
            G,
        )
        is O
    )

    print(
        "    PASS"
    )

    # ------------------------------------------------------------------------
    # Montgomery ladder regression test
    # ------------------------------------------------------------------------

    print(
        "[4] Comparing Montgomery ladder with old double-and-add..."
    )

    test_scalars = [
        0,
        1,
        2,
        3,
        4,
        5,
        N - 1,
    ]

    test_scalars.extend(
        secrets.randbelow(N)
        for _ in range(500)
    )

    for k in test_scalars:
        old = scalar_mult_double_and_add(
            k,
            G,
        )

        new = scalar_mult_ladder(
            k,
            G,
        )

        assert old == new, (
            "scalar multiplication mismatch"
        )

    print(
        f"    PASS ({len(test_scalars)} comparisons)"
    )

    # ------------------------------------------------------------------------
    # Interactive Schnorr completeness
    # ------------------------------------------------------------------------

    print(
        "[5] Interactive Schnorr completeness..."
    )

    secret = random_scalar()

    public_key = scalar_mult(
        secret,
        G,
    )

    for _ in range(250):
        r = random_scalar()

        T = scalar_mult(
            r,
            G,
        )

        c = secrets.randbelow(N)

        s = (
            r
            + c * secret
        ) % N

        lhs = scalar_mult(
            s,
            G,
        )

        rhs = point_add(
            T,
            scalar_mult(
                c,
                public_key,
            ),
        )

        assert lhs == rhs

    print(
        "    PASS (250/250)"
    )

    # ------------------------------------------------------------------------
    # Knowledge extraction
    # ------------------------------------------------------------------------

    print(
        "[6] Knowledge extraction..."
    )

    r = random_scalar()

    T = scalar_mult(
        r,
        G,
    )

    c1 = secrets.randbelow(N)
    c2 = secrets.randbelow(N)

    while c2 == c1:
        c2 = secrets.randbelow(N)

    s1 = (
        r
        + c1 * secret
    ) % N

    s2 = (
        r
        + c2 * secret
    ) % N

    extracted = (
        (s1 - s2)
        * inv_mod(
            c1 - c2,
            N,
        )
    ) % N

    assert extracted == secret

    print(
        "    PASS"
    )

    # ------------------------------------------------------------------------
    # Deterministic nonce
    # ------------------------------------------------------------------------

    print(
        "[7] Deterministic nonce tests..."
    )

    message_a = (
        b"hello schnorr"
    )

    message_b = (
        b"hello schnorr!"
    )

    hash_a = sha256(
        message_a
    )

    hash_b = sha256(
        message_b
    )

    r_a1 = deterministic_nonce(
        secret,
        hash_a,
    )

    r_a2 = deterministic_nonce(
        secret,
        hash_a,
    )

    r_b = deterministic_nonce(
        secret,
        hash_b,
    )

    assert r_a1 == r_a2
    assert r_a1 != r_b

    print(
        "    PASS"
    )

    # ------------------------------------------------------------------------
    # Signature
    # ------------------------------------------------------------------------

    print(
        "[8] Schnorr signatures..."
    )

    signature = sign_message(
        secret,
        message_a,
    )

    assert verify_signature(
        public_key,
        message_a,
        signature,
    )

    assert not verify_signature(
        public_key,
        message_b,
        signature,
    )

    print(
        "    PASS"
    )

    # ------------------------------------------------------------------------
    # Deterministic signatures
    # ------------------------------------------------------------------------

    print(
        "[9] Deterministic signature equality..."
    )

    sig1 = sign_message(
        secret,
        message_a,
    )

    sig2 = sign_message(
        secret,
        message_a,
    )

    assert (
        serialize_point(sig1.R)
        == serialize_point(sig2.R)
    )

    assert sig1.s == sig2.s

    different_message_sig = sign_message(
        secret,
        message_b,
    )

    assert (
        different_message_sig.R
        != sig1.R
    )

    print(
        "    PASS"
    )

    # ------------------------------------------------------------------------
    # Blind forgery
    # ------------------------------------------------------------------------

    print(
        "[10] Blind forgery experiment..."
    )

    forgery_attempts = 100
    forgery_successes = 0

    for _ in range(
        forgery_attempts
    ):
        # Attacker chooses e and s without knowing x.
        guessed_e = int.from_bytes(
            secrets.token_bytes(32),
            "big",
        ) % N

        guessed_s = random_scalar()

        # Construct R so the group equation would hold for guessed e:
        #
        #     R = sG - eY
        #
        forged_R = point_subtract(
            scalar_mult(
                guessed_s,
                G,
            ),
            scalar_mult(
                guessed_e,
                public_key,
            ),
        )

        if forged_R is O:
            continue

        actual_e = challenge_for_signature(
            forged_R,
            public_key,
            hash_a,
        )

        if actual_e == guessed_e:
            forgery_successes += 1

    assert (
        forgery_successes == 0
    )

    print(
        f"    PASS "
        f"({forgery_successes}/{forgery_attempts} accepted)"
    )

    print()
    print(
        "ALL SELF TESTS PASSED"
    )
    print()


# ============================================================================
# 18. CLI DEMONSTRATION
# ============================================================================
#
# This function is optional. It demonstrates the requested four verification
# cases entirely in memory:
#
#     1. original file + original signature       -> VALID
#     2. tampered file + original signature       -> INVALID
#     3. original file + tampered signature       -> INVALID
#     4. tampered file + forged signature         -> INVALID
#
# It also checks deterministic signing.
#
# ============================================================================

def run_demo() -> None:
    print()
    print("=" * 72)
    print("END-TO-END DEMONSTRATION")
    print("=" * 72)

    secret = random_scalar()

    public_key = scalar_mult(
        secret,
        G,
    )

    original = (
        b"This is the original file.\n"
        b"Only one byte will be changed.\n"
    )

    tampered = (
        b"This is the original file.\n"
        b"Only one byte will be CHANGED.\n"
    )

    # Same file twice.
    sig_original_1 = sign_message(
        secret,
        original,
    )

    sig_original_2 = sign_message(
        secret,
        original,
    )

    encoded_1 = (
        serialize_point(
            sig_original_1.R
        )
        + fixed_width_int(
            sig_original_1.s
        )
    )

    encoded_2 = (
        serialize_point(
            sig_original_2.R
        )
        + fixed_width_int(
            sig_original_2.s
        )
    )

    print(
        "same-file signatures byte-identical:",
        encoded_1 == encoded_2,
    )

    # Different file.
    sig_tampered = sign_message(
        secret,
        tampered,
    )

    print(
        "different-file R values differ:",
        sig_original_1.R != sig_tampered.R,
    )

    # Case 1.
    case_1 = verify_signature(
        public_key,
        original,
        sig_original_1,
    )

    # Case 2.
    case_2 = verify_signature(
        public_key,
        tampered,
        sig_original_1,
    )

    # Case 3: modify s.
    modified_s = (
        sig_original_1.s + 1
    ) % N

    tampered_signature = SchnorrSignature(
        R=sig_original_1.R,
        s=modified_s,
    )

    case_3 = verify_signature(
        public_key,
        original,
        tampered_signature,
    )

    # Case 4: attacker tries blind construction against tampered message.
    tampered_hash = sha256(
        tampered
    )

    guessed_e = (
        int.from_bytes(
            secrets.token_bytes(32),
            "big",
        )
        % N
    )

    guessed_s = random_scalar()

    forged_R = point_subtract(
        scalar_mult(
            guessed_s,
            G,
        ),
        scalar_mult(
            guessed_e,
            public_key,
        ),
    )

    if forged_R is O:
        case_4 = False
    else:
        forged_signature = SchnorrSignature(
            R=forged_R,
            s=guessed_s,
        )

        case_4 = verify_signature(
            public_key,
            tampered,
            forged_signature,
        )

    print()
    print(
        "case 1: original file + original signature:",
        "VALID" if case_1 else "INVALID",
    )

    print(
        "case 2: tampered file + original signature:",
        "VALID" if case_2 else "INVALID",
    )

    print(
        "case 3: original file + tampered signature:",
        "VALID" if case_3 else "INVALID",
    )

    print(
        "case 4: tampered file + blind forged signature:",
        "VALID" if case_4 else "INVALID",
    )

    assert case_1
    assert not case_2
    assert not case_3
    assert not case_4

    print()
    print(
        "END-TO-END DEMONSTRATION PASSED"
    )


# ============================================================================
# 19. MAIN
# ============================================================================

def main() -> int:
    parser = build_argument_parser()

    args = parser.parse_args()

    return args.function(
        args
    )


if __name__ == "__main__":
    # Run:
    #
    #     python schnorr_p521.py --help
    #
    # For the complete internal test suite, execute:
    #
    #     python schnorr_p521.py --self-test
    #
    # For the CLI itself:
    #
    #     python schnorr_p521.py keygen --out mykey
    #     python schnorr_p521.py sign --key mykey --file document.bin
    #     python schnorr_p521.py verify \
    #         --pubkey mykey.pub \
    #         --file document.bin \
    #         --sig document.bin.sig
    #
    # The special self-test/demo options are handled below.

    if (
        len(sys.argv) == 2
        and sys.argv[1] == "--self-test"
    ):
        run_self_tests()
        run_demo()
        sys.exit(0)

    sys.exit(
        main()
    )