# Schnorr-P-521
Educational Schnorr signature tool over NIST P-521, implemented from scratch in Python. Supports key generation, file signing, and signature verification. Uses only Python standard library (hashlib, hmac, secrets). Not for production use. Made By ChatGPT and prompt by Claude


The original secret-dependent if k & 1: scalar multiplication is now replaced by a 521-bit Montgomery ladder. Every nonzero scalar executes exactly 521 ladder iterations, with one Jacobian addition and one Jacobian doubling per bit, while scalar-bit selection uses an arithmetic-masked cswap() rather than a branch. The old double-and-add implementation remains in the file only as a regression oracle. NIST SP 800-186 specifies P-521 as a prime-field Weierstrass curve with cofactor 1 and prime subgroup order \(n\). 

The qualification is important: this is structurally constant-time, not truly constant-time in Python. Python's arbitrary-precision integers, allocator, garbage collector, interpreter, and runtime implementation can still introduce timing variation. A production implementation would need machine-code-level constant-time arithmetic, fixed memory-access behavior, and additional side-channel defenses.

The deterministic nonce generator is an RFC-6979-style HMAC-SHA256 V/K generator, adapted for Schnorr rather than trying to be bit-for-bit RFC 6979. RFC 6979 defines the underlying HMAC-based deterministic construction and explicitly uses the private key plus the message hash as input. 

I used 66-byte output candidates, masked to 521 bits, followed by rejection for values outside [1,n). That avoids artificially restricting the nonce to only 256 bits.

One mathematical nuance is worth correcting from the requested wording: different messages do not produce different HMAC outputs with mathematical certainty—cryptographic hash/HMAC collisions are theoretically possible. What the construction gives is that, without knowing \(x\), producing a useful nonce collision for two distinct messages is computationally infeasible under the security assumptions. The self-test observed distinct \(r\)/\(R\) values for distinct messages.

Signature construction

The tool now implements

\[
r = \operatorname{DetNonce}(x,H(m))
\]

\[
R=rG
\]

\[
e=\operatorname{SHA256}(\operatorname{enc}(R)\Vert
\operatorname{enc}(Y)\Vert H(m))\bmod n
\]

\[
s=(r+ex)\bmod n.
\]

Verification checks

\[
sG=R+eY.
\]

Thus the old Fiat-Shamir proof of “I know the discrete logarithm of \(Y\)” becomes a message-bound signature: the hash challenge commits the proof to the specific file digest. This key/message-prefixing pattern is also found in deployed Schnorr designs such as BIP-340, although BIP-340 uses secp256k1 and a different encoding/signature format. 

The implementation intentionally uses (R,s) rather than (e,s). An (e,s) representation is possible because a verifier can reconstruct \(R=sG-eY\), but (R,s) makes the signature transcript explicit.

Exact file formats

.priv

132 uppercase hexadecimal characters + newline

representing the 66-byte big-endian private scalar.

.pub

266 uppercase hexadecimal characters + newline

representing exactly:

04 || x(66 bytes) || y(66 bytes)

.sig

SCHNORR-P521-SIG-V1
R=<266 uppercase hex characters>
s=<132 uppercase hex characters>

The private key is deliberately plaintext for this exercise; the file is created with mode 0600 where the platform permits it.

CLI

python schnorr_p521.py keygen --out mykey

python schnorr_p521.py sign \
    --key mykey \
    --file document.bin

python schnorr_p521.py verify \
    --pubkey mykey.pub \
    --file document.bin \
    --sig document.bin.sig

Verification prints either:

VALID

and exits 0, or:

INVALID

and exits nonzero, so it can be used directly in shell pipelines.

Tests actually executed

The regression suite first compared the new ladder against the old double-and-add implementation for the required structured scalars 1, 2, and n-1, plus 500 independent random scalars:

SELFTEST: parameter and group-law checks
  n*G == O: PASS
  2G(add) == 2G(double): PASS
SELFTEST: 500-random-scalar ladder-vs-old-double-and-add
  503/503 scalar comparisons: PASS

The retained original protocol also passed:

SELFTEST: interactive completeness: 250/250 PASS
SELFTEST: knowledge extraction: PASS

Deterministic nonce and signature checks:

SELFTEST: deterministic nonce repeatability/different-message separation: PASS
SELFTEST: Schnorr signing/verification: PASS
SELFTEST: blind signature forgery: INVALID as expected
SELFTEST: all protocol tests PASS

The actual command-line workflow was then exercised end-to-end.

KEYPAIR_CREATED demo.priv demo.pub
SIGNED message.txt -> message.txt.sig
SIGNED message.txt -> message.txt.sig
SIGNED different.txt -> different.txt.sig

same_file_signatures_byte_identical=YES
different_message_R_values_differ=YES

The four requested verification cases all behaved correctly:

case_1_valid_original= VALID
case_2_tampered_file_original_sig= INVALID
case_3_original_file_tampered_sig= INVALID
case_4_tampered_file_attacker_forged_sig= INVALID

The test also confirmed the private-key file permissions:

private_key_permissions=600

The fourth case used the classic blind-forgery construction: an attacker chooses a guessed challenge \(e\) and \(s\), constructs \(R=sG-eY\), then hopes the real hash challenge happens to equal the guess. Without the private key, the resulting signature was rejected.

Why deterministic nonces close the old failure mode

The previous implementation depended on an operational rule:

"remember to generate a fresh random r every time"

The new signer instead makes:

\[
r=\operatorname{HMAC\_DRBG}(x,H(m)).
\]

For the same key and exact same message, the signature is consequently identical. That is intentional and safe for this Schnorr construction: signing the identical message again does not create a second independent nonce transcript.

For a different message, the deterministic generator receives different input. An attacker who does not know \(x\) cannot predict the resulting nonce or deliberately arrange the same nonce except through breaking the underlying cryptographic assumptions. This is substantially stronger than merely trusting every caller to remember not to reuse secrets.randbelow() output.

Final scope

This is now real enough to use and learn from, not real enough to protect anything you actually care about losing.

It is suitable for personal/experimental use such as signing your own files and detecting accidental or malicious modification. It should not be substituted for a security-reviewed signing implementation for Git commit signing, software distribution, authentication tokens, or other high-value applications.

Remaining gaps include:

No hardware-backed key storage. Theft of .priv is total key compromise; there is no HSM/TPM/secure-enclave integration.

No encryption at rest. The private scalar is deliberately stored as plaintext hex, albeit with restrictive file permissions.

Python-level constant-time only. The Montgomery ladder removes the obvious secret-bit branch and makes the scalar-multiplication schedule fixed, but Python cannot provide a machine-code-level constant-time guarantee.

No formal interoperability profile. This is deliberately its own P-521 format rather than BIP-340; BIP-340's deployed Schnorr scheme uses secp256k1 and a different encoding and hashing specification. 

No independent security audit or formal proof of this exact construction.

No production-grade key lifecycle, backup, revocation, rotation, or trust-management system.


The code therefore closes the two specific implementation failures from the original exercise—secret-dependent scalar-bit branching and accidental nonce reuse—while keeping the limitations visible rather than presenting Python educational cryptography as production-hardened cryptography.
