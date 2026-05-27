namespace PixSmith.Authorization.Services.Cryptography;

/// <summary>
/// Cryptographic signing algorithm families, ordered by era.
///
/// Current deployment: RSA4096 — classical-maximum security (~140-bit), unbreakable
/// with any hardware that exists today. Shor's algorithm on a fault-tolerant quantum
/// computer (Q*) reduces this to ~0 bits. Until Q* exists, RSA4096 is the ceiling.
///
/// Post-quantum path (activate when IETF draft-ietf-jose-pqc is finalized):
///   ML-DSA  — NIST FIPS 204 (CRYSTALS-Dilithium), lattice-based
///   SLH-DSA — NIST FIPS 205 (SPHINCS+), stateless hash-based
/// Both are secure against both classical and quantum adversaries.
/// </summary>
public enum SigningAlgorithm
{
    // ── Classical maximum ────────────────────────────────────────────────────
    RSA4096,

    // ── NIST FIPS 204 — ML-DSA (CRYSTALS-Dilithium) ─────────────────────────
    MLDSA_65,       // Category 3 — ~128-bit quantum security
    MLDSA_87,       // Category 5 — ~192-bit quantum security

    // ── NIST FIPS 205 — SLH-DSA (SPHINCS+) — most conservative PQC argument ─
    SLHDSA_SHA2_128S,
    SLHDSA_SHA2_256S,
}
