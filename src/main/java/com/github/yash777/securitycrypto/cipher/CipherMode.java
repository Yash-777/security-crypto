package com.github.yash777.securitycrypto.cipher;

/**
 * AES cipher modes supported by this library, expressed as JCE
 * transformation strings ({@code Algorithm/Mode/Padding}).
 *
 * <p>Refer to the Oracle standard names specification for the complete list:
 * <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#cipher-algorithm-names">
 * Cipher Algorithm Standard Names</a>
 *
 * <table border="1" cellpadding="4">
 *   <tr><th>Mode</th><th>IV required</th><th>Authenticated</th><th>Padding</th></tr>
 *   <tr><td>ECB</td><td>No</td><td>No</td><td>PKCS5</td></tr>
 *   <tr><td>CBC</td><td>Yes (16 bytes)</td><td>No</td><td>PKCS5</td></tr>
 *   <tr><td>GCM</td><td>Yes (12 bytes recommended)</td><td>Yes (128-bit tag)</td><td>None</td></tr>
 * </table>
 *
 * <p><strong>Recommendation:</strong> Prefer {@link #GCM} for all new code.
 * ECB must not be used for any data with repeated patterns.
 *
 * @author Yash
 * @version 1.0.0
 * @see <a href="http://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html">javax.crypto.Cipher</a>
 */
public enum CipherMode {

    /**
     * Electronic Codebook mode — {@code AES/ECB/PKCS5Padding}.
     * <p><strong>Warning:</strong> ECB encrypts each 16-byte block independently.
     * Identical plaintext blocks produce identical ciphertext blocks, leaking
     * structural information. Only use ECB for single-block payloads or legacy
     * interoperability, never for arbitrary data.
     */
    ECB("AES/ECB/PKCS5Padding", false, false),

    /**
     * Cipher Block Chaining mode — {@code AES/CBC/PKCS5Padding}.
     * <p>Each block is XOR-ed with the previous ciphertext block before encryption,
     * so an IV is required. The IV must be unpredictable (use
     * {@link com.github.yash777.securitycrypto.util.IvUtils#generateRandom()}).
     * Provides confidentiality but not authenticity — combine with HMAC if
     * tamper detection is required.
     */
    CBC("AES/CBC/PKCS5Padding", true, false),

    /**
     * Galois/Counter Mode — {@code AES/GCM/NoPadding}.
     * <p>Authenticated Encryption with Associated Data (AEAD). Produces a
     * 128-bit authentication tag that guarantees both confidentiality and
     * integrity. Any bit-level tampering of the ciphertext causes decryption
     * to throw {@link javax.crypto.AEADBadTagException}.
     * <p>Use a unique 12-byte nonce per encryption operation. Never reuse a
     * (key, nonce) pair.
     */
    GCM("AES/GCM/NoPadding", true, true);

    /** JCE transformation string passed to {@link javax.crypto.Cipher#getInstance(String)}. */
    public final String transformation;

    /** Whether this mode requires an initialisation vector (IV / nonce). */
    public final boolean requiresIv;

    /** Whether this mode provides authenticated encryption (integrity + confidentiality). */
    public final boolean authenticated;

    CipherMode(String transformation, boolean requiresIv, boolean authenticated) {
        this.transformation = transformation;
        this.requiresIv     = requiresIv;
        this.authenticated  = authenticated;
    }
}
