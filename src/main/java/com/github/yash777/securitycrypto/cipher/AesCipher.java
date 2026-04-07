package com.github.yash777.securitycrypto.cipher;

import com.github.yash777.securitycrypto.exception.CryptoOperationException;
import com.github.yash777.securitycrypto.exception.InvalidCiphertextException;
import com.github.yash777.securitycrypto.util.IvUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * AES encryption and decryption using the Java Cryptographic Extension (JCE) framework.
 *
 * <p>Supports three {@link CipherMode cipher modes}:
 * <ul>
 *   <li><strong>ECB</strong> — no IV; avoid for non-trivial data</li>
 *   <li><strong>CBC</strong> — requires a random 16-byte IV; provides confidentiality</li>
 *   <li><strong>GCM</strong> — requires a unique 12-byte nonce; provides confidentiality
 *       <em>and</em> integrity (authenticated encryption)</li>
 * </ul>
 *
 * <h2>Output format</h2>
 * When an IV is used (CBC or GCM), the IV is prepended to the ciphertext
 * before Base64 encoding:
 * <pre>
 *   Base64( IV_bytes || ciphertext_bytes )
 * </pre>
 * This means the receiver does not need to transmit the IV separately —
 * it is always recovered during {@link #decrypt(String, SecretKey, CipherMode)}.
 *
 * <h2>GCM authentication tag</h2>
 * GCM appends a 128-bit (16-byte) authentication tag to the ciphertext.
 * The JCE handles tag computation and verification transparently inside
 * {@code Cipher.doFinal()}. Any modification to the ciphertext or the tag
 * causes {@link AEADBadTagException} to be wrapped and re-thrown as
 * {@link InvalidCiphertextException}.
 *
 * <h2>Usage example</h2>
 * <pre>{@code
 * SecretKey key  = KeyManager.generateAesKey(KeySize.AES_256);
 * AesCipher aes  = new AesCipher();
 *
 * // Encrypt (IV auto-generated and prepended)
 * String cipherText = aes.encrypt("Hello, World!", key, CipherMode.GCM);
 *
 * // Decrypt (IV extracted from the first bytes of the payload)
 * String plainText  = aes.decrypt(cipherText, key, CipherMode.GCM);
 * }</pre>
 *
 * @author Yash
 * @version 1.0.0
 * @see <a href="http://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html">javax.crypto.Cipher</a>
 * @see <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#cipher-algorithm-names">
 *      Cipher Algorithm Standard Names</a>
 */
public class AesCipher {

    private static final Logger log = LoggerFactory.getLogger(AesCipher.class);

    /** GCM authentication tag length in bits (128 = maximum, recommended by NIST). */
    private static final int GCM_TAG_LENGTH_BITS = 128;

    // -----------------------------------------------------------------------
    // Encrypt
    // -----------------------------------------------------------------------

    /**
     * Encrypts {@code plaintext} with the given AES {@code key} and {@code mode},
     * auto-generating a secure random IV for CBC and GCM modes.
     *
     * <p>The returned string is safe to store or transmit. It encodes
     * {@code IV || ciphertext} (or just {@code ciphertext} for ECB) as Base64.
     *
     * @param plaintext the UTF-8 string to encrypt
     * @param key       AES secret key (128, 192, or 256-bit)
     * @param mode      cipher mode ({@link CipherMode#ECB}, {@link CipherMode#CBC},
     *                  or {@link CipherMode#GCM})
     * @return Base64-encoded encrypted payload
     * @throws CryptoOperationException if the cipher cannot be initialised
     *         (wraps {@link NoSuchAlgorithmException}, {@link InvalidKeyException}, etc.)
     */
    public String encrypt(String plaintext, SecretKey key, CipherMode mode) {
        IvParameterSpec iv = mode.requiresIv
                ? (mode == CipherMode.GCM ? IvUtils.generateRandomGcm() : IvUtils.generateRandom())
                : null;
        return encrypt(plaintext, key, mode, iv);
    }

    /**
     * Encrypts {@code plaintext} using an explicitly supplied IV.
     *
     * <p>Use this overload when the IV must be derived from a known value
     * (e.g. a protocol-defined nonce or a date) or when testing with a fixed IV.
     * For production encryption prefer {@link #encrypt(String, SecretKey, CipherMode)}.
     *
     * @param plaintext the UTF-8 string to encrypt
     * @param key       AES secret key
     * @param mode      cipher mode
     * @param ivSpec    IV/nonce to use; ignored (may be {@code null}) for ECB
     * @return Base64-encoded encrypted payload (IV prepended if applicable)
     * @throws CryptoOperationException if the cipher cannot be initialised
     */
    public String encrypt(String plaintext, SecretKey key, CipherMode mode, IvParameterSpec ivSpec) {
        try {
            Cipher cipher = buildCipher(mode, Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] cipherBytes = cipher.doFinal(plaintext.getBytes(UTF_8));

            // Prepend IV so decrypt() can recover it without out-of-band communication
            byte[] payload = (ivSpec != null)
                    ? combine(ivSpec.getIV(), cipherBytes)
                    : cipherBytes;

            String encoded = Base64.getEncoder().encodeToString(payload);
            log.debug("Encrypted {} chars → {} Base64 chars [mode={}]",
                    plaintext.length(), encoded.length(), mode.name());
            return encoded;

        } catch (Exception e) {
            throw new CryptoOperationException(
                    "AES encrypt failed [mode=" + mode.name() + "]: " + e.getMessage(), e);
        }
    }

    // -----------------------------------------------------------------------
    // Decrypt
    // -----------------------------------------------------------------------

    /**
     * Decrypts a Base64-encoded payload previously produced by
     * {@link #encrypt(String, SecretKey, CipherMode)}.
     *
     * <p>The IV is extracted from the first bytes of the decoded payload
     * (16 bytes for CBC, 12 bytes for GCM). ECB decryption uses no IV.
     *
     * @param encryptedBase64 the Base64-encoded payload returned by {@code encrypt()}
     * @param key             the same AES key used for encryption
     * @param mode            the same cipher mode used for encryption
     * @return the decrypted plaintext string
     * @throws InvalidCiphertextException if the payload is malformed, truncated, or tampered
     *         (GCM tag mismatch, bad padding, etc.)
     * @throws CryptoOperationException   if the cipher cannot be initialised
     */
    public String decrypt(String encryptedBase64, SecretKey key, CipherMode mode)
            throws InvalidCiphertextException {

        byte[] payload;
        try {
            payload = Base64.getDecoder().decode(encryptedBase64);
        } catch (IllegalArgumentException e) {
            throw new InvalidCiphertextException(
                    "Payload is not valid Base64: " + e.getMessage(), e);
        }

        // Extract IV from the front of the payload (not present for ECB)
        IvParameterSpec ivSpec = null;
        byte[] cipherBytes     = payload;

        if (mode.requiresIv) {
            int ivLen = (mode == CipherMode.GCM) ? IvUtils.IV_LENGTH_GCM : IvUtils.IV_LENGTH_CBC;
            if (payload.length <= ivLen) {
                throw new InvalidCiphertextException(
                        "Payload too short to contain IV — expected >" + ivLen
                        + " bytes but got " + payload.length);
            }
            ivSpec     = IvUtils.fromBytes(Arrays.copyOfRange(payload, 0, ivLen));
            cipherBytes = Arrays.copyOfRange(payload, ivLen, payload.length);
        }

        try {
            Cipher cipher  = buildCipher(mode, Cipher.DECRYPT_MODE, key, ivSpec);
            byte[] plain   = cipher.doFinal(cipherBytes);
            String result  = new String(plain, UTF_8);
            log.debug("Decrypted {} Base64 chars → {} chars [mode={}]",
                    encryptedBase64.length(), result.length(), mode.name());
            return result;

        } catch (AEADBadTagException e) {
            throw new InvalidCiphertextException(
                    "GCM authentication tag mismatch — data may have been tampered with", e);
        } catch (Exception e) {
            // Covers BadPaddingException, IllegalBlockSizeException, etc.
            throw new InvalidCiphertextException(
                    "Decryption failed [mode=" + mode.name() + "]: " + e.getMessage(), e);
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /**
     * Constructs and initialises a {@link Cipher} for the given mode and direction.
     *
     * @param mode      cipher mode
     * @param opMode    {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE}
     * @param key       AES secret key
     * @param ivSpec    IV; may be {@code null} for ECB
     * @return initialised {@link Cipher}
     * @throws Exception propagated JCE exceptions (caller wraps into library exceptions)
     */
    private Cipher buildCipher(CipherMode mode, int opMode, SecretKey key, IvParameterSpec ivSpec)
            throws Exception {

        Cipher cipher;
        try {
            cipher = Cipher.getInstance(mode.transformation);
        } catch (NoSuchAlgorithmException | javax.crypto.NoSuchPaddingException e) {
            throw new CryptoOperationException(
                    "Cipher transformation not available: " + mode.transformation, e);
        }

        try {
            switch (mode) {
                case GCM:
                    if (ivSpec == null) {
                        throw new CryptoOperationException("GCM mode requires a non-null IV/nonce");
                    }
                    GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, ivSpec.getIV());
                    cipher.init(opMode, key, gcmSpec);
                    break;

                case CBC:
                    if (ivSpec == null) {
                        throw new CryptoOperationException("CBC mode requires a non-null IV");
                    }
                    cipher.init(opMode, key, ivSpec);
                    break;

                case ECB:
                default:
                    cipher.init(opMode, key);
                    break;
            }
        } catch (InvalidKeyException e) {
            throw new CryptoOperationException(
                    "Invalid key for " + mode.transformation + ": " + e.getMessage(), e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new CryptoOperationException(
                    "Invalid algorithm parameter for " + mode.transformation + ": " + e.getMessage(), e);
        }

        return cipher;
    }

    /**
     * Concatenates two byte arrays: {@code prefix || data}.
     *
     * @param prefix first array (IV bytes)
     * @param data   second array (ciphertext bytes)
     * @return new array containing all bytes of {@code prefix} followed by all bytes of {@code data}
     */
    private static byte[] combine(byte[] prefix, byte[] data) {
        byte[] combined = new byte[prefix.length + data.length];
        System.arraycopy(prefix, 0, combined, 0, prefix.length);
        System.arraycopy(data,   0, combined, prefix.length, data.length);
        return combined;
    }
}
