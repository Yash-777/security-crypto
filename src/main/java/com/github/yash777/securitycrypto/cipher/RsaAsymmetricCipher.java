package com.github.yash777.securitycrypto.cipher;

import com.github.yash777.securitycrypto.exception.CryptoOperationException;
import com.github.yash777.securitycrypto.exception.InvalidCiphertextException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * RSA asymmetric encryption and decryption using the JCE framework.
 *
 * <p>Uses {@code RSA/ECB/OAEPWithSHA-256AndMGF1Padding} — the modern,
 * recommended RSA padding scheme. OAEP (Optimal Asymmetric Encryption Padding)
 * is probabilistic and secure against chosen-ciphertext attacks.
 *
 * <h2>Limitations</h2>
 * <p>RSA can only encrypt data smaller than the key modulus minus padding overhead.
 * For a 2048-bit key with OAEP-SHA-256 the usable plaintext limit is approximately
 * 190 bytes. For larger payloads, use the <em>hybrid</em> pattern:
 * <ol>
 *   <li>Generate a random AES key</li>
 *   <li>Encrypt the plaintext with AES-GCM</li>
 *   <li>Encrypt the AES key with RSA (this class)</li>
 *   <li>Transmit both the RSA-encrypted key and the AES ciphertext</li>
 * </ol>
 *
 * <h2>Usage example</h2>
 * <pre>{@code
 * KeyPair rsa = KeyManager.generateRsaKeyPair(2048);
 * RsaCipher rsaCipher = new RsaCipher();
 *
 * // Encrypt with public key (sender side)
 * String encrypted = rsaCipher.encrypt("secret", rsa.getPublic());
 *
 * // Decrypt with private key (receiver side)
 * String plain = rsaCipher.decrypt(encrypted, rsa.getPrivate());
 * }</pre>
 *
 * @author Yash
 * @version 1.0.0
 * @see <a href="http://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html">javax.crypto.Cipher</a>
 */
public class RsaAsymmetricCipher {

    private static final Logger log = LoggerFactory.getLogger(RsaAsymmetricCipher.class);

    /**
     * RSA transformation with OAEP padding (SHA-256 hash, MGF1 mask generation function).
     * Preferred over the legacy {@code RSA/ECB/PKCS1Padding}.
     */
    private static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    // -----------------------------------------------------------------------
    // Encrypt
    // -----------------------------------------------------------------------

    /**
     * Encrypts a plaintext string using the given RSA public key.
     *
     * <p>The plaintext is encoded as UTF-8 before encryption. The result is
     * Base64-encoded and safe to store or transmit.
     *
     * @param plaintext the string to encrypt (must be ≤ ~190 bytes for RSA-2048 + OAEP-SHA256)
     * @param publicKey the recipient's RSA public key
     * @return Base64-encoded RSA ciphertext
     * @throws CryptoOperationException if the cipher cannot be initialised or the plaintext
     *         exceeds the RSA block size limit
     */
    public String encrypt(String plaintext, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(UTF_8));
            String result    = Base64.getEncoder().encodeToString(encrypted);
            log.debug("RSA-encrypted {} chars → {} Base64 chars", plaintext.length(), result.length());
            return result;
        } catch (Exception e) {
            throw new CryptoOperationException(
                    "RSA encrypt failed: " + e.getMessage(), e);
        }
    }

    /**
     * Encrypts raw bytes using the given RSA public key.
     *
     * <p>Useful for encrypting AES session keys in the hybrid encryption pattern.
     *
     * @param data      raw bytes to encrypt (e.g. {@code secretKey.getEncoded()})
     * @param publicKey the recipient's RSA public key
     * @return Base64-encoded RSA ciphertext
     * @throws CryptoOperationException if the cipher cannot be initialised
     */
    public String encryptBytes(byte[] data, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encrypted = cipher.doFinal(data);
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new CryptoOperationException(
                    "RSA encrypt (bytes) failed: " + e.getMessage(), e);
        }
    }

    // -----------------------------------------------------------------------
    // Decrypt
    // -----------------------------------------------------------------------

    /**
     * Decrypts a Base64-encoded RSA ciphertext using the given private key.
     *
     * @param encryptedBase64 ciphertext produced by {@link #encrypt(String, PublicKey)}
     * @param privateKey      the RSA private key corresponding to the public key used for encryption
     * @return the decrypted plaintext string
     * @throws InvalidCiphertextException if the payload is not valid Base64, is malformed,
     *         or was encrypted with a different key
     * @throws CryptoOperationException   if the cipher cannot be initialised
     */
    public String decrypt(String encryptedBase64, PrivateKey privateKey)
            throws InvalidCiphertextException {

        byte[] payload;
        try {
            payload = Base64.getDecoder().decode(encryptedBase64);
        } catch (IllegalArgumentException e) {
            throw new InvalidCiphertextException("RSA payload is not valid Base64", e);
        }

        try {
            Cipher cipher  = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] plain   = cipher.doFinal(payload);
            String result  = new String(plain, UTF_8);
            log.debug("RSA-decrypted {} Base64 chars → {} chars", encryptedBase64.length(), result.length());
            return result;
        } catch (Exception e) {
            throw new InvalidCiphertextException(
                    "RSA decrypt failed — wrong key or corrupted ciphertext: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypts a Base64-encoded RSA ciphertext to raw bytes.
     *
     * <p>Used in the hybrid pattern to recover an encrypted AES session key.
     *
     * @param encryptedBase64 ciphertext produced by {@link #encryptBytes(byte[], PublicKey)}
     * @param privateKey      the RSA private key
     * @return the decrypted raw bytes
     * @throws InvalidCiphertextException if decryption fails
     */
    public byte[] decryptBytes(String encryptedBase64, PrivateKey privateKey)
            throws InvalidCiphertextException {

        byte[] payload;
        try {
            payload = Base64.getDecoder().decode(encryptedBase64);
        } catch (IllegalArgumentException e) {
            throw new InvalidCiphertextException("RSA payload is not valid Base64", e);
        }
        try {
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(payload);
        } catch (Exception e) {
            throw new InvalidCiphertextException(
                    "RSA decrypt (bytes) failed: " + e.getMessage(), e);
        }
    }
}