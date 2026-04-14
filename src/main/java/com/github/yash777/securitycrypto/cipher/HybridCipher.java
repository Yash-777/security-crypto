package com.github.yash777.securitycrypto.cipher;

import com.github.yash777.securitycrypto.exception.CryptoOperationException;
import com.github.yash777.securitycrypto.exception.InvalidCiphertextException;
import com.github.yash777.securitycrypto.key.KeyManager;
import com.github.yash777.securitycrypto.key.KeySize;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Hybrid encryption combining RSA asymmetric key wrapping with AES-GCM
 * authenticated symmetric encryption.
 *
 * <h2>Why hybrid?</h2>
 * <p>RSA can only encrypt small payloads (≈190 bytes for RSA-2048 + OAEP-SHA-256).
 * Hybrid encryption solves this:
 * <ol>
 *   <li>A random 256-bit AES session key is generated per message.</li>
 *   <li>The plaintext is encrypted with AES-GCM (fast, authenticated).</li>
 *   <li>The session key is encrypted with RSA (only ~32 bytes).</li>
 *   <li>Both the RSA-wrapped key and the AES ciphertext are transmitted together.</li>
 * </ol>
 *
 * <h2>Wire format — {@link HybridPayload}</h2>
 * <pre>
 *   wrappedKey    — Base64( RSA_OAEP( aesKey.getEncoded() ) )
 *   ciphertext    — Base64( IV_GCM || AES_GCM( plaintext ) )
 * </pre>
 *
 * <h2>Usage example</h2>
 * <pre>{@code
 * KeyPair rsa          = KeyManager.generateRsaKeyPair(2048);
 * HybridCipher hybrid  = new HybridCipher();
 *
 * // Sender
 * HybridPayload payload = hybrid.encrypt("Large payload...", rsa.getPublic());
 *
 * // Receiver
 * String plaintext = hybrid.decrypt(payload, rsa.getPrivate());
 * }</pre>
 *
 * @author Yash
 * @version 1.0.0
 */
public class HybridCipher {

    private static final Logger log = LoggerFactory.getLogger(HybridCipher.class);
    private static final String AES_ALGORITHM = "AES";

    private final AesSymmetricCipher  aesSymmetricCipher  = new AesSymmetricCipher();
    private final RsaAsymmetricCipher rsaAsymmetricCipher = new RsaAsymmetricCipher();

    // -----------------------------------------------------------------------
    // Encrypt
    // -----------------------------------------------------------------------

    /**
     * Encrypts arbitrary-length plaintext using hybrid RSA + AES-GCM encryption.
     *
     * @param plaintext any UTF-8 string of any length
     * @param publicKey the recipient's RSA public key (2048-bit minimum)
     * @return a {@link HybridPayload} containing the RSA-wrapped AES key and the AES ciphertext
     * @throws CryptoOperationException if key generation or cipher initialisation fails
     */
    public HybridPayload encrypt(String plaintext, PublicKey publicKey) {
        // 1. Generate a fresh 256-bit AES session key
        SecretKey sessionKey = KeyManager.generateAesKey(KeySize.AES_256);

        // 2. Encrypt plaintext with AES-GCM (IV auto-generated and prepended)
        String ciphertext = aesSymmetricCipher.encrypt(plaintext, sessionKey, CipherMode.GCM);

        // 3. Wrap the session key with RSA OAEP
        String wrappedKey = rsaAsymmetricCipher.encryptBytes(sessionKey.getEncoded(), publicKey);

        log.info("Hybrid encrypt complete — wrappedKey={} chars, ciphertext={} chars",
                wrappedKey.length(), ciphertext.length());
        return new HybridPayload(wrappedKey, ciphertext);
    }

    // -----------------------------------------------------------------------
    // Decrypt
    // -----------------------------------------------------------------------

    /**
     * Decrypts a {@link HybridPayload} using the recipient's RSA private key.
     *
     * @param payload    the payload returned by {@link #encrypt(String, PublicKey)}
     * @param privateKey the RSA private key matching the public key used to encrypt
     * @return the original plaintext string
     * @throws InvalidCiphertextException if the RSA-wrapped key or AES ciphertext is malformed
     * @throws CryptoOperationException   if cipher initialisation fails
     */
    public String decrypt(HybridPayload payload, PrivateKey privateKey)
            throws InvalidCiphertextException {

        // 1. Unwrap the AES session key with RSA
        byte[] keyBytes  = rsaAsymmetricCipher.decryptBytes(payload.wrappedKey(), privateKey);
        SecretKey sessionKey = new SecretKeySpec(keyBytes, AES_ALGORITHM);

        // 2. Decrypt the AES-GCM ciphertext
        String plaintext = aesSymmetricCipher.decrypt(payload.ciphertext(), sessionKey, CipherMode.GCM);

        log.info("Hybrid decrypt complete — recovered {} chars", plaintext.length());
        return plaintext;
    }

    // -----------------------------------------------------------------------
    // Payload record
    // -----------------------------------------------------------------------

    /**
     * Immutable container for the two components of a hybrid-encrypted message.
     *
     * <p>Both fields are Base64 strings suitable for JSON serialisation or
     * any text-safe transport.
     */
    public static final class HybridPayload {

        private final String wrappedKey;
        private final String ciphertext;

        /**
         * Constructs a new payload.
         *
         * @param wrappedKey Base64-encoded RSA-OAEP-encrypted AES session key
         * @param ciphertext Base64-encoded AES-GCM ciphertext (IV prepended)
         */
        public HybridPayload(String wrappedKey, String ciphertext) {
            this.wrappedKey = wrappedKey;
            this.ciphertext = ciphertext;
        }

        /**
         * Returns the Base64-encoded RSA-wrapped AES session key.
         *
         * @return RSA-encrypted session key
         */
        public String wrappedKey() { return wrappedKey; }

        /**
         * Returns the Base64-encoded AES-GCM ciphertext (with IV prepended).
         *
         * @return AES-GCM ciphertext
         */
        public String ciphertext() { return ciphertext; }

        @Override
        public String toString() {
            return "HybridPayload{wrappedKey=" + wrappedKey.length()
                    + " chars, ciphertext=" + ciphertext.length() + " chars}";
        }
    }
}
