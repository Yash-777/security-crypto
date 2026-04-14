package com.github.yash777.securitycrypto.cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Base64;

/**
 * AES/CBC encryption and decryption with a <strong>fixed, pre-shared key and IV</strong>.
 *
 * <p>Use this class when both parties have agreed on a fixed {@code AES-key} and {@code IV}
 * out-of-band (e.g. both sides read them from the same config file). The key and IV are
 * supplied at construction time so a single instance handles all operations.
 *
 * <p><strong>Security note:</strong> Reusing a fixed IV with the same key across
 * different plaintexts weakens confidentiality. This pattern is appropriate for
 * internal service-to-service communication with a shared secret, not for user data
 * encryption where each record should have a unique IV.
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * AesCbcFixedKeyCipher cipher = new AesCbcFixedKeyCipher(
 *         "aVhYZ2ZsbFdENmh6VlNFQ3BmUHhXZz09",     // 32-char AES key
 *         "E1SPRygLKfztpjec");                    // 16-char IV
 *
 * String encrypted = cipher.encryptRawString("grant_type=client_credentials");
 * String decrypted = cipher.decryptRawString(encrypted);
 * }</pre>
 *
 * @author  Yashwanth
 * @version 1.0.1
 * @see     <a href="http://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html">javax.crypto.Cipher</a>
 */
public class AesCbcFixedKeyCipher {

    private final Logger log = LoggerFactory.getLogger(AesCbcFixedKeyCipher.class);

    private static final String TRANSFORMATION = "AES/CBC/PKCS5PADDING";
    private static final String ALGORITHM      = "AES";

    private final String aesKey;
    private final String ivKey;

    /**
     * Constructs an {@code AesCbcFixedKeyCipher} with the given key and IV strings.
     *
     * @param aesKey 16, 24, or 32-character AES key string (bytes used directly)
     * @param ivKey  exactly 16-character IV string (one AES block)
     * @throws IllegalArgumentException if either argument is null or empty
     */
    public AesCbcFixedKeyCipher(String aesKey, String ivKey) {
        if (aesKey == null || aesKey.isEmpty()) {
            throw new IllegalArgumentException("AES key must not be null or empty");
        }
        if (ivKey == null || ivKey.isEmpty()) {
            throw new IllegalArgumentException("IV key must not be null or empty");
        }
        this.aesKey = aesKey;
        this.ivKey  = ivKey;
    }

    // -----------------------------------------------------------------------
    // Decrypt
    // -----------------------------------------------------------------------

    /**
     * Attempts AES/CBC decryption and returns the raw decrypted string.
     *
     * <p>If decryption fails because the input is plain text (not encrypted),
     * the original input is returned unchanged. This makes it safe to call on
     * values that may or may not have been encrypted — the caller always gets
     * a usable string.
     *
     * @param input Base64-encoded ciphertext, or a plain string
     * @return the decrypted plaintext, or {@code input} unchanged if decryption fails
     */
    public String decryptRawString(String input) {
        if (input == null || input.trim().isEmpty()) {
            return input;
        }
        try {
            byte[] decoded = DatatypeConverter.parseBase64Binary(input);
            Key key = new SecretKeySpec(aesKey.getBytes(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivKey.getBytes()));
            return new String(cipher.doFinal(decoded));
        } catch (javax.crypto.IllegalBlockSizeException e) {
            // Input is already plain text — return as-is
            log.info("decryptRawString: input is plain text (not encrypted), returning as-is");
            return input;
        } catch (Exception e) {
            log.error("decryptRawString: failed — {}", e.getMessage());
            return input;
        }
    }

    // -----------------------------------------------------------------------
    // Encrypt
    // -----------------------------------------------------------------------

    /**
     * Encrypts a raw string using AES/CBC with the configured key and IV.
     *
     * <p>The string bytes are encrypted directly without any JSON wrapping —
     * suitable for OAuth form bodies, JWT tokens, or any raw string payload.
     *
     * @param rawPayload the plaintext string to encrypt
     * @return Base64-encoded ciphertext, or {@code null} if encryption fails
     */
    public String encryptRawString(String rawPayload) {
        try {
            Key key = new SecretKeySpec(aesKey.getBytes(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivKey.getBytes()));
            byte[] cipherText = cipher.doFinal(rawPayload.getBytes());
            String encrypted = Base64.getEncoder().encodeToString(cipherText);
            log.info("encryptRawString: encrypted successfully — len={}", encrypted.length());
            return encrypted;
        } catch (Exception e) {
            log.error("encryptRawString: failed — msg={}", e.getMessage(), e);
            return null;
        }
    }
}