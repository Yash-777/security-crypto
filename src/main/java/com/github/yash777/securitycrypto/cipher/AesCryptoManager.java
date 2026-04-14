package com.github.yash777.securitycrypto.cipher;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.util.Base64;

/**
 * Static helper methods for AES-GCM (Galois/Counter Mode) encryption and decryption.
 *
 * <p>GCM is an Authenticated Encryption with Associated Data (AEAD) mode that
 * provides both <em>confidentiality</em> and <em>integrity</em> in a single pass.
 * A 128-bit authentication tag is appended to the ciphertext; any modification
 * causes decryption to throw {@link javax.crypto.AEADBadTagException}.
 *
 * <p>Unlike {@link AesSymmetricCipher}, this class does <strong>not</strong> manage
 * IV generation or embedding — the caller supplies and manages the IV (nonce).
 * Use a unique 12-byte nonce per (key, message) pair; never reuse.
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * SecretKey key = SecretKeyGenerator.generateAesSymmetricKey(256);
 * byte[] iv     = new byte[12];
 * new SecureRandom().nextBytes(iv);
 *
 * String ciphertext = AesCryptoManager.encrypt("Hello GCM!", key, iv);
 * String plaintext  = AesCryptoManager.decrypt(ciphertext, key, iv);
 * }</pre>
 *
 * @author  Yashwanth
 * @version 1.0.1
 * @see     AesSymmetricCipher     for IV-managed (auto-prepend) encrypt/decrypt
 * @see     <a href="http://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html">javax.crypto.Cipher</a>
 */
public final class AesCryptoManager {

    /** AES-GCM transformation string. */
    private static final String ALGO = "AES/GCM/NoPadding";

    /** GCM authentication tag length in bits (128 = maximum, per NIST SP 800-38D). */
    private static final int TAG_LENGTH_BITS = 128;

    private AesCryptoManager() { /* static utility class */ }

    /**
     * Encrypts {@code data} with AES-GCM using the supplied key and IV.
     *
     * <p>The returned Base64 string contains the raw ciphertext + 16-byte auth tag.
     * The IV is <strong>not</strong> included — the caller must store it separately.
     *
     * @param data the UTF-8 plaintext to encrypt
     * @param key  AES secret key (128, 192, or 256-bit)
     * @param iv   12-byte GCM nonce (must be unique per key per message)
     * @return Base64-encoded {@code ciphertext + GCM tag}
     * @throws Exception if encryption fails
     */
    public static String encrypt(String data, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
        byte[] encrypted = cipher.doFinal(data.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Decrypts a Base64-encoded AES-GCM ciphertext produced by {@link #encrypt}.
     *
     * @param encryptedData Base64-encoded {@code ciphertext + GCM tag}
     * @param key           the same AES key used for encryption
     * @param iv            the same 12-byte nonce used for encryption
     * @return the decrypted plaintext string (UTF-8)
     * @throws Exception if decryption or tag verification fails
     */
    public static String decrypt(String encryptedData, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
        byte[] decoded = Base64.getDecoder().decode(encryptedData);
        return new String(cipher.doFinal(decoded), "UTF-8");
    }
}