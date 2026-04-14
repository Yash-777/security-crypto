package com.github.yash777.securitycrypto.cipher;

import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * Static helper methods for RSA asymmetric encryption and decryption.
 *
 * <p>Asymmetric encryption (RSA) uses a <em>key pair</em>:
 * <ul>
 *   <li><strong>Public key</strong> — shared freely; used to encrypt.</li>
 *   <li><strong>Private key</strong> — kept secret; used to decrypt.</li>
 * </ul>
 * This solves the key-distribution problem of symmetric encryption, but RSA is
 * computationally much slower than AES. Use it for small payloads (key exchange,
 * tokens) or in the hybrid pattern: RSA wraps an AES session key,
 * AES encrypts the bulk data.
 *
 * <p>This class uses the basic {@code "RSA"} transformation (PKCS#1 v1.5 padding
 * via the JCE default). For OAEP-SHA-256 padding (more secure, recommended for
 * new code) use {@link RsaAsymmetricCipher}.
 *
 * <p>RSA-2048 with PKCS#1 padding supports up to 245 bytes of plaintext.
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * KeyPair kp = KeyManager.generateRsaKeyPair(2048);
 *
 * String encrypted = RsaCryptoManager.encrypt("secret", kp.getPublic());
 * String decrypted = RsaCryptoManager.decrypt(encrypted, kp.getPrivate());
 * }</pre>
 *
 * @author  Yashwanth
 * @version 1.0.1
 * @see     RsaAsymmetricCipher    for OAEP-SHA-256 padding (recommended)
 * @see     <a href="http://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html">javax.crypto.Cipher</a>
 */
public final class RsaCryptoManager {

    private static final String ALGO = "RSA";

    private RsaCryptoManager() { /* static utility class */ }

    /**
     * Encrypts {@code data} using the given RSA public key (PKCS#1 v1.5 padding).
     *
     * @param data      UTF-8 plaintext (max ~245 bytes for RSA-2048)
     * @param publicKey the recipient's RSA public key
     * @return Base64-encoded RSA ciphertext
     * @throws Exception if encryption fails or plaintext exceeds key size limit
     */
    public static String encrypt(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes("UTF-8")));
    }

    /**
     * Decrypts a Base64-encoded RSA ciphertext produced by {@link #encrypt}.
     *
     * @param encryptedData Base64-encoded RSA ciphertext
     * @param privateKey    the RSA private key matching the public key used for encryption
     * @return decrypted plaintext string (UTF-8)
     * @throws Exception if decryption fails or the wrong private key is supplied
     */
    public static String decrypt(String encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decoded = Base64.getDecoder().decode(encryptedData);
        return new String(cipher.doFinal(decoded), "UTF-8");
    }
}