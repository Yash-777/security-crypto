package com.github.yash777.securitycrypto;

import com.github.yash777.securitycrypto.cipher.AesSymmetricCipher;
import com.github.yash777.securitycrypto.cipher.CipherMode;
import com.github.yash777.securitycrypto.cipher.HybridCipher;
import com.github.yash777.securitycrypto.cipher.HybridCipher.HybridPayload;
import com.github.yash777.securitycrypto.cipher.RsaAsymmetricCipher;
import com.github.yash777.securitycrypto.exception.CryptoOperationException;
import com.github.yash777.securitycrypto.exception.InvalidCiphertextException;
import com.github.yash777.securitycrypto.key.KeyManager;
import com.github.yash777.securitycrypto.key.KeySize;
import com.github.yash777.securitycrypto.util.IvUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Facade providing the primary, opinionated API for the {@code security-crypto} library.
 *
 * <p>Most applications only need this class. It wires together
 * {@link AesSymmetricCipher}, {@link RsaAsymmetricCipher}, {@link HybridCipher},
 * {@link KeyManager}, and {@link IvUtils} into simple, coherent methods.
 *
 * <h2>Quick-start examples</h2>
 *
 * <h3>AES-GCM (recommended for symmetric encryption)</h3>
 * <pre>{@code
 * CryptoFacade crypto = new CryptoFacade();
 *
 * SecretKey key      = crypto.generateAesKey(KeySize.AES_256);
 * String ciphertext  = crypto.aesEncrypt("Hello, World!", key);        // GCM by default
 * String plaintext   = crypto.aesDecrypt(ciphertext, key);
 * }</pre>
 *
 * <h3>AES-CBC with an explicit IV</h3>
 * <pre>{@code
 * IvParameterSpec iv = IvUtils.generateRandom();                        // random 16-byte IV
 * String ciphertext  = crypto.aesEncrypt("Hello", key, CipherMode.CBC, iv);
 * String plaintext   = crypto.aesDecrypt(ciphertext, key, CipherMode.CBC);
 * }</pre>
 *
 * <h3>RSA (small payload / key exchange)</h3>
 * <pre>{@code
 * KeyPair rsa       = crypto.generateRsaKeyPair(2048);
 * String encrypted  = crypto.rsaEncrypt("secret", rsa.getPublic());
 * String decrypted  = crypto.rsaDecrypt(encrypted, rsa.getPrivate());
 * }</pre>
 *
 * <h3>Hybrid RSA + AES-GCM (large payload)</h3>
 * <pre>{@code
 * HybridPayload payload = crypto.hybridEncrypt("Long text...", rsa.getPublic());
 * String plaintext      = crypto.hybridDecrypt(payload, rsa.getPrivate());
 * }</pre>
 *
 * @author Yash
 * @version 1.0.0
 */
public class CryptoFacade {

    private final AesSymmetricCipher   aesSymmetricCipher  = new AesSymmetricCipher();
    private final RsaAsymmetricCipher  rsaAsymmetricCipher = new RsaAsymmetricCipher();
    private final HybridCipher         hybridCipher        = new HybridCipher();

    // -----------------------------------------------------------------------
    // Key management
    // -----------------------------------------------------------------------

    /**
     * Generates a new in-memory AES key of the specified size.
     *
     * @param size key size (128, 192, or 256 bits)
     * @return newly generated {@link SecretKey}
     * @throws CryptoOperationException if AES is not available
     */
    public SecretKey generateAesKey(KeySize size) {
        return KeyManager.generateAesKey(size);
    }

    /**
     * Generates or reloads a persisted AES key from disk.
     *
     * @param size   desired key size
     * @param keyDir directory containing (or to create) the key file
     * @return the persisted or newly created {@link SecretKey}
     */
    public SecretKey getOrCreateAesKey(KeySize size, File keyDir) {
        return KeyManager.getOrCreateAesKey(size, keyDir);
    }

    /**
     * Generates a new RSA key pair.
     *
     * @param keyBits RSA modulus size in bits (minimum 2048)
     * @return the generated {@link KeyPair}
     */
    public KeyPair generateRsaKeyPair(int keyBits) {
        return KeyManager.generateRsaKeyPair(keyBits);
    }

    // -----------------------------------------------------------------------
    // AES encrypt / decrypt (default GCM, random IV)
    // -----------------------------------------------------------------------

    /**
     * Encrypts {@code plaintext} with AES-GCM and a randomly generated 12-byte nonce.
     * <strong>Recommended for all new symmetric encryption.</strong>
     *
     * @param plaintext UTF-8 string to encrypt
     * @param key       AES key (128/192/256-bit)
     * @return Base64-encoded payload: {@code Base64(nonce || ciphertext || GCM_tag)}
     * @throws CryptoOperationException if encryption fails
     */
    public String aesEncrypt(String plaintext, SecretKey key) {
        return aesSymmetricCipher.encrypt(plaintext, key, CipherMode.GCM);
    }

    /**
     * Decrypts an AES-GCM ciphertext produced by {@link #aesEncrypt(String, SecretKey)}.
     *
     * @param ciphertext Base64-encoded payload returned by {@code aesEncrypt}
     * @param key        the same AES key used for encryption
     * @return decrypted plaintext
     * @throws InvalidCiphertextException if the tag check fails or data is malformed
     */
    public String aesDecrypt(String ciphertext, SecretKey key)
            throws InvalidCiphertextException {
        return aesSymmetricCipher.decrypt(ciphertext, key, CipherMode.GCM);
    }

    // -----------------------------------------------------------------------
    // AES encrypt / decrypt (explicit mode)
    // -----------------------------------------------------------------------

    /**
     * Encrypts {@code plaintext} using the specified AES cipher mode with an
     * auto-generated IV.
     *
     * @param plaintext UTF-8 string to encrypt
     * @param key       AES key
     * @param mode      cipher mode (ECB, CBC, or GCM)
     * @return Base64-encoded payload (IV prepended for CBC and GCM)
     */
    public String aesEncrypt(String plaintext, SecretKey key, CipherMode mode) {
        return aesSymmetricCipher.encrypt(plaintext, key, mode);
    }

    /**
     * Encrypts {@code plaintext} using the specified AES cipher mode with an
     * explicitly supplied IV.
     *
     * @param plaintext UTF-8 string to encrypt
     * @param key       AES key
     * @param mode      cipher mode
     * @param ivSpec    IV to use (ignored for ECB)
     * @return Base64-encoded payload
     */
    public String aesEncrypt(String plaintext, SecretKey key, CipherMode mode, IvParameterSpec ivSpec) {
        return aesSymmetricCipher.encrypt(plaintext, key, mode, ivSpec);
    }

    /**
     * Decrypts an AES ciphertext produced by one of the {@code aesEncrypt} methods.
     *
     * @param ciphertext Base64-encoded payload
     * @param key        the same AES key used for encryption
     * @param mode       the same cipher mode used for encryption
     * @return decrypted plaintext
     * @throws InvalidCiphertextException if the payload is malformed or tampered
     */
    public String aesDecrypt(String ciphertext, SecretKey key, CipherMode mode)
            throws InvalidCiphertextException {
        return aesSymmetricCipher.decrypt(ciphertext, key, mode);
    }

    // -----------------------------------------------------------------------
    // RSA encrypt / decrypt
    // -----------------------------------------------------------------------

    /**
     * Encrypts a short string with an RSA public key (OAEP-SHA-256 padding).
     *
     * <p>Limited to approximately 190 bytes of plaintext for RSA-2048.
     * For larger payloads use {@link #hybridEncrypt(String, PublicKey)}.
     *
     * @param plaintext short plaintext to encrypt
     * @param publicKey recipient's RSA public key
     * @return Base64-encoded RSA ciphertext
     */
    public String rsaEncrypt(String plaintext, PublicKey publicKey) {
        return rsaAsymmetricCipher.encrypt(plaintext, publicKey);
    }

    /**
     * Decrypts an RSA ciphertext produced by {@link #rsaEncrypt(String, PublicKey)}.
     *
     * @param ciphertext Base64-encoded RSA ciphertext
     * @param privateKey the RSA private key
     * @return decrypted plaintext
     * @throws InvalidCiphertextException if decryption fails
     */
    public String rsaDecrypt(String ciphertext, PrivateKey privateKey)
            throws InvalidCiphertextException {
        return rsaAsymmetricCipher.decrypt(ciphertext, privateKey);
    }

    // -----------------------------------------------------------------------
    // Hybrid RSA + AES-GCM
    // -----------------------------------------------------------------------

    /**
     * Encrypts an arbitrary-length plaintext using hybrid RSA + AES-GCM.
     *
     * <p>A fresh AES-256 session key is generated, used to encrypt the plaintext
     * with GCM, then wrapped with the RSA public key.
     *
     * @param plaintext any UTF-8 string
     * @param publicKey recipient's RSA public key (≥ 2048-bit)
     * @return a {@link HybridPayload} containing the RSA-wrapped key and the GCM ciphertext
     */
    public HybridPayload hybridEncrypt(String plaintext, PublicKey publicKey) {
        return hybridCipher.encrypt(plaintext, publicKey);
    }

    /**
     * Decrypts a {@link HybridPayload} produced by {@link #hybridEncrypt(String, PublicKey)}.
     *
     * @param payload    the hybrid payload to decrypt
     * @param privateKey the RSA private key
     * @return the original plaintext
     * @throws InvalidCiphertextException if the RSA key unwrap or GCM decryption fails
     */
    public String hybridDecrypt(HybridPayload payload, PrivateKey privateKey)
            throws InvalidCiphertextException {
        return hybridCipher.decrypt(payload, privateKey);
    }
}
