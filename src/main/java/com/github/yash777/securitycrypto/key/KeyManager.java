package com.github.yash777.securitycrypto.key;

import com.github.yash777.securitycrypto.exception.CryptoOperationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Base64;

/**
 * Factory and persistence utilities for AES symmetric keys and RSA asymmetric
 * key pairs used within the JCE (Java Cryptographic Extension) framework.
 *
 * <h2>AES key management</h2>
 * <ul>
 *   <li>{@link #generateAesKey(KeySize)} — generate a fresh in-memory key</li>
 *   <li>{@link #getOrCreateAesKey(KeySize, File)} — generate and persist, or reload from disk</li>
 *   <li>{@link #saveAesKey(SecretKey, File)} / {@link #loadAesKey(File)} — explicit I/O</li>
 * </ul>
 *
 * <h2>RSA key management</h2>
 * <ul>
 *   <li>{@link #generateRsaKeyPair(int)} — generate a fresh RSA key pair</li>
 * </ul>
 *
 * <h2>Base64 helpers</h2>
 * <ul>
 *   <li>{@link #encodeKeyToBase64(Key)} — export any key as a Base64 string</li>
 *   <li>{@link #decodeAesKeyFromBase64(String, KeySize)} — reconstruct an AES key</li>
 * </ul>
 *
 * <p>All operations that can fail due to missing algorithms or I/O throw
 * {@link CryptoOperationException} (unchecked) so callers stay clean.
 *
 * @author Yash
 * @version 1.0.0
 * @see <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#keygenerator-algorithms">
 *      KeyGenerator Algorithm Names</a>
 */
public final class KeyManager {

    private static final Logger log = LoggerFactory.getLogger(KeyManager.class);

    private static final String AES_ALGORITHM = "AES";
    private static final String RSA_ALGORITHM = "RSA";

    private KeyManager() {}

    // -----------------------------------------------------------------------
    // AES key generation
    // -----------------------------------------------------------------------

    /**
     * Generates a new AES {@link SecretKey} of the specified size using a
     * {@link KeyGenerator} backed by the default JCE provider.
     *
     * @param size desired key size (128, 192, or 256 bits)
     * @return newly generated {@link SecretKey}
     * @throws CryptoOperationException if AES is not available on this JVM
     *         (wraps {@link NoSuchAlgorithmException})
     */
    public static SecretKey generateAesKey(KeySize size) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
            keyGen.init(size.bits, new SecureRandom());
            SecretKey key = keyGen.generateKey();
            log.info("Generated AES-{} key", size.bits);
            return key;
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoOperationException(
                    "AES KeyGenerator not available: " + e.getMessage(), e);
        }
    }

    /**
     * Returns an existing AES key from disk, or generates and persists a new one
     * if the key file does not yet exist.
     *
     * <p>Key file naming convention: {@code secret_128bit.key},
     * {@code secret_256bit.key}, etc. (see {@link KeySize#fileName()}).
     *
     * @param size   desired key size
     * @param keyDir directory in which to store or read the key file
     * @return the loaded or newly created {@link SecretKey}
     * @throws CryptoOperationException if AES is unavailable or the file cannot be read/written
     */
    public static SecretKey getOrCreateAesKey(KeySize size, File keyDir) {
        File keyFile = new File(keyDir, size.fileName());
        if (keyFile.exists()) {
            log.info("Loading existing AES-{} key from {}", size.bits, keyFile.getAbsolutePath());
            return loadAesKey(keyFile);
        }
        log.info("Key file not found — generating new AES-{} key", size.bits);
        SecretKey key = generateAesKey(size);
        saveAesKey(key, keyFile);
        return key;
    }

    /**
     * Writes the raw encoded bytes of a {@link SecretKey} to the given file.
     *
     * @param key  the AES key to persist
     * @param file target file (created if absent, overwritten if present)
     * @throws CryptoOperationException if the write fails
     */
    public static void saveAesKey(SecretKey key, File file) {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(key.getEncoded());
            log.info("Saved AES key to {}", file.getAbsolutePath());
        } catch (IOException e) {
            throw new CryptoOperationException(
                    "Failed to save AES key to " + file.getAbsolutePath(), e);
        }
    }

    /**
     * Reads raw key bytes from a file and reconstructs the {@link SecretKey}.
     *
     * @param file the key file produced by {@link #saveAesKey}
     * @return the reconstructed {@link SecretKey}
     * @throws CryptoOperationException if the file cannot be read
     */
    public static SecretKey loadAesKey(File file) {
        try {
            byte[] encoded = new byte[(int) file.length()];
            try (FileInputStream fis = new FileInputStream(file)) {
                int bytesRead = fis.read(encoded);
                if (bytesRead != encoded.length) {
                    throw new CryptoOperationException(
                            "Incomplete key read from " + file.getAbsolutePath());
                }
            }
            log.info("Loaded AES key ({} bytes) from {}", encoded.length, file.getAbsolutePath());
            return new SecretKeySpec(encoded, AES_ALGORITHM);
        } catch (IOException e) {
            throw new CryptoOperationException(
                    "Failed to load AES key from " + file.getAbsolutePath(), e);
        }
    }

    // -----------------------------------------------------------------------
    // RSA key generation
    // -----------------------------------------------------------------------

    /**
     * Generates a new RSA {@link KeyPair} with the specified key size.
     *
     * <p>Common RSA key sizes: 2048 (minimum recommended), 3072, 4096 bits.
     *
     * @param keyBits RSA key size in bits (must be ≥ 2048 for security)
     * @return a new RSA {@link KeyPair} ({@link PublicKey} + {@link PrivateKey})
     * @throws CryptoOperationException if RSA is not available
     */
    public static KeyPair generateRsaKeyPair(int keyBits) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            kpg.initialize(keyBits, new SecureRandom());
            KeyPair pair = kpg.generateKeyPair();
            log.info("Generated RSA-{} key pair", keyBits);
            return pair;
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoOperationException(
                    "RSA KeyPairGenerator not available: " + e.getMessage(), e);
        }
    }

    // -----------------------------------------------------------------------
    // Base64 helpers
    // -----------------------------------------------------------------------

    /**
     * Encodes any {@link Key} (symmetric or asymmetric) to a Base64 string.
     * Useful for logging, configuration, or transport.
     *
     * @param key the key to encode
     * @return Base64-encoded string of the key's raw bytes
     */
    public static String encodeKeyToBase64(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Reconstructs an AES {@link SecretKey} from a Base64 string previously
     * produced by {@link #encodeKeyToBase64(Key)}.
     *
     * @param base64Key Base64-encoded key material
     * @param size      expected key size (used only for logging; the byte array length is authoritative)
     * @return the reconstructed {@link SecretKey}
     */
    public static SecretKey decodeAesKeyFromBase64(String base64Key, KeySize size) {
        byte[] decoded = Base64.getDecoder().decode(base64Key);
        log.info("Decoded AES key ({} bytes, expected {})", decoded.length, size.bytes());
        return new SecretKeySpec(decoded, AES_ALGORITHM);
    }

    /**
     * Logs the Base64 representation of a key for debugging.
     *
     * <p><strong>Warning:</strong> Do not call this in production with real
     * secret keys — logging key material is a security risk.
     *
     * @param key the key to inspect
     */
    public static void logKeyInfo(Key key) {
        log.info("Key algorithm={} format={} length={}bytes encoded(Base64)={}",
                key.getAlgorithm(),
                key.getFormat(),
                key.getEncoded().length,
                encodeKeyToBase64(key));
    }
}
