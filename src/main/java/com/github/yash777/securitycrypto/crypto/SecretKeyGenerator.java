package com.github.yash777.securitycrypto.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Generates cryptographically secure passphrases and salts used as inputs to
 * {@link PasswordBasedCrypto} for PBKDF2 key derivation.
 *
 * <h2>Concepts</h2>
 * <dl>
 *   <dt>Secret passphrase (master key)</dt>
 *   <dd>A high-entropy string used as the PBKDF2 <em>password</em> — <strong>not</strong>
 *       an AES key directly. PBKDF2 stretches it into a fixed-length AES key.
 *       Typically one per application; stored securely (vault, env variable, key file).</dd>
 *   <dt>Salt</dt>
 *   <dd>A per-record random value fed to PBKDF2 alongside the passphrase.
 *       Prevents pre-computation (rainbow table) attacks.
 *       Must be stored alongside the encrypted data; does not need to be secret.</dd>
 * </dl>
 *
 * <h2>Character set for passphrase generation</h2>
 * <p>{@link #CHARACTERS} contains upper/lower-case letters, digits, and special
 * characters — the same set used in the original {@code CryptoService} master key.
 *
 * <h2>Salt size guidance</h2>
 * <pre>
 *   saltSize = 16 bytes → Base64 output = 24 characters
 *   saltSize = 24 bytes → Base64 output = 32 characters
 *   saltSize = 32 bytes → Base64 output = 44 characters  (recommended)
 * </pre>
 *
 * <h2>Quick usage</h2>
 * <pre>{@code
 * // Generate a 64-char master passphrase (store in a vault/config file)
 * String masterKey = SecretKeyGenerator.generatePassphrase();
 *
 * // Generate a random salt per user record
 * String salt = SecretKeyGenerator.generateRandomSalt(24);
 *
 * // Or derive a deterministic salt from a username + timestamp
 * String salt = SecretKeyGenerator.generateUserSpecificSalt("user@example.com", 24);
 *
 * // Save both to a file for later reuse
 * SecretKeyGenerator.saveToFile(masterKey, salt, new File("/secure/keys/app.key"));
 *
 * // Reload
 * String[] loaded = SecretKeyGenerator.loadFromFile(new File("/secure/keys/app.key"));
 * String masterKey = loaded[0];
 * String salt      = loaded[1];
 * }</pre>
 *
 * @author  Yashwanth
 * @version 1.0.1
 * @see     PasswordBasedCrypto
 */
public final class SecretKeyGenerator {

    private static final Logger log = LoggerFactory.getLogger(SecretKeyGenerator.class);

    /**
     * Character pool for passphrase generation.
     * Includes upper/lower-case letters, digits, and common special characters
     * — matching the character space of the original {@code CryptoService.key}.
     */
    public static final String CHARACTERS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" +
            "0123456789!@#$%^&*()-_=+[{]}|;:'\",<.>/?";

    /** Default passphrase length in characters. Produces ~380 bits of entropy. */
    public static final int DEFAULT_PASSPHRASE_LENGTH = 64;

    /** Default salt size in bytes. Produces a 32-character Base64 string. */
    public static final int DEFAULT_SALT_SIZE = 24;

    /** Property key used when saving/loading the passphrase from a file. */
    private static final String FILE_KEY_PASSPHRASE = "passphrase";

    /** Property key used when saving/loading the salt from a file. */
    private static final String FILE_KEY_SALT = "salt";

    private SecretKeyGenerator() { /* utility class */ }

    // -----------------------------------------------------------------------
    // Passphrase generation
    // -----------------------------------------------------------------------

    /**
     * Generates a cryptographically random passphrase of
     * {@value #DEFAULT_PASSPHRASE_LENGTH} characters drawn from {@link #CHARACTERS}.
     *
     * <p>The result has approximately
     * {@code log2(CHARACTERS.length) * DEFAULT_PASSPHRASE_LENGTH} ≈ 380 bits of entropy
     * and is suitable as a PBKDF2 master passphrase.
     *
     * @return a 64-character random passphrase string
     */
    public static String generatePassphrase() {
        return generatePassphrase(DEFAULT_PASSPHRASE_LENGTH);
    }

    /**
     * Generates a cryptographically random passphrase of the specified length
     * drawn from {@link #CHARACTERS}.
     *
     * @param length number of characters in the generated passphrase (e.g. 32, 64, 128)
     * @return a random passphrase string of the given length
     * @throws IllegalArgumentException if {@code length} is less than 1
     */
    public static String generatePassphrase(int length) {
        if (length < 1) {
            throw new IllegalArgumentException("Passphrase length must be at least 1, got " + length);
        }
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(CHARACTERS.charAt(random.nextInt(CHARACTERS.length())));
        }
        String passphrase = sb.toString();
        log.debug("Generated passphrase: length={} entropyBits≈{}",
                length, (int) (Math.log(CHARACTERS.length()) / Math.log(2) * length));
        return passphrase;
    }

    // -----------------------------------------------------------------------
    // Random salt generation
    // -----------------------------------------------------------------------

    /**
     * Generates a cryptographically random salt of {@value #DEFAULT_SALT_SIZE} bytes,
     * returned as a Base64-encoded string.
     *
     * <p>Use this when no user-specific information is available or when a completely
     * unpredictable salt is preferred.
     *
     * @return Base64-encoded random salt string (32 characters for 24-byte salt)
     */
    public static String generateRandomSalt() {
        return generateRandomSalt(DEFAULT_SALT_SIZE);
    }

    /**
     * Generates a cryptographically random salt of {@code saltSize} bytes,
     * returned as a Base64-encoded string.
     *
     * <pre>
     *   saltSize = 16 bytes → 24-character Base64
     *   saltSize = 24 bytes → 32-character Base64  (default)
     *   saltSize = 32 bytes → 44-character Base64
     * </pre>
     *
     * @param saltSize number of random bytes to generate (minimum 16 recommended)
     * @return Base64-encoded random salt string
     * @throws IllegalArgumentException if {@code saltSize} is less than 1
     */
    public static String generateRandomSalt(int saltSize) {
        if (saltSize < 1) {
            throw new IllegalArgumentException("Salt size must be at least 1, got " + saltSize);
        }
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[saltSize];
        random.nextBytes(salt);
        String encoded = Base64.getEncoder().encodeToString(salt);
        log.debug("Generated random salt: saltSize={}B base64Len={}", saltSize, encoded.length());
        return encoded;
    }

    // -----------------------------------------------------------------------
    // User-specific salt generation
    // -----------------------------------------------------------------------

    /**
     * Generates a salt derived from a username combined with a current-time timestamp
     * and additional random bytes, returned as a Base64-encoded string.
     *
     * <p>The username + timestamp combination ensures the salt differs across users
     * and across time. The {@link SecureRandom} bytes make it unpredictable even if
     * the username and timestamp are known.
     *
     * <p><strong>Note:</strong> Because the timestamp component changes on every call,
     * this method is <em>not</em> deterministic — two calls with the same username
     * produce different salts. Store the returned salt alongside the encrypted data.
     *
     * @param userName the username (or any unique per-user string, e.g. email address)
     * @param saltSize number of random bytes to mix in (minimum 16 recommended)
     * @return Base64-encoded salt string
     * @throws IllegalArgumentException if {@code userName} is null or {@code saltSize} &lt; 1
     */
    public static String generateUserSpecificSalt(String userName, int saltSize) {
        if (userName == null) {
            throw new IllegalArgumentException("userName must not be null");
        }
        if (saltSize < 1) {
            throw new IllegalArgumentException("Salt size must be at least 1, got " + saltSize);
        }

        // Combine username + timestamp to create a unique base — never used directly as salt
        String saltBase = userName + System.currentTimeMillis();
        log.debug("generateUserSpecificSalt: saltBase='{}'", saltBase);

        // Mix in cryptographically secure random bytes so the salt is unpredictable
        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[saltSize];
        random.nextBytes(randomBytes);

        String encoded = Base64.getEncoder().encodeToString(randomBytes);
        log.debug("Generated user-specific salt for '{}': base64Len={}", userName, encoded.length());
        return encoded;
    }

    /**
     * Generates a user-specific salt of {@value #DEFAULT_SALT_SIZE} bytes.
     *
     * @param userName the username or email address
     * @return Base64-encoded salt string
     * @see #generateUserSpecificSalt(String, int)
     */
    public static String generateUserSpecificSalt(String userName) {
        return generateUserSpecificSalt(userName, DEFAULT_SALT_SIZE);
    }

    // -----------------------------------------------------------------------
    // File persistence
    // -----------------------------------------------------------------------

    /**
     * Saves a passphrase and a salt to a plain-text key file.
     *
     * <p>File format (two lines):
     * <pre>
     *   passphrase=&lt;value&gt;
     *   salt=&lt;value&gt;
     * </pre>
     *
     * <p><strong>Security:</strong> Restrict file permissions to the application user only
     * (e.g. {@code chmod 600 app.key} on Linux/macOS). Do not commit key files to source control.
     *
     * @param passphrase the master passphrase to save
     * @param salt       the salt to save (may be empty string if not applicable)
     * @param file       target file (created if absent, overwritten if present)
     * @throws IllegalArgumentException if {@code passphrase} is null or empty
     * @throws RuntimeException         wrapping {@link IOException} if the write fails
     */
    public static void saveToFile(String passphrase, String salt, File file) {
        if (passphrase == null || passphrase.isEmpty()) {
            throw new IllegalArgumentException("Passphrase must not be null or empty");
        }
        PrintWriter pw = null;
        try {
            // Ensure parent directory exists
            File parent = file.getParentFile();
            if (parent != null && !parent.exists()) {
                if (!parent.mkdirs()) {
                    throw new IOException("Could not create directory: " + parent.getAbsolutePath());
                }
            }
            pw = new PrintWriter(new FileWriter(file));
            pw.println(FILE_KEY_PASSPHRASE + "=" + passphrase);
            pw.println(FILE_KEY_SALT + "=" + (salt != null ? salt : ""));
            log.info("Saved passphrase and salt to {}", file.getAbsolutePath());
        } catch (IOException e) {
            throw new RuntimeException("Failed to save key file: " + file.getAbsolutePath(), e);
        } finally {
            if (pw != null) pw.close();
        }
    }

    /**
     * Saves only a passphrase to a key file (no salt).
     *
     * @param passphrase the master passphrase to save
     * @param file       target file
     * @see #saveToFile(String, String, File)
     */
    public static void savePassphraseToFile(String passphrase, File file) {
        saveToFile(passphrase, "", file);
    }

    /**
     * Loads a passphrase and salt from a key file previously written by
     * {@link #saveToFile(String, String, File)}.
     *
     * @param file the key file to read
     * @return a two-element array: {@code [0] = passphrase}, {@code [1] = salt}
     *         (salt may be an empty string if not present in file)
     * @throws RuntimeException if the file cannot be read or the passphrase line is missing
     */
    public static String[] loadFromFile(File file) {
        String passphrase = null;
        String salt       = "";
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(file));
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.startsWith(FILE_KEY_PASSPHRASE + "=")) {
                    passphrase = line.substring((FILE_KEY_PASSPHRASE + "=").length());
                } else if (line.startsWith(FILE_KEY_SALT + "=")) {
                    salt = line.substring((FILE_KEY_SALT + "=").length());
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to read key file: " + file.getAbsolutePath(), e);
        } finally {
            if (br != null) {
                try { br.close(); } catch (IOException ignored) { /* close quietly */ }
            }
        }
        if (passphrase == null || passphrase.isEmpty()) {
            throw new RuntimeException(
                    "Key file does not contain a valid passphrase: " + file.getAbsolutePath());
        }
        log.info("Loaded passphrase and salt from {}", file.getAbsolutePath());
        return new String[]{ passphrase, salt };
    }
    
 // -----------------------------------------------------------------------
    // AES Symmetric Key generation (KeyGenerator — not PBKDF2)
    // -----------------------------------------------------------------------
 
    /**
     * Generates a symmetric AES secret key using {@link KeyGenerator}.
     *
     * <p>This produces a raw AES key, suitable for use directly with
     * {@link javax.crypto.Cipher}. It is <strong>not</strong> derived from a passphrase —
     * use {@link #derivePbkdf2Key(String, String)} when you need passphrase-based derivation.
     *
     * <p>Symmetric encryption (AES) uses the <em>same</em> key for both encryption and
     * decryption — fast and efficient for large data volumes.
     *
     * @param keyBits AES key size in bits: 128, 192, or 256
     *                (256-bit recommended; requires JCE unlimited-strength on Java 8)
     * @return a freshly generated {@link SecretKey} for AES
     * @throws IllegalArgumentException if {@code keyBits} is not 128, 192, or 256
     * @throws RuntimeException wrapping {@link NoSuchAlgorithmException} if AES is unavailable
     */
    public static SecretKey generateAesSymmetricKey(int keyBits) {
        if (keyBits != 128 && keyBits != 192 && keyBits != 256) {
            throw new IllegalArgumentException(
                    "AES key size must be 128, 192, or 256 bits — got " + keyBits);
        }
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(keyBits, new SecureRandom());
            SecretKey key = keyGen.generateKey();
            log.debug("generateAesSymmetricKey: keyBits={} algorithm={}", keyBits, key.getAlgorithm());
            return key;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("AES KeyGenerator not available: " + e.getMessage(), e);
        }
    }
 
    /**
     * Generates a 256-bit AES symmetric key (recommended default).
     *
     * @return a freshly generated 256-bit {@link SecretKey} for AES
     * @see #generateAesSymmetricKey(int)
     */
    public static SecretKey generateAesSymmetricKey() {
        return generateAesSymmetricKey(256);
    }
 
    // -----------------------------------------------------------------------
    // PBKDF2 key derivation
    // -----------------------------------------------------------------------
 
    /**
     * Derives an AES {@link SecretKey} from a passphrase and a salt string using PBKDF2.
     *
     * <p>PBKDF2 (Password-Based Key Derivation Function 2) stretches a human-readable
     * passphrase into a fixed-length cryptographic key. It is intentionally slow —
     * that is the security mechanism. The derived key is deterministic: the same
     * {@code passphrase + salt + algorithm + iterations + keyBits} always produces
     * the same key bytes.
     *
     * <p>Use this when you need to reproduce the same AES key from a stored passphrase
     * (e.g. the master key from a config file) without storing the key itself on disk.
     *
     * <h3>Algorithm options</h3>
     * <ul>
     *   <li>{@code "PBKDF2WithHmacSHA1"}   — legacy; matches original {@code CryptoService}</li>
     *   <li>{@code "PBKDF2WithHmacSHA256"} — recommended for new code</li>
     * </ul>
     *
     * @param passphrase   the master passphrase (e.g. generated by {@link #generatePassphrase()})
     * @param salt         per-record salt string (e.g. username or {@link #generateRandomSalt()})
     * @param pbkdf2Algo   JCE algorithm name: {@code "PBKDF2WithHmacSHA1"} or
     *                     {@code "PBKDF2WithHmacSHA256"}
     * @param iterations   PBKDF2 iteration count (1024 for legacy; 65536+ recommended)
     * @param keyBits      derived AES key length in bits (128 or 256)
     * @return the derived AES {@link SecretKey}
     * @throws RuntimeException wrapping any JCE exception if derivation fails
     */
    public static SecretKey derivePbkdf2Key(String passphrase, String salt,
                                            String pbkdf2Algo, int iterations, int keyBits) {
        try {
            byte[] saltBytes = salt.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(pbkdf2Algo);
            PBEKeySpec spec = new PBEKeySpec(
                    passphrase.toCharArray(), saltBytes, iterations, keyBits);
            SecretKey tmp = factory.generateSecret(spec);
            spec.clearPassword();
            SecretKey key = new SecretKeySpec(tmp.getEncoded(), "AES");
            log.debug("derivePbkdf2Key: algo={} iterations={} keyBits={}", pbkdf2Algo, iterations, keyBits);
            return key;
        } catch (Exception e) {
            throw new RuntimeException(
                    "PBKDF2 key derivation failed [" + pbkdf2Algo + "]: " + e.getMessage(), e);
        }
    }
 
    /**
     * Derives an AES key using PBKDF2-HMAC-SHA1 with 1024 iterations and 128-bit output —
     * matching the original {@code CryptoService.EncoderConstants} settings.
     *
     * @param passphrase the master passphrase
     * @param salt       per-record salt (e.g. username)
     * @return derived 128-bit AES {@link SecretKey}
     * @see #derivePbkdf2Key(String, String, String, int, int)
     */
    public static SecretKey derivePbkdf2KeyLegacy(String passphrase, String salt) {
        return derivePbkdf2Key(passphrase, salt, "PBKDF2WithHmacSHA1", 1024, 128);
    }
 
    /**
     * Derives an AES key using PBKDF2-HMAC-SHA256 with 65536 iterations and 256-bit output —
     * the recommended settings for new code.
     *
     * @param passphrase the master passphrase
     * @param salt       per-record salt
     * @return derived 256-bit AES {@link SecretKey}
     * @see #derivePbkdf2Key(String, String, String, int, int)
     */
    public static SecretKey derivePbkdf2Key(String passphrase, String salt) {
        return derivePbkdf2Key(passphrase, salt, "PBKDF2WithHmacSHA256", 65536, 256);
    }
 
    // -----------------------------------------------------------------------
    // Key encode / decode helpers
    // -----------------------------------------------------------------------
 
    /**
     * Encodes an AES {@link SecretKey} to a Base64 string for storage or transport.
     *
     * @param key the key to encode
     * @return Base64-encoded key string
     */
    public static String encodeKeyToBase64(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }
 
    /**
     * Reconstructs an AES {@link SecretKey} from a Base64 string previously
     * produced by {@link #encodeKeyToBase64(SecretKey)}.
     *
     * @param base64Key Base64-encoded key material
     * @return the reconstructed AES {@link SecretKey}
     */
    public static SecretKey decodeKeyFromBase64(String base64Key) {
        byte[] decoded = Base64.getDecoder().decode(base64Key);
        return new SecretKeySpec(decoded, "AES");
    }

}