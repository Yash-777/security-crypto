package com.github.yash777.securitycrypto.crypto;

import com.github.yash777.securitycrypto.exception.CryptoOperationException;
import com.github.yash777.securitycrypto.exception.InvalidCiphertextException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Password-based AES-CBC encryption using PBKDF2 key derivation — Java 8 compatible.
 *
 * <p>This class implements the pattern used in
 * {@code com.github.yash777.security.crypto.CryptoService} from the MyWorld project,
 * generalised to support two IV strategies:
 * <ul>
 *   <li><strong>IV from Date</strong> — the first 16 bytes of the date string
 *       (formatted as {@value #DEFAULT_DATE_FORMAT}) are used as a deterministic IV.
 *       Both sides must agree on the same date to reproduce the same IV.</li>
 *   <li><strong>Random IV</strong> — a cryptographically random 16-byte IV is generated
 *       with {@link SecureRandom} and prepended to the ciphertext, so the receiver
 *       does not need any out-of-band IV transmission.</li>
 * </ul>
 *
 * <h2>Key derivation</h2>
 * <p>The passphrase is strengthened using
 * <a href="https://www.ietf.org/rfc/rfc2898.txt">PBKDF2WithHmacSHA256</a>
 * (SHA-1 variant also available via {@link Algorithm}) with a configurable salt and
 * iteration count. This approach is recommended in:
 * <ul>
 *   <li><a href="https://stackoverflow.com/a/32583766/5081877">
 *       SO answer 32583766</a> — AES password-based encryption</li>
 *   <li><a href="https://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption">
 *       SO 992019</a> — Java 256-bit AES password-based encryption</li>
 * </ul>
 *
 * <h2>Wire format — with random IV</h2>
 * <pre>
 *   Base64( IV_bytes_16 || ciphertext_bytes )
 * </pre>
 *
 * <h2>Wire format — with date IV</h2>
 * <pre>
 *   Base64( ciphertext_bytes )
 *   (IV is re-derived from the date on decrypt — not prepended)
 * </pre>
 *
 * <h2>Usage example</h2>
 * <pre>{@code
 * PasswordBasedCrypto pbc = new PasswordBasedCrypto();
 *
 * // Encrypt with random IV — self-contained, IV embedded in output
 * String ct = pbc.encryptWithRandomIv("secret data", "myPassphrase", "userSalt");
 * String pt = pbc.decryptWithRandomIv(ct, "myPassphrase", "userSalt");
 *
 * // Encrypt with date IV — deterministic, both sides must share the date
 * Date enrollDate = new Date();
 * String ctDate = pbc.encryptWithDateIv("secret data", "myPassphrase", "userSalt", enrollDate);
 * String ptDate  = pbc.decryptWithDateIv(ctDate, "myPassphrase", "userSalt", enrollDate);
 * }</pre>
 *
 * @author  Yash
 * @version 1.0.0
 * @since   1.0.0
 * @see     <a href="https://stackoverflow.com/a/32583766/5081877">SO 32583766 — password-based AES</a>
 * @see     <a href="https://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption">SO 992019</a>
 * @see     <a href="http://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html">javax.crypto.Cipher</a>
 */
public class PasswordBasedCrypto {

    private static final Logger log = LoggerFactory.getLogger(PasswordBasedCrypto.class);

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    /** Default date format used to derive an IV string from a {@link Date}. Matches the pattern in CryptoService. */
    public static final String DEFAULT_DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss";

    /** AES cipher transformation used for all encrypt/decrypt operations. */
    public static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    /** AES algorithm name for {@link SecretKeySpec}. */
    public static final String AES_ALGORITHM = "AES";

    /** IV length in bytes required by AES-CBC (one AES block = 16 bytes). */
    public static final int IV_LENGTH = 16;

    /**
     * PBKDF2 key derivation algorithm variants.
     *
     * <p>HMAC-SHA256 is preferred for new code. HMAC-SHA1 is provided for compatibility
     * with legacy systems (used in the original {@code CryptoService}).
     */
    public enum Algorithm {

        /**
         * PBKDF2 with HMAC-SHA-1 — legacy, used in CryptoService from MyWorld.
         * Produces a 128-bit or 256-bit AES key.
         */
        PBKDF2_HMAC_SHA1("PBKDF2WithHmacSHA1"),

        /**
         * PBKDF2 with HMAC-SHA-256 — recommended for new code.
         * Stronger hash function; produces a 128-bit or 256-bit AES key.
         */
        PBKDF2_HMAC_SHA256("PBKDF2WithHmacSHA256");

        /** JCE algorithm name passed to {@link SecretKeyFactory#getInstance(String)}. */
        public final String jceName;

        Algorithm(String jceName) {
            this.jceName = jceName;
        }
    }

    // -----------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------

    /** Number of PBKDF2 iterations. Higher = slower = stronger against brute force. */
    private final int iterations;

    /** Derived AES key length in bits (128 or 256). */
    private final int keyLengthBits;

    /** PBKDF2 algorithm to use. */
    private final Algorithm algorithm;

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Creates a {@code PasswordBasedCrypto} with recommended defaults:
     * PBKDF2-HMAC-SHA256, 65536 iterations, 256-bit key.
     */
    public PasswordBasedCrypto() {
        this(Algorithm.PBKDF2_HMAC_SHA256, 65536, 256);
    }

    /**
     * Creates a {@code PasswordBasedCrypto} matching the original {@code CryptoService}
     * behaviour: PBKDF2-HMAC-SHA1, 1024 iterations, 128-bit key.
     *
     * @return a {@code PasswordBasedCrypto} configured for legacy compatibility
     */
    public static PasswordBasedCrypto legacyMode() {
        return new PasswordBasedCrypto(Algorithm.PBKDF2_HMAC_SHA1, 1024, 128);
    }

    /**
     * Creates a {@code PasswordBasedCrypto} with explicit settings.
     *
     * @param algorithm     PBKDF2 algorithm ({@link Algorithm#PBKDF2_HMAC_SHA1} or
     *                      {@link Algorithm#PBKDF2_HMAC_SHA256})
     * @param iterations    PBKDF2 iteration count (minimum 10000 recommended for new code;
     *                      use 1024 for legacy CryptoService compatibility)
     * @param keyLengthBits AES key length in bits (128 or 256)
     */
    public PasswordBasedCrypto(Algorithm algorithm, int iterations, int keyLengthBits) {
        this.algorithm      = algorithm;
        this.iterations     = iterations;
        this.keyLengthBits  = keyLengthBits;
    }

    // -----------------------------------------------------------------------
    // Random IV — self-contained (recommended)
    // -----------------------------------------------------------------------

    /**
     * Encrypts {@code data} using PBKDF2-derived AES-CBC with a <strong>random IV</strong>.
     *
     * <p>The IV is generated with {@link SecureRandom} and prepended to the ciphertext,
     * so the returned Base64 string is fully self-contained — no separate IV transmission
     * is required. Use {@link #decryptWithRandomIv} to decrypt.
     *
     * <p>This is the recommended method for all new code where both sides share
     * the same passphrase and salt but do not need a deterministic IV.
     *
     * @param data       plaintext to encrypt (UTF-8)
     * @param passphrase secret passphrase for PBKDF2 key derivation
     * @param salt       per-user/per-record salt (e.g. username or record ID);
     *                   does not need to be secret, but should be unique per record
     * @return Base64-encoded payload: {@code Base64(IV_16bytes || ciphertext)}
     * @throws CryptoOperationException if key derivation or cipher init fails
     */
    public String encryptWithRandomIv(String data, String passphrase, String salt) {
        byte[] iv = new byte[IV_LENGTH];
        secureRandom.nextBytes(iv);
        byte[] cipherBytes = doEncrypt(data, passphrase, salt, iv);

        // Prepend IV so the receiver can recover it without out-of-band communication
        byte[] payload = new byte[IV_LENGTH + cipherBytes.length];
        System.arraycopy(iv,          0, payload, 0,         IV_LENGTH);
        System.arraycopy(cipherBytes, 0, payload, IV_LENGTH, cipherBytes.length);

        String result = Base64.getEncoder().encodeToString(payload);
        log.debug("encryptWithRandomIv: plainLen={} base64Len={}", data.length(), result.length());
        return result;
    }

    /**
     * Decrypts a Base64-encoded payload produced by {@link #encryptWithRandomIv}.
     *
     * <p>The first 16 bytes of the decoded payload are the IV; the remainder
     * is the ciphertext.
     *
     * @param encryptedBase64 the Base64 string returned by {@code encryptWithRandomIv}
     * @param passphrase      the same passphrase used during encryption
     * @param salt            the same salt used during encryption
     * @return decrypted plaintext string (UTF-8)
     * @throws InvalidCiphertextException if the payload is malformed, truncated,
     *         or the wrong passphrase/salt is supplied
     * @throws CryptoOperationException   if cipher initialisation fails
     */
    public String decryptWithRandomIv(String encryptedBase64, String passphrase, String salt)
            throws InvalidCiphertextException {

        byte[] payload = decodeBase64(encryptedBase64);
        if (payload.length <= IV_LENGTH) {
            throw new InvalidCiphertextException(
                    "Payload too short — expected >" + IV_LENGTH + " bytes but got " + payload.length);
        }
        byte[] iv          = Arrays.copyOfRange(payload, 0, IV_LENGTH);
        byte[] cipherBytes = Arrays.copyOfRange(payload, IV_LENGTH, payload.length);

        return doDecrypt(cipherBytes, passphrase, salt, iv);
    }

    // -----------------------------------------------------------------------
    // Date-derived IV — deterministic (matches CryptoService pattern)
    // -----------------------------------------------------------------------

    /**
     * Encrypts {@code data} using PBKDF2-derived AES-CBC with an IV
     * <strong>derived from a {@link Date}</strong>.
     *
     * <p>The date is formatted using {@value #DEFAULT_DATE_FORMAT} and the first
     * 16 UTF-8 bytes of that string become the IV. This mirrors the approach in
     * {@code CryptoService.encode()} from the MyWorld project, where the IV comes
     * from the record creation date.
     *
     * <p><strong>Security note:</strong> A date-derived IV is predictable. Use only
     * in protocols where the date is a known, agreed-upon parameter. The receiver must
     * call {@link #decryptWithDateIv(String, String, String, Date)} with the same date.
     *
     * @param data       plaintext to encrypt (UTF-8)
     * @param passphrase secret passphrase for PBKDF2 key derivation
     * @param salt       per-user/per-record salt (e.g. username)
     * @param date       the date from which to derive the IV
     * @return Base64-encoded ciphertext (IV is NOT prepended — re-derived on decrypt)
     * @throws CryptoOperationException if key derivation or cipher init fails
     */
    public String encryptWithDateIv(String data, String passphrase, String salt, Date date) {
        byte[] iv = ivFromDate(date, DEFAULT_DATE_FORMAT);
        byte[] cipherBytes = doEncrypt(data, passphrase, salt, iv);
        String result = Base64.getEncoder().encodeToString(cipherBytes);
        log.debug("encryptWithDateIv: date={} plainLen={} base64Len={}",
                formatDate(date, DEFAULT_DATE_FORMAT), data.length(), result.length());
        return result;
    }

    /**
     * Encrypts {@code data} with an IV derived from a date string.
     *
     * <p>Convenience overload accepting the date as a string; the string is parsed
     * using {@link #DEFAULT_DATE_FORMAT} ({@value #DEFAULT_DATE_FORMAT}).
     *
     * @param data        plaintext to encrypt (UTF-8)
     * @param passphrase  secret passphrase
     * @param salt        per-record salt
     * @param dateString  date string in format {@value #DEFAULT_DATE_FORMAT},
     *                    e.g. {@code "2023-12-29T10:09:34"}
     * @return Base64-encoded ciphertext
     * @throws CryptoOperationException if the date string cannot be parsed or encryption fails
     */
    public String encryptWithDateIv(String data, String passphrase, String salt, String dateString) {
        Date date = parseDate(dateString, DEFAULT_DATE_FORMAT);
        return encryptWithDateIv(data, passphrase, salt, date);
    }

    /**
     * Decrypts a Base64-encoded payload produced by {@link #encryptWithDateIv(String, String, String, Date)}.
     *
     * <p>The IV is re-derived from {@code date} using {@value #DEFAULT_DATE_FORMAT} — it
     * is not embedded in the ciphertext.
     *
     * @param encryptedBase64 the Base64 string returned by {@code encryptWithDateIv}
     * @param passphrase      the same passphrase used during encryption
     * @param salt            the same salt used during encryption
     * @param date            the same date used during encryption
     * @return decrypted plaintext string (UTF-8)
     * @throws InvalidCiphertextException if the ciphertext is malformed or the wrong credentials
     * @throws CryptoOperationException   if cipher initialisation fails
     */
    public String decryptWithDateIv(String encryptedBase64, String passphrase, String salt, Date date)
            throws InvalidCiphertextException {
        byte[] iv          = ivFromDate(date, DEFAULT_DATE_FORMAT);
        byte[] cipherBytes = decodeBase64(encryptedBase64);
        return doDecrypt(cipherBytes, passphrase, salt, iv);
    }

    /**
     * Decrypts a Base64-encoded payload using a date string to re-derive the IV.
     *
     * @param encryptedBase64 the Base64 string returned by {@code encryptWithDateIv}
     * @param passphrase      the same passphrase used during encryption
     * @param salt            the same salt used during encryption
     * @param dateString      date string in format {@value #DEFAULT_DATE_FORMAT}
     * @return decrypted plaintext string
     * @throws InvalidCiphertextException if decryption fails
     * @throws CryptoOperationException   if the date string cannot be parsed
     */
    public String decryptWithDateIv(String encryptedBase64, String passphrase, String salt,
                                    String dateString) throws InvalidCiphertextException {
        Date date = parseDate(dateString, DEFAULT_DATE_FORMAT);
        return decryptWithDateIv(encryptedBase64, passphrase, salt, date);
    }

    // -----------------------------------------------------------------------
    // Custom date format overloads
    // -----------------------------------------------------------------------

    /**
     * Encrypts {@code data} with an IV derived from {@code date} formatted using a
     * custom {@code dateFormat}.
     *
     * @param data        plaintext to encrypt
     * @param passphrase  secret passphrase
     * @param salt        per-record salt
     * @param date        the date from which to derive the IV
     * @param dateFormat  {@link SimpleDateFormat} pattern, e.g. {@code "yyyy-MM-dd HH:mm:ss"}
     * @return Base64-encoded ciphertext
     * @throws CryptoOperationException if encryption fails
     */
    public String encryptWithDateIv(String data, String passphrase, String salt,
                                    Date date, String dateFormat) {
        byte[] iv = ivFromDate(date, dateFormat);
        byte[] cipherBytes = doEncrypt(data, passphrase, salt, iv);
        return Base64.getEncoder().encodeToString(cipherBytes);
    }

    /**
     * Decrypts with an IV derived from {@code date} using a custom {@code dateFormat}.
     *
     * @param encryptedBase64 Base64 ciphertext
     * @param passphrase      secret passphrase
     * @param salt            per-record salt
     * @param date            the date used during encryption
     * @param dateFormat      {@link SimpleDateFormat} pattern used during encryption
     * @return decrypted plaintext
     * @throws InvalidCiphertextException if decryption fails
     */
    public String decryptWithDateIv(String encryptedBase64, String passphrase, String salt,
                                    Date date, String dateFormat) throws InvalidCiphertextException {
        byte[] iv          = ivFromDate(date, dateFormat);
        byte[] cipherBytes = decodeBase64(encryptedBase64);
        return doDecrypt(cipherBytes, passphrase, salt, iv);
    }

    // -----------------------------------------------------------------------
    // Date utility methods
    // -----------------------------------------------------------------------

    /**
     * Parses a date string using the given format pattern.
     *
     * @param dateString the date string to parse
     * @param format     {@link SimpleDateFormat} pattern
     * @return the parsed {@link Date}
     * @throws CryptoOperationException if parsing fails
     */
    public static Date parseDate(String dateString, String format) {
        try {
            return new SimpleDateFormat(format).parse(dateString);
        } catch (ParseException e) {
            throw new CryptoOperationException(
                    "Cannot parse date '" + dateString + "' with format '" + format + "'", e);
        }
    }

    /**
     * Formats a {@link Date} using the given pattern.
     *
     * @param date   the date to format
     * @param format {@link SimpleDateFormat} pattern
     * @return formatted date string
     */
    public static String formatDate(Date date, String format) {
        return new SimpleDateFormat(format).format(date);
    }

    // -----------------------------------------------------------------------
    // Internal — key derivation and cipher operations
    // -----------------------------------------------------------------------

    /**
     * Derives an AES {@link SecretKey} from the passphrase and salt using PBKDF2.
     *
     * <p>Implements the key derivation approach described in
     * <a href="https://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption">
     * SO 992019</a>.
     *
     * @param passphrase the secret passphrase
     * @param salt       the per-record salt bytes
     * @return derived AES {@link SecretKey}
     * @throws CryptoOperationException if the PBKDF2 algorithm is unavailable
     */
    private SecretKey deriveKey(String passphrase, byte[] salt) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm.jceName);
            PBEKeySpec spec = new PBEKeySpec(
                    passphrase.toCharArray(), salt, iterations, keyLengthBits);
            SecretKey tmp = factory.generateSecret(spec);
            spec.clearPassword(); // defensive: clear passphrase from memory
            return new SecretKeySpec(tmp.getEncoded(), AES_ALGORITHM);
        } catch (Exception e) {
            throw new CryptoOperationException(
                    "PBKDF2 key derivation failed [" + algorithm.jceName + "]: " + e.getMessage(), e);
        }
    }

    /**
     * Performs raw AES-CBC encryption.
     *
     * @param plaintext  plaintext UTF-8 string
     * @param passphrase secret passphrase
     * @param salt       salt string (e.g. username)
     * @param iv         16-byte initialisation vector
     * @return raw ciphertext bytes
     * @throws CryptoOperationException if encryption fails
     */
    private byte[] doEncrypt(String plaintext, String passphrase, String salt, byte[] iv) {
        try {
            SecretKey key = deriveKey(passphrase, salt.getBytes(UTF_8));
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(plaintext.getBytes(UTF_8));
        } catch (Exception e) {
            throw new CryptoOperationException("AES encrypt failed: " + e.getMessage(), e);
        }
    }

    /**
     * Performs raw AES-CBC decryption.
     *
     * @param cipherBytes raw ciphertext bytes (without IV prefix)
     * @param passphrase  secret passphrase
     * @param salt        salt string
     * @param iv          16-byte initialisation vector
     * @return decrypted plaintext string
     * @throws InvalidCiphertextException if decryption fails (bad padding, wrong key, etc.)
     */
    private String doDecrypt(byte[] cipherBytes, String passphrase, String salt, byte[] iv)
            throws InvalidCiphertextException {
        try {
            SecretKey key = deriveKey(passphrase, salt.getBytes(UTF_8));
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] plain = cipher.doFinal(cipherBytes);
            return new String(plain, UTF_8);
        } catch (Exception e) {
            throw new InvalidCiphertextException(
                    "AES decrypt failed — wrong passphrase/salt/date or corrupted ciphertext: "
                            + e.getMessage(), e);
        }
    }

    /**
     * Derives a 16-byte IV from a {@link Date} by formatting it as a string and
     * taking the first 16 UTF-8 bytes (zero-padded if shorter).
     *
     * @param date   source date
     * @param format {@link SimpleDateFormat} pattern
     * @return 16-byte IV array
     */
    private static byte[] ivFromDate(Date date, String format) {
        String dateStr  = new SimpleDateFormat(format).format(date);
        byte[] dateBytes = dateStr.getBytes(UTF_8);
        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(dateBytes, 0, iv, 0, Math.min(dateBytes.length, IV_LENGTH));
        return iv;
    }

    /**
     * Decodes a Base64 string, throwing {@link InvalidCiphertextException} for invalid input.
     *
     * @param base64 the Base64 string to decode
     * @return decoded bytes
     * @throws InvalidCiphertextException if the input is not valid Base64
     */
    private static byte[] decodeBase64(String base64) throws InvalidCiphertextException {
        try {
            return Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new InvalidCiphertextException("Payload is not valid Base64: " + e.getMessage(), e);
        }
    }

    // -----------------------------------------------------------------------
    // Getters for configuration inspection
    // -----------------------------------------------------------------------

    /**
     * Returns the PBKDF2 iteration count configured for this instance.
     *
     * @return number of PBKDF2 iterations
     */
    public int getIterations() { return iterations; }

    /**
     * Returns the AES key length in bits configured for this instance.
     *
     * @return key length in bits (128 or 256)
     */
    public int getKeyLengthBits() { return keyLengthBits; }

    /**
     * Returns the PBKDF2 algorithm configured for this instance.
     *
     * @return the {@link Algorithm} enum value
     */
    public Algorithm getAlgorithm() { return algorithm; }
}
