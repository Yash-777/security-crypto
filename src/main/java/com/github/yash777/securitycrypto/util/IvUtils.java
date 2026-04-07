package com.github.yash777.securitycrypto.util;

import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Utility methods for creating and inspecting {@link IvParameterSpec} instances
 * used when initialising AES-CBC and AES-GCM ciphers.
 *
 * <h2>IV / Nonce sizes</h2>
 * <ul>
 *   <li><strong>CBC</strong> — 16 bytes (one AES block = 128 bits)</li>
 *   <li><strong>GCM</strong> — 12 bytes (96-bit nonce; NIST SP 800-38D preferred size)</li>
 * </ul>
 *
 * <h2>IV strategies provided</h2>
 * <table border="1" summary="IV strategies" cellpadding="4">
 *   <tr><th>Method</th><th>Deterministic?</th><th>Safe for production?</th><th>Use case</th></tr>
 *   <tr><td>{@link #generateRandom()}</td><td>No</td><td>Yes ✓</td><td>AES-CBC production encryption</td></tr>
 *   <tr><td>{@link #generateRandomGcm()}</td><td>No</td><td>Yes ✓</td><td>AES-GCM production nonce</td></tr>
 *   <tr><td>{@link #fromDate(Date)}</td><td>Yes</td><td>Protocol-only</td><td>IV derived from record creation date</td></tr>
 *   <tr><td>{@link #fromDateString(String, String)}</td><td>Yes</td><td>Protocol-only</td><td>IV derived from a date string</td></tr>
 *   <tr><td>{@link #fromString(String)}</td><td>Yes</td><td>Testing only</td><td>Fixed-protocol test scenarios</td></tr>
 *   <tr><td>{@link #fromBytes(byte[])}</td><td>Caller-controlled</td><td>Depends</td><td>Wrapping raw bytes</td></tr>
 * </table>
 *
 * <h2>Security requirements</h2>
 * <ul>
 *   <li>Always use {@link #generateRandom()} or {@link #generateRandomGcm()} in production.</li>
 *   <li>Date-derived and string-derived IVs are predictable. Only use them when the IV
 *       derivation rule is part of a defined protocol (e.g. both sides share the date).</li>
 *   <li>Never reuse a (key, IV) pair in GCM mode.</li>
 * </ul>
 *
 * @author  Yash
 * @version 1.0.0
 * @since   1.0.0
 * @see     <a href="http://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html">javax.crypto.Cipher</a>
 */
public final class IvUtils {

    /** Standard IV length for AES-CBC — one AES block (16 bytes / 128 bits). */
    public static final int IV_LENGTH_CBC = 16;

    /**
     * Recommended nonce length for AES-GCM — 12 bytes / 96 bits per NIST SP 800-38D.
     * Using 12 bytes avoids an internal GHASH derivation step for the counter block.
     */
    public static final int IV_LENGTH_GCM = 12;

    /** Default date format used by {@link #fromDate(Date)} and {@link #fromDateString(String)}. */
    public static final String DEFAULT_DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private IvUtils() { /* utility class */ }

    // -----------------------------------------------------------------------
    // Random IV / nonce factory methods (recommended for production)
    // -----------------------------------------------------------------------

    /**
     * Generates a cryptographically random IV of the specified length using {@link SecureRandom}.
     *
     * <p>This is the <strong>recommended method</strong> for all production encryption.
     *
     * @param length IV length in bytes — use {@link #IV_LENGTH_CBC} (16) for CBC or
     *               {@link #IV_LENGTH_GCM} (12) for GCM
     * @return a new {@link IvParameterSpec} backed by securely-random bytes
     */
    public static IvParameterSpec generateRandom(int length) {
        byte[] iv = new byte[length];
        SECURE_RANDOM.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    /**
     * Generates a random 16-byte IV suitable for AES-CBC.
     *
     * @return a new {@link IvParameterSpec} with 16 securely-random bytes
     */
    public static IvParameterSpec generateRandom() {
        return generateRandom(IV_LENGTH_CBC);
    }

    /**
     * Generates a random 12-byte nonce suitable for AES-GCM.
     *
     * @return a new {@link IvParameterSpec} with 12 securely-random bytes
     */
    public static IvParameterSpec generateRandomGcm() {
        return generateRandom(IV_LENGTH_GCM);
    }

    // -----------------------------------------------------------------------
    // Deterministic IV factory methods (for protocols / testing)
    // -----------------------------------------------------------------------

    /**
     * Creates a deterministic 16-byte IV from a {@link Date}.
     *
     * <p>The date is formatted using {@link #DEFAULT_DATE_FORMAT}
     * ({@value #DEFAULT_DATE_FORMAT}), encoded as UTF-8, and the first 16 bytes
     * are used as the IV (zero-padded if the string is shorter than 16 bytes).
     *
     * <p>This matches the IV derivation approach used in
     * {@code com.github.yash777.security.crypto.CryptoService} in the MyWorld project.
     *
     * <p><strong>Warning:</strong> Timestamps are predictable. Only use when both sides
     * independently reproduce the same IV from a shared date.
     *
     * @param date source date
     * @return 16-byte {@link IvParameterSpec}
     */
    public static IvParameterSpec fromDate(Date date) {
        return fromDate(date, DEFAULT_DATE_FORMAT);
    }

    /**
     * Creates a deterministic 16-byte IV from a {@link Date} using a custom format pattern.
     *
     * @param date       source date
     * @param dateFormat {@link SimpleDateFormat} pattern (e.g. {@code "yyyy-MM-dd HH:mm:ss"})
     * @return 16-byte {@link IvParameterSpec}
     */
    public static IvParameterSpec fromDate(Date date, String dateFormat) {
        String formatted = new SimpleDateFormat(dateFormat).format(date);
        return fromString(formatted, IV_LENGTH_CBC);
    }

    /**
     * Creates a deterministic 16-byte IV from a date string.
     *
     * <p>The string is parsed using {@link #DEFAULT_DATE_FORMAT}
     * ({@value #DEFAULT_DATE_FORMAT}), then the first 16 UTF-8 bytes become the IV.
     * This is a convenience wrapper for the pattern:
     * <pre>{@code
     * IvUtils.fromDate(PasswordBasedCrypto.parseDate(dateStr, DEFAULT_DATE_FORMAT));
     * }</pre>
     *
     * @param dateString date string in format {@value #DEFAULT_DATE_FORMAT},
     *                   e.g. {@code "2023-12-29T10:09:34"}
     * @return 16-byte {@link IvParameterSpec}
     * @throws IllegalArgumentException if the date string cannot be parsed
     */
    public static IvParameterSpec fromDateString(String dateString) {
        return fromDateString(dateString, DEFAULT_DATE_FORMAT);
    }

    /**
     * Creates a deterministic 16-byte IV from a date string using a custom format pattern.
     *
     * @param dateString date string to parse
     * @param dateFormat {@link SimpleDateFormat} pattern
     * @return 16-byte {@link IvParameterSpec}
     * @throws IllegalArgumentException if the date string cannot be parsed
     */
    public static IvParameterSpec fromDateString(String dateString, String dateFormat) {
        try {
            Date date = new SimpleDateFormat(dateFormat).parse(dateString);
            return fromDate(date, dateFormat);
        } catch (ParseException e) {
            throw new IllegalArgumentException(
                    "Cannot parse date '" + dateString + "' with format '" + dateFormat + "'", e);
        }
    }

    /**
     * Creates a deterministic IV derived from a {@link Date}'s epoch-millisecond timestamp,
     * packed into the first 8 bytes of a 16-byte array (remaining 8 bytes zeroed).
     *
     * <p>This is an alternative date-to-IV approach that packs epoch millis directly rather
     * than using a formatted string. Prefer {@link #fromDate(Date)} unless you need to
     * exactly replicate legacy epoch-millis-based IV generation.
     *
     * @param date source date
     * @return 16-byte {@link IvParameterSpec}
     */
    public static IvParameterSpec fromDateEpochMillis(Date date) {
        ByteBuffer buf = ByteBuffer.allocate(IV_LENGTH_CBC);
        buf.putLong(date.getTime());
        buf.putLong(0L); // pad remaining 8 bytes with zeros
        return new IvParameterSpec(buf.array());
    }

    /**
     * Creates a deterministic IV from a UTF-8 string, truncated or zero-padded
     * to exactly {@code targetLength} bytes.
     *
     * <p><strong>Warning:</strong> Predictable IV. Use only for fixed-protocol
     * interoperability or unit tests — never for general production encryption.
     *
     * @param str          source string
     * @param targetLength desired IV length in bytes (typically 12 or 16)
     * @return {@link IvParameterSpec} of exactly {@code targetLength} bytes
     */
    public static IvParameterSpec fromString(String str, int targetLength) {
        byte[] raw = str.getBytes(UTF_8);
        byte[] iv  = Arrays.copyOf(raw, targetLength); // pads with 0x00 if shorter
        return new IvParameterSpec(iv);
    }

    /**
     * Creates a 16-byte deterministic IV from a UTF-8 string (CBC-length convenience overload).
     *
     * @param str source string
     * @return 16-byte {@link IvParameterSpec}
     */
    public static IvParameterSpec fromString(String str) {
        return fromString(str, IV_LENGTH_CBC);
    }

    /**
     * Creates an {@link IvParameterSpec} directly from a raw byte array.
     *
     * @param ivBytes raw IV bytes (12 bytes for GCM, 16 bytes for CBC)
     * @return {@link IvParameterSpec} wrapping the supplied bytes
     * @throws IllegalArgumentException if {@code ivBytes} is null or empty
     */
    public static IvParameterSpec fromBytes(byte[] ivBytes) {
        if (ivBytes == null || ivBytes.length == 0) {
            throw new IllegalArgumentException("IV byte array must not be null or empty");
        }
        return new IvParameterSpec(ivBytes);
    }

    // -----------------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------------

    /**
     * Returns the raw byte array from an {@link IvParameterSpec}.
     *
     * @param spec the spec to inspect
     * @return copy of the underlying IV bytes
     */
    public static byte[] toBytes(IvParameterSpec spec) {
        return spec.getIV();
    }
}
