package com.github.yash777.securitycrypto.exception;

/**
 * Thrown when encrypted data is malformed, tampered with, or cannot be
 * decrypted — for example when an AES-GCM authentication tag fails
 * verification, the Base64 payload is truncated, or the extracted IV
 * length does not match the expected value for the chosen cipher mode.
 *
 * <p>This exception wraps the low-level JCE exceptions
 * ({@link javax.crypto.AEADBadTagException},
 * {@link javax.crypto.BadPaddingException},
 * {@link javax.crypto.IllegalBlockSizeException}) so callers do not need
 * to handle each individually.
 *
 * <pre>{@code
 * try {
 *     String plain = cipher.decrypt(encrypted, key, CipherMode.GCM);
 * } catch (InvalidCiphertextException e) {
 *     log.error("Data integrity check failed: {}", e.getMessage());
 * }
 * }</pre>
 *
 * @author Yash
 * @version 1.0.0
 */
public class InvalidCiphertextException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new {@code InvalidCiphertextException} with the given detail message.
     *
     * @param message human-readable description of the failure
     */
    public InvalidCiphertextException(String message) {
        super(message);
    }

    /**
     * Constructs a new {@code InvalidCiphertextException} with the given detail message
     * and underlying cause.
     *
     * @param message human-readable description of the failure
     * @param cause   the JCE exception that triggered this failure
     */
    public InvalidCiphertextException(String message, Throwable cause) {
        super(message, cause);
    }
}
