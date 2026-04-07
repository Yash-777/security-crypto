package com.github.yash777.securitycrypto.exception;

/**
 * General-purpose exception for cryptographic operation failures that are
 * not caused by bad ciphertext — for example an unsupported algorithm,
 * invalid key material, or a missing JCE provider.
 *
 * <p>Wraps checked JCE exceptions such as
 * {@link java.security.NoSuchAlgorithmException},
 * {@link java.security.InvalidKeyException},
 * {@link javax.crypto.NoSuchPaddingException}, and
 * {@link java.security.InvalidAlgorithmParameterException} into a single
 * unchecked surface, keeping callers clean while preserving the root cause.
 *
 * <pre>{@code
 * try {
 *     SecretKey key = KeyManager.generateAesKey(KeySize.AES_256);
 * } catch (CryptoOperationException e) {
 *     // AES-256 not available on this JVM/provider
 *     log.error("Key generation failed", e);
 * }
 * }</pre>
 *
 * @author Yash
 * @version 1.0.0
 */
public class CryptoOperationException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new {@code CryptoOperationException} with the given message.
     *
     * @param message human-readable description of the failure
     */
    public CryptoOperationException(String message) {
        super(message);
    }

    /**
     * Constructs a new {@code CryptoOperationException} wrapping the given cause.
     *
     * @param message human-readable description of the failure
     * @param cause   the underlying JCE or security exception
     */
    public CryptoOperationException(String message, Throwable cause) {
        super(message, cause);
    }
}
