# security-crypto

[![Maven Central](https://img.shields.io/maven-central/v/io.github.yash-777/security-crypto.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/io.github.yash-777/security-crypto)
[![Java 8+](https://img.shields.io/badge/Java-8%2B-blue.svg)](https://www.oracle.com/java/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://www.apache.org/licenses/LICENSE-2.0)

**security-crypto** is a reusable Java cryptographic library built on the Java Cryptography Architecture (JCA/JCE).  
It provides AES symmetric encryption (ECB, CBC, GCM), RSA asymmetric encryption, PBKDF2 password-based encryption, and hybrid RSA + AES-GCM — all with a clean, exception-safe, Java-8-compatible API and zero mandatory runtime dependencies.

---

## Maven dependency

```xml
<dependency>
    <groupId>io.github.yash-777</groupId>
    <artifactId>security-crypto</artifactId>
    <version>1.0.0</version>
</dependency>
```

The only compile-scope dependency is `slf4j-api`. Supply a runtime implementation (Logback, Log4j2, etc.) in your own project.

---

## Project structure

```
src/main/java/com/github/yash777/securitycrypto/
│
├── CryptoFacade.java                  ← Single entry-point — wires all subsystems together
│
├── cipher/
│   ├── AesCipher.java                 ← AES encrypt/decrypt  (ECB · CBC · GCM)
│   ├── CipherMode.java                ← Enum: ECB | CBC | GCM  (transformation strings)
│   ├── HybridCipher.java              ← RSA key-wrap + AES-GCM payload (any payload size)
│   └── RsaCipher.java                 ← RSA OAEP-SHA-256 encrypt/decrypt
│
├── crypto/
│   └── PasswordBasedCrypto.java       ← PBKDF2 AES-CBC · IV from Date OR random IV
│
├── demo/
│   └── CryptoFacadeRunner.java        ← Runnable main class — 18 demo sections
│
├── exception/
│   ├── CryptoOperationException.java  ← Unchecked: algorithm / key / I/O failures
│   └── InvalidCiphertextException.java← Checked: tampered / malformed ciphertext
│
├── key/
│   ├── KeyManager.java                ← AES/RSA key generation, file persistence, Base64
│   └── KeySize.java                   ← Enum: AES_128 | AES_192 | AES_256
│
└── util/
    └── IvUtils.java                   ← IV/nonce factory: random, fromDate, fromDateString, fromString
```

---

## Quick start

### AES-GCM — recommended for symmetric encryption

```java
CryptoFacade crypto = new CryptoFacade();

SecretKey key     = crypto.generateAesKey(KeySize.AES_256);
String ciphertext = crypto.aesEncrypt("Hello, World!", key);   // GCM + random 12-byte nonce
String plaintext  = crypto.aesDecrypt(ciphertext, key);
```

### AES-CBC with random IV

```java
// Random IV is auto-generated and prepended to the Base64 output
String ciphertext = crypto.aesEncrypt("Hello", key, CipherMode.CBC);
String plaintext  = crypto.aesDecrypt(ciphertext, key, CipherMode.CBC);
```

### AES-CBC with IV from a Date

```java
// IV derived from a date — both sides independently reproduce the same IV
IvParameterSpec iv = IvUtils.fromDate(new Date());           // "yyyy-MM-dd'T'HH:mm:ss" → 16 bytes
String ciphertext  = crypto.aesEncrypt("Hello", key, CipherMode.CBC, iv);
String plaintext   = crypto.aesDecrypt(ciphertext, key, CipherMode.CBC);
```

### AES-CBC with IV from a date string

```java
IvParameterSpec iv = IvUtils.fromDateString("2023-12-29T10:09:34");
String ciphertext  = crypto.aesEncrypt("Hello", key, CipherMode.CBC, iv);
```

### RSA (short payloads ≤ ~190 bytes)

```java
KeyPair rsa      = crypto.generateRsaKeyPair(2048);
String encrypted = crypto.rsaEncrypt("secret-token", rsa.getPublic());
String decrypted = crypto.rsaDecrypt(encrypted, rsa.getPrivate());
```

### Hybrid RSA + AES-GCM (unlimited payload size)

```java
// Sender — fresh AES-256 session key generated per message, RSA-wrapped
HybridPayload payload = crypto.hybridEncrypt("Any length payload...", rsa.getPublic());

// Receiver
String plaintext = crypto.hybridDecrypt(payload, rsa.getPrivate());
```

### Key persistence

```java
// Generate on first run, reload from disk on subsequent runs
SecretKey key = crypto.getOrCreateAesKey(KeySize.AES_256, new File("/secure/keys"));
// File: /secure/keys/secret_256bit.key
```

### Key transport via Base64

```java
String base64Key   = KeyManager.encodeKeyToBase64(key);
SecretKey restored = KeyManager.decodeAesKeyFromBase64(base64Key, KeySize.AES_256);
```

---

## Password-based encryption (PBKDF2)

`PasswordBasedCrypto` derives an AES key from a passphrase + salt using PBKDF2, then encrypts with AES-CBC. Two IV strategies are provided.

### Random IV — self-contained, recommended

The IV is generated with `SecureRandom` and **prepended** to the ciphertext. The receiver needs only the Base64 string, the passphrase, and the salt — no separate IV transmission.

```java
PasswordBasedCrypto pbc = new PasswordBasedCrypto();   // SHA-256 · 65536 iter · 256-bit key

String ct = pbc.encryptWithRandomIv("secret data", "myPassphrase", "user@example.com");
String pt = pbc.decryptWithRandomIv(ct,            "myPassphrase", "user@example.com");
```

### IV from Date — deterministic (CryptoService pattern)

The IV is derived from a `Date` (formatted as `yyyy-MM-dd'T'HH:mm:ss`, first 16 bytes). Both sides must share the same date — the IV is **not** stored in the ciphertext.  
This matches the pattern in `CryptoService.encode()` from the MyWorld project.

```java
Date enrollDate = new Date();

// Encrypt
String ct = pbc.encryptWithDateIv("secret data", "myPassphrase", "user@example.com", enrollDate);

// Decrypt — IV re-derived from the same date
String pt = pbc.decryptWithDateIv(ct, "myPassphrase", "user@example.com", enrollDate);
```

### IV from date string

```java
String ct = pbc.encryptWithDateIv("secret", "passphrase", "salt", "2023-12-29T10:09:34");
String pt = pbc.decryptWithDateIv(ct,       "passphrase", "salt", "2023-12-29T10:09:34");
```

### Legacy CryptoService mode

Reproduces the exact configuration from `CryptoService`: PBKDF2-HMAC-SHA1, 1024 iterations, 128-bit key.

```java
PasswordBasedCrypto pbc = PasswordBasedCrypto.legacyMode();
String encoded = pbc.encryptWithDateIv(rawPassword, masterKey, username, creationDate);
```

### Custom PBKDF2 settings

```java
PasswordBasedCrypto pbc = new PasswordBasedCrypto(
        PasswordBasedCrypto.Algorithm.PBKDF2_HMAC_SHA256,
        100_000,   // iterations
        256        // key length in bits
);
```

---

## IV utilities

```java
// Production (secure, random)
IvUtils.generateRandom()                      // 16-byte random IV  (AES-CBC)
IvUtils.generateRandomGcm()                   // 12-byte random nonce (AES-GCM)
IvUtils.generateRandom(n)                     // n-byte random IV

// Deterministic (for defined protocols only)
IvUtils.fromDate(new Date())                  // yyyy-MM-dd'T'HH:mm:ss → 16 bytes
IvUtils.fromDate(date, "dd/MM/yyyy HH:mm")    // custom format
IvUtils.fromDateString("2023-12-29T10:09:34")
IvUtils.fromDateString("29/12/2023", "dd/MM/yyyy")
IvUtils.fromDateEpochMillis(new Date())       // epoch millis in first 8 bytes
IvUtils.fromString("FixedIV-16bytes!")        // string → 16 bytes (pad/truncate)
IvUtils.fromBytes(rawBytes)                   // wrap raw byte array
```

---

## Cipher modes

| Mode | IV required | Authenticated | Padding | Recommendation |
|------|:-----------:|:-------------:|---------|----------------|
| ECB  | No          | No            | PKCS5   | ⚠ Avoid — identical blocks leak patterns |
| CBC  | Yes (16 B)  | No            | PKCS5   | ✓ OK with random IV |
| GCM  | Yes (12 B)  | **Yes** (128-bit tag) | None | ✅ Best choice — AEAD |

---

## Wire format

For CBC and GCM, the IV is **prepended** to the ciphertext before Base64 encoding so no separate IV transport is needed:

```
Base64( IV_bytes || ciphertext_bytes )
         12 B (GCM) or 16 B (CBC)
```

For `PasswordBasedCrypto` with **date IV**, the IV is re-derived on both sides and is **not** stored in the output:

```
Base64( ciphertext_bytes )      ← only the ciphertext, no IV prefix
```

For GCM, the JCE appends a 128-bit (16-byte) authentication tag inside `ciphertext_bytes`. Any bit-level modification causes `AEADBadTagException`, wrapped as `InvalidCiphertextException`.

---

## Exception model

| Exception | Type | When thrown |
|-----------|------|-------------|
| `InvalidCiphertextException` | **checked** | GCM tag mismatch · bad Base64 · truncated payload · wrong key · wrong date |
| `CryptoOperationException`   | **unchecked** | Missing algorithm · invalid key · I/O failure during key persist |

---

## Running the demo

```bash
mvn package
java -cp target/security-crypto-1.0.0.jar \
     com.github.yash777.securitycrypto.demo.CryptoFacadeRunner
```

The runner covers 18 sections without requiring a test framework:

| # | Section |
|---|---------|
| 1 | AES-GCM via `CryptoFacade` (recommended default) |
| 2 | AES-CBC random IV — all key sizes |
| 3 | AES-CBC with deterministic IV from string |
| 4 | AES-CBC with IV from `Date` (CryptoService pattern) |
| 5 | AES-ECB — all key sizes |
| 6 | All cipher modes × all key sizes matrix (9 combinations) |
| 7 | Key persistence — save to / load from disk |
| 8 | Key encode / decode via Base64 |
| 9 | GCM tamper detection |
| 10 | RSA encrypt / decrypt |
| 11 | Hybrid RSA + AES-GCM — short and large (10 KB) payloads |
| 12 | Password-based — random IV (without date) |
| 13 | Password-based — IV from `Date` (with date) |
| 14 | Password-based — IV from date string |
| 15 | Password-based — legacy `CryptoService` mode |
| 16 | Password-based — SHA-256 / 256-bit key |
| 17 | `IvUtils` — all factory methods |
| 18 | Error handling — negative paths |

---

## Build and release

```bash
# Compile + test + JAR
mvn clean package

# Also attach sources + Javadoc JARs
mvn clean verify

# Release to Maven Central (requires GPG key + Sonatype token in settings.xml)
mvn release:prepare -P release
mvn release:perform -P release
```

Credentials are never stored in `pom.xml`. Configure them in `~/.m2/settings.xml`:

```xml
<servers>
    <server>
        <id>central</id>
        <username>SONATYPE_TOKEN_USER</username>
        <password>SONATYPE_TOKEN_PASS</password>
    </server>
    <server>
        <id>gpg-passphrase</id>
        <passphrase>YOUR_GPG_PASSPHRASE</passphrase>
    </server>
    <server>
        <id>github-scm</id>
        <username>Yash-777</username>
        <password>GITHUB_PAT</password>
    </server>
</servers>
```

---

## Security notes

- Always use `IvUtils.generateRandom()` or `IvUtils.generateRandomGcm()` in production. Date-derived and string-derived IVs are predictable — only use them when IV derivation is part of a defined protocol.
- Never reuse a (key, nonce) pair in GCM mode. Each `aesEncrypt(…, GCM)` call auto-generates a fresh random nonce.
- RSA is limited to ~190 bytes of plaintext (RSA-2048 + OAEP-SHA-256). Use `hybridEncrypt` for larger payloads.
- On Java 8, some distributions restrict key sizes to 128 bits. Install the **JCE Unlimited Strength Policy Files** to enable 192-bit and 256-bit AES keys. Java 9+ has unlimited strength by default.
- Never log secret key material in production. `KeyManager.logKeyInfo()` is for debugging only.

---

## References

- [javax.crypto.Cipher — Oracle Javadoc](http://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html)
- [Java 8 JCA Standard Names](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html)
- [SO 32583766 — Password-based AES encryption](https://stackoverflow.com/a/32583766/5081877)
- [SO 992019 — Java 256-bit AES password-based encryption](https://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption)
- [NIST SP 800-38D — GCM specification](https://csrc.nist.gov/publications/detail/sp/800-38d/final)

---

## License

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).  
Copyright © 2025 Yashwanth. See [LICENSE](LICENSE) for details.
