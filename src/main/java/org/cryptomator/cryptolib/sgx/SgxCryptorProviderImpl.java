package org.cryptomator.cryptolib.sgx;

import org.cryptomator.cryptolib.api.*;
import org.cryptomator.cryptolib.common.AesKeyWrap;
import org.cryptomator.cryptolib.common.MacSupplier;
import org.cryptomator.cryptolib.common.Scrypt;
import org.cryptomator.cryptolib.v1.CryptorProviderImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.cryptomator.cryptolib.v1.Constants.*;
import static org.cryptomator.cryptolib.v1.Constants.KEY_LEN_BYTES;

public class SgxCryptorProviderImpl implements CryptorProvider {

    private static final Logger LOG = LoggerFactory.getLogger(CryptorProviderImpl.class);

    private final SecureRandom random;
    private final KeyGenerator encKeyGen;
    private final KeyGenerator macKeyGen;

    public SgxCryptorProviderImpl(SecureRandom random) {
        assertRequiredKeyLengthIsAllowed();
        this.random = random;
        try {
            this.encKeyGen = KeyGenerator.getInstance(ENC_ALG);
            encKeyGen.init(KEY_LEN_BYTES * Byte.SIZE, random);
            this.macKeyGen = KeyGenerator.getInstance(MAC_ALG);
            macKeyGen.init(KEY_LEN_BYTES * Byte.SIZE, random);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Hard-coded algorithm doesn't exist.", e);
        }
    }

    private static void assertRequiredKeyLengthIsAllowed() {
        if (!isRequiredKeyLengthAllowed()) {
            LOG.error("Required key length not supported. See https://github.com/cryptomator/cryptolib/wiki/Restricted-Key-Size.");
            throw new IllegalStateException("Required key length not supported.");
        }
    }

    // visible for testing
    private static boolean isRequiredKeyLengthAllowed() {
        try {
            int requiredKeyLengthBits = KEY_LEN_BYTES * Byte.SIZE;
            int allowedKeyLengthBits = Cipher.getMaxAllowedKeyLength(ENC_ALG);
            return allowedKeyLengthBits >= requiredKeyLengthBits;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Hard-coded algorithm \"" + ENC_ALG + "\" not supported.", e);
        }
    }

    @Override
    public SgxCryptorImpl createNew() {
        SecretKey encKey = encKeyGen.generateKey();
        SecretKey macKey = macKeyGen.generateKey();
        return new SgxCryptorImpl(encKey, macKey, random);
    }

    @Override
    public SgxCryptorImpl createFromKeyFile(KeyFile keyFile, CharSequence passphrase, int expectedVaultVersion) throws UnsupportedVaultFormatException, InvalidPassphraseException {
        return createFromKeyFile(keyFile, passphrase, new byte[0], expectedVaultVersion);
    }

    @Override
    public SgxCryptorImpl createFromKeyFile(KeyFile keyFile, CharSequence passphrase, byte[] pepper, int expectedVaultVersion) throws UnsupportedVaultFormatException, InvalidPassphraseException {
        final SgxKeyFileImpl keyFileImpl = keyFile.as(SgxKeyFileImpl.class);
        final byte[] salt = keyFileImpl.scryptSalt;
        final byte[] saltAndPepper = new byte[salt.length + pepper.length];
        System.arraycopy(salt, 0, saltAndPepper, 0, salt.length);
        System.arraycopy(pepper, 0, saltAndPepper, salt.length, pepper.length);
        final byte[] kekBytes = Scrypt.scrypt(passphrase, saltAndPepper, keyFileImpl.scryptCostParam, keyFileImpl.scryptBlockSize, KEY_LEN_BYTES);
        try {
            SecretKey kek = new SecretKeySpec(kekBytes, ENC_ALG);
            return createFromKeyFile(keyFileImpl, kek, expectedVaultVersion);
        } finally {
            Arrays.fill(kekBytes, (byte) 0x00);
        }
    }

    private SgxCryptorImpl createFromKeyFile(SgxKeyFileImpl keyFile, SecretKey kek, int expectedVaultVersion) throws UnsupportedVaultFormatException, InvalidPassphraseException {
        // check version
        if (expectedVaultVersion != keyFile.getVersion()) {
            throw new UnsupportedVaultFormatException(keyFile.getVersion(), expectedVaultVersion);
        }

        try {
            SecretKey macKey = AesKeyWrap.unwrap(kek, keyFile.macMasterKey, MAC_ALG);
            Mac mac = MacSupplier.HMAC_SHA256.withKey(macKey);
            byte[] versionMac = mac.doFinal(ByteBuffer.allocate(Integer.SIZE / Byte.SIZE).putInt(expectedVaultVersion).array());
            if (keyFile.versionMac == null || !MessageDigest.isEqual(versionMac, keyFile.versionMac)) {
                // attempted downgrade attack: versionMac doesn't match version.
                throw new UnsupportedVaultFormatException(Integer.MAX_VALUE, expectedVaultVersion);
            }
            SecretKey encKey = AesKeyWrap.unwrap(kek, keyFile.encryptionMasterKey, ENC_ALG);
            return new SgxCryptorImpl(encKey, macKey, random);
        } catch (InvalidKeyException e) {
            throw new InvalidPassphraseException();
        }
    }
}
